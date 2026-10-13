"""Read exact-release dependency metadata without installing or running packages.

A null release-level requires_dist is not evidence of zero dependencies. A
compatible wheel's PEP 658 metadata can supply that evidence, after validating
its independently advertised SHA256, package identity and metadata headers.
"""
import hashlib
import json
import os
import tempfile
import time
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from packageurl import PackageURL
from packaging.specifiers import SpecifierSet
from packaging.tags import Tag, sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from scripts.inventory import target_environment

MAX_METADATA_BYTES = 2 * 1024 * 1024


def _compatible_tags(environment):
    if environment == target_environment():
        return list(sys_tags())
    # Marker fields do not specify libc/platform ABI. Only generic pure Python
    # wheels are provably compatible with a foreign environment described here.
    major, minor = map(int, environment["python_version"].split("."))
    return [Tag(f"py{major}{n}", "none", "any") for n in range(minor, -1, -1)] + [Tag(f"py{major}", "none", "any")]


def _wheel_metadata(package, artifacts, environment):
    tags = {tag: i for i, tag in enumerate(_compatible_tags(environment))}
    candidates = []
    for artifact in artifacts:
        try:
            name, version, _, wheel_tags = parse_wheel_filename(artifact["filename"])
            ranks = [tags[tag] for tag in wheel_tags if tag in tags]
            if name != canonicalize_name(package.name) or version != Version(package.version) or not ranks:
                continue
            if artifact.get("requires_python") and not SpecifierSet(artifact["requires_python"]).contains(environment["python_full_version"], prereleases=True):
                continue
            candidates.append((min(ranks), artifact["filename"], artifact))
        except (ValueError, KeyError, TypeError):
            continue
    if not candidates:
        return {}
    index_url = f"https://pypi.org/simple/{canonicalize_name(package.name)}/"
    response = requests.get(index_url, headers={"Accept": "application/vnd.pypi.simple.v1+json"}, timeout=30)
    response.raise_for_status()
    files = {file["filename"]: file for file in response.json().get("files", [])}
    failures = []
    for _, filename, artifact in sorted(candidates)[:3]:
        try:
            indexed = files.get(filename, {})
            hashes = indexed.get("core-metadata", indexed.get("dist-info-metadata"))
            if not isinstance(hashes, dict) or not hashes.get("sha256"):
                continue
            url = urljoin(index_url, indexed["url"])
            parts = urlsplit(url)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            if url != artifact["url"] or parts.scheme != "https" or parts.hostname != "files.pythonhosted.org":
                continue
            # PyPI artifact URLs have no query. Do not append after a query.
            metadata_url = urlunsplit((parts.scheme, parts.netloc, parts.path + ".metadata", parts.query, ""))
            content = bytearray()
            with requests.get(metadata_url, stream=True, timeout=30) as metadata_response:
                metadata_response.raise_for_status()
                for chunk in metadata_response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > MAX_METADATA_BYTES:
                        raise ValueError("Wheel metadata exceeds size limit")
            digest = hashlib.sha256(content).hexdigest()
            if digest != hashes["sha256"]:
                raise ValueError("Wheel metadata SHA256 mismatch")
            message = BytesParser().parsebytes(bytes(content), headersonly=True)
            if message.defects:
                raise ValueError("Malformed wheel metadata")
            for field in ("Metadata-Version", "Name", "Version"):
                if len(message.get_all(field, [])) != 1:
                    raise ValueError(f"Missing or repeated {field} header")
            if not (Version("1.2") <= Version(message["Metadata-Version"]) < Version("3")):
                raise ValueError("Unsupported core metadata version")
            if canonicalize_name(message["Name"]) != canonicalize_name(package.name) or Version(message["Version"]) != Version(package.version):
                raise ValueError("Wheel metadata identity mismatch")
            dynamic = {item.strip().lower() for value in message.get_all("Dynamic", []) for item in value.split(",")}
            if dynamic & {"requires-dist", "requires-python"}:
                raise ValueError("Dynamic dependency metadata")
            return {"requires_dist": message.get_all("Requires-Dist", []),
                    "requires_python": message.get("Requires-Python"),
                    "metadata_source": "verified_wheel_core_metadata",
                    "wheel_filename": filename, "metadata_url": metadata_url,
                    "metadata_sha256": digest, "metadata_index_url": index_url}
        except (ValueError, KeyError, TypeError, requests.RequestException) as exc:
            failures.append({"wheel": filename, "error": str(exc)})
    return {"metadata_failures": failures} if failures else {}


def package_metadata(purl, directory, *, environment=None):
    environment = target_environment(environment)
    package = PackageURL.from_string(purl)
    if package.type != "pypi" or not package.version or package.namespace or package.subpath:
        raise ValueError("An exact PyPI package version is required")
    key = hashlib.sha256(json.dumps(["metadata-v2", purl, environment], sort_keys=True).encode()).hexdigest()
    destination = Path(directory) / "metadata" / (key + ".json")
    if destination.is_file() and time.time() - destination.stat().st_mtime < 86400:
        try:
            cached = json.loads(destination.read_text(encoding="utf-8"))
            digest = cached.pop("sha256", None)
            if (cached.get("purl") == purl and cached.get("environment") == environment
                    and digest == hashlib.sha256(json.dumps(cached, sort_keys=True).encode()).hexdigest()):
                return {**cached, "sha256": digest}
        except (ValueError, OSError, AttributeError):
            pass
    url = f"https://pypi.org/pypi/{package.name}/{package.version}/json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    payload = response.json()
    info = payload["info"]
    metadata = {"purl": purl, "environment": environment, "requires_dist": info.get("requires_dist"),
                "requires_python": info.get("requires_python"), "registry_url": url,
                "metadata_source": "pypi_release_json"}
    if metadata["requires_dist"] is None:
        try:
            metadata.update(_wheel_metadata(package, payload.get("urls", []), environment))
        except (ValueError, KeyError, TypeError, requests.RequestException) as exc:
            metadata["metadata_failures"] = [{"error": str(exc)}]
    if metadata["requires_dist"] is not None and (
            not isinstance(metadata["requires_dist"], list)
            or any(not isinstance(requirement, str) for requirement in metadata["requires_dist"])):
        raise ValueError("Invalid requires_dist metadata")
    metadata["sha256"] = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".metadata-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(metadata, stream, sort_keys=True)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    return metadata
