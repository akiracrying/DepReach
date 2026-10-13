"""Materialize the exact npm artifacts recorded in a captured lock tree.

Only verified archives are cached. Each scan extracts fresh sources, so edits
in a previous report cannot silently acquire registry provenance. npm scripts,
package managers and target code are never executed.
"""
import base64
import binascii
import hashlib
import json
import os
import tempfile
import time
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import requests

from scripts.npm_inventory import _location
from scripts.source_store import extract_archive, MAX_ARCHIVE_BYTES

_ALGORITHMS = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}


class SourceError(ValueError):
    def __init__(self, reason, message):
        self.reason = reason
        super().__init__(message)


def integrity_tokens(value):
    if not isinstance(value, str) or not value.strip():
        raise SourceError("npm_archive_integrity_missing", "The lockfile has no artifact integrity")
    supported = []
    for token in value.split():
        algorithm, separator, encoded = token.partition("-")
        if algorithm not in _ALGORITHMS:
            continue
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SourceError("npm_archive_integrity_invalid", "Invalid integrity encoding") from exc
        if not separator or len(digest) != _ALGORITHMS[algorithm]:
            raise SourceError("npm_archive_integrity_invalid", "Invalid integrity digest size")
        supported.append((algorithm, digest))
    if not supported:
        raise SourceError("npm_archive_integrity_unsupported", "No supported lockfile integrity algorithm")
    strongest = max(_ALGORITHMS[algorithm] for algorithm, _ in supported)
    return [(algorithm, digest) for algorithm, digest in supported if _ALGORITHMS[algorithm] == strongest]


def verify_archive(path, integrity):
    tokens = integrity_tokens(integrity)
    algorithm = tokens[0][0]
    digest, sha256, size = hashlib.new(algorithm), hashlib.sha256(), 0
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                raise SourceError("npm_archive_size_limit", "npm archive exceeds the size limit")
            digest.update(chunk)
            sha256.update(chunk)
    if not any(digest.digest() == expected for _, expected in tokens):
        raise SourceError("npm_archive_integrity_mismatch", "npm archive does not match lockfile integrity")
    return {"integrity_algorithm": algorithm, "archive_sha256": sha256.hexdigest(), "archive_bytes": size}


def _archive(instance, cache):
    integrity_tokens(instance.get("integrity"))
    url = instance.get("resolved")
    parsed = urlsplit(url or "")
    if (parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
            or parsed.username or parsed.password or parsed.port not in {None, 443}):
        raise SourceError("npm_registry_source_unsupported", "Source retrieval currently supports HTTPS registry.npmjs.org tarballs")
    key = hashlib.sha256(json.dumps([instance["purl"], url, instance["integrity"]]).encode()).hexdigest()
    path = cache / (key + ".tgz")
    if path.is_file():
        try:
            verified = verify_archive(path, instance["integrity"])
            return key, path, {**verified, "archive_cache_hit": True}
        except SourceError:
            # Replace only this content-scoped cache artifact after a verified download.
            pass
    with tempfile.TemporaryDirectory(prefix="npm-download-", dir=cache) as temporary:
        downloaded = Path(temporary) / "archive"
        with requests.get(url, stream=True, timeout=30, allow_redirects=False) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise SourceError("npm_archive_http_status", f"Unexpected npm archive status {response.status_code}")
            total = 0
            with downloaded.open("wb") as destination:
                for chunk in response.iter_content(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise SourceError("npm_archive_size_limit", "npm archive exceeds the size limit")
                    destination.write(chunk)
        verified = verify_archive(downloaded, instance["integrity"])
        os.replace(downloaded, path)
    return key, path, {**verified, "archive_cache_hit": False}


def _package_identity(source, instance):
    raw = (source / "package.json").read_bytes()
    package = json.loads(raw)
    if not isinstance(package, dict) or package.get("name") != instance["name"] or package.get("version") != instance["version"]:
        raise SourceError("npm_archive_identity_mismatch", "package.json name/version differs from the locked package identity")
    return {"package_json_sha256": hashlib.sha256(raw).hexdigest()}


def _publish_source(extracted, final, destination):
    destination = destination.resolve()
    if destination not in extracted.resolve().parents or destination not in final.resolve().parents:
        raise ValueError("npm source publication leaves its output directory")
    # Windows scanners can briefly hold a freshly extracted file. Retry the
    # same bounded rename, never delete or overwrite an existing source tree.
    for attempt, delay in enumerate((0.05, 0.15, 0.5, 1.0, None)):
        try:
            os.rename(extracted, final)
            return attempt
        except PermissionError:
            if delay is None:
                raise
            time.sleep(delay)


def _registry_source(instance, cache, destination):
    key, archive, verification = _archive(instance, cache)
    final = destination / key
    with tempfile.TemporaryDirectory(prefix="npm-extract-", dir=destination) as temporary:
        extracted = Path(temporary) / "content"
        extract_archive(archive, extracted)
        if (extracted / "package" / "package.json").is_file():
            relative = "package"
        elif (extracted / "package.json").is_file():
            relative = "."
        else:
            candidates = [p for p in extracted.iterdir() if p.is_dir() and (p / "package.json").is_file()]
            if len(candidates) != 1:
                raise SourceError("npm_archive_package_root_missing", "Cannot identify a unique package root in archive")
            relative = candidates[0].name
        identity = _package_identity(extracted / relative, instance)
        retries = _publish_source(extracted, final, destination)
    return {"source_publish_retries": retries, "source": str(final / relative), "artifact_key": key, "resolved": instance["resolved"],
            "integrity": instance["integrity"], "provenance": "npm_lockfile_verified_tarball", **verification, **identity}


def prepare_npm_sources(inventory, output_dir, *, archive_cache="data/npm-archives", jobs=6):
    if jobs < 1:
        raise ValueError("jobs must be positive")
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    cache = Path(archive_cache).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    root = Path(inventory["root"]).resolve()
    instances = {i["location"]: i for i in inventory["instances"]}
    groups, records, issues = {}, {}, []
    for location, instance in instances.items():
        _location(location)
        if instance["source_kind"] == "registry_tarball":
            key = (instance["purl"], instance.get("resolved"), instance.get("integrity"))
            groups.setdefault(key, []).append(instance)
        elif instance["source_kind"] == "workspace":
            try:
                path = (root / _location(instance["source_location"])).resolve()
                if path != root and root not in path.parents:
                    raise SourceError("npm_workspace_outside_project", "Workspace source leaves the scanned project")
                identity = _package_identity(path, instance)
                records[location] = {"source": str(path), "provenance": "local_workspace_package_json", **identity}
            except (ValueError, OSError) as exc:
                issues.append({"location": location, "purl": instance["purl"], "reason": getattr(exc, "reason", "npm_workspace_source_unavailable"), "error": str(exc)})
        elif instance["source_kind"] != "bundled":
            issues.append({"location": location, "purl": instance["purl"], "reason": "npm_source_kind_unsupported", "source_kind": instance["source_kind"]})
    with ThreadPoolExecutor(max_workers=min(jobs, 8)) as pool:
        futures = {pool.submit(_registry_source, group[0], cache, destination): group for group in groups.values()}
        for future in as_completed(futures):
            group = futures[future]
            try:
                record = future.result()
                for instance in group:
                    records[instance["location"]] = dict(record)
            except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile, requests.RequestException) as exc:
                for instance in group:
                    issues.append({"location": instance["location"], "purl": instance["purl"],
                                   "reason": getattr(exc, "reason", "npm_package_source_unavailable"), "error": str(exc)})
    # Bundled modules are bytes inside an ancestor artifact, not independent
    # downloads with invented checksums. Resolve from the nearest verified owner.
    for location, instance in sorted(instances.items()):
        if instance["source_kind"] != "bundled":
            continue
        try:
            owner = next((p.as_posix() for p in PurePosixPath(location).parents
                          if p.as_posix() in records and records[p.as_posix()].get("archive_sha256")), None)
            if owner is None:
                raise SourceError("npm_bundled_owner_unavailable", "No verified ancestor artifact for bundled package")
            relative = PurePosixPath(location).relative_to(owner)
            parent = records[owner]
            owner_source = Path(parent["source"]).resolve()
            source = (owner_source / relative).resolve()
            if owner_source not in source.parents:
                raise SourceError("npm_bundled_path_invalid", "Bundled source leaves its verified owner")
            identity = _package_identity(source, instance)
            records[location] = {**parent, **identity, "source": str(source), "provenance": "npm_bundled_in_verified_archive", "bundled_owner": owner}
        except (ValueError, OSError) as exc:
            issues.append({"location": location, "purl": instance["purl"], "reason": getattr(exc, "reason", "npm_bundled_source_unavailable"), "error": str(exc)})
    sources = [{"location": loc, "purl": instances[loc]["purl"], **records[loc]} for loc in sorted(records)]
    artifacts = {s["artifact_key"]: s for s in sources if s.get("artifact_key")}
    manifest = {"schema_version": 1, "ecosystem": "npm", "inventory_sha256": inventory["input_sha256"],
                "sources": sources, "issues": sorted(issues, key=lambda i: (i["location"], i["reason"])),
                "complete": len(sources) == len(instances) and not issues,
                "metrics": {"instances": len(instances), "sources": len(sources), "artifacts": len(artifacts),
                            "archive_cache_hits": sum(a["archive_cache_hit"] for a in artifacts.values())},
                "verification_scope": "lockfile_integrity_and_package_identity; no installation or runtime execution"}
    manifest["fingerprint"] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return manifest
