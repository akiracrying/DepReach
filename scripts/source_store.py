"""Download versioned PyPI sources without executing package build hooks."""
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath

import requests
from packageurl import PackageURL

_LOCKS = {}
_LOCK_GUARD = threading.Lock()
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_FILES = 50000


def _destination(root, name):
    # Reject links, Windows drive/ADS names and absolute paths on every OS.
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts or normalized.startswith("/") or any(p in {"..", "."} or ":" in p for p in parts):
        raise ValueError(f"Unsafe archive member: {name}")
    path = root.joinpath(*parts).resolve()
    if root.resolve() not in path.parents:
        raise ValueError(f"Unsafe archive member: {name}")
    return path


def extract_archive(archive, target):
    root = Path(target)
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as src:
            if len(src.infolist()) > MAX_FILES:
                raise ValueError("Too many archive members")
            for member in src.infolist():
                path = _destination(root, member.filename)
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Archive links are not supported")
                total += member.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive expands beyond limit")
                if member.is_dir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with src.open(member) as stream, path.open("wb") as dest:
                        shutil.copyfileobj(stream, dest)
    else:
        with tarfile.open(archive, "r:*") as src:
            for count, member in enumerate(src, 1):
                if count > MAX_FILES:
                    raise ValueError("Too many archive members")
                path = _destination(root, member.name)
                if member.issym() or member.islnk():
                    # Materialize a regular archive member, never create a filesystem link.
                    import posixpath
                    link = member.linkname.replace("\\", "/")
                    if link.startswith("/") or ":" in link:
                        raise ValueError("Unsafe archive links")
                    target_name = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), link) if member.issym() else link)
                    try:
                        _destination(root, target_name)
                        target_member = src.getmember(target_name)
                    except (ValueError, KeyError) as exc:
                        raise ValueError("Unsafe or missing archive links") from exc
                    if not target_member.isfile():
                        raise ValueError("Archive links must point directly to regular files")
                    total += target_member.size
                    if total > MAX_EXTRACTED_BYTES:
                        raise ValueError("Archive expands beyond limit")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with src.extractfile(target_member) as stream, path.open("wb") as dest:
                        shutil.copyfileobj(stream, dest)
                    continue
                if not (member.isfile() or member.isdir()):
                    raise ValueError("Archive links and special files are not supported")
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive expands beyond limit")
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with src.extractfile(member) as stream, path.open("wb") as dest:
                        shutil.copyfileobj(stream, dest)


def download_purl_source(purl, target_dir):
    package = PackageURL.from_string(purl)
    if package.type != "pypi" or not package.version or package.namespace or package.subpath:
        raise ValueError("A versioned PyPI PURL is required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", package.name) or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", package.version):
        raise ValueError("Invalid package name or version")
    key = hashlib.sha256(purl.encode()).hexdigest()
    destination = Path(target_dir).resolve() / key
    marker = destination / ".depreach-source.json"
    with _LOCK_GUARD:
        lock = _LOCKS.setdefault(str(destination), threading.Lock())
    with lock:
        if marker.is_file():
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            source = destination / metadata["source"]
            if source.is_dir():
                return str(source)
        response = requests.get(f"https://pypi.org/pypi/{package.name}/{package.version}/json", timeout=30)
        response.raise_for_status()
        files = [f for f in response.json().get("urls", []) if f.get("packagetype") == "sdist"]
        if not files:
            raise ValueError("No source distribution available")
        artifact = sorted(files, key=lambda f: f["filename"])[0]
        expected = artifact.get("digests", {}).get("sha256")
        if not expected:
            raise ValueError("Source distribution has no SHA256 digest")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="depreach-", dir=destination.parent) as tmp:
            archive = Path(tmp) / "archive"
            digest, total = hashlib.sha256(), 0
            with requests.get(artifact["url"], stream=True, timeout=30) as response:
                response.raise_for_status()
                with archive.open("wb") as out:
                    for chunk in response.iter_content(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_ARCHIVE_BYTES:
                            raise ValueError("Source archive exceeds size limit")
                        digest.update(chunk)
                        out.write(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("Source archive checksum mismatch")
            extracted = Path(tmp) / "source"
            extract_archive(archive, extracted)
            children = list(extracted.iterdir())
            relative_source = children[0].name if len(children) == 1 and children[0].is_dir() else "."
            metadata = {"purl": purl, "sha256": expected, "source": relative_source}
            (extracted / ".depreach-source.json").write_text(json.dumps(metadata), encoding="utf-8")
            # Atomic publication: a concurrent process may have completed first.
            try:
                os.rename(extracted, destination)
            except OSError:
                if not marker.is_file():
                    raise
            return str(destination / json.loads(marker.read_text(encoding="utf-8"))["source"])
