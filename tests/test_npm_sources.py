import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts import npm_sources as sources


def sri(raw, algorithm="sha512"):
    return algorithm + "-" + base64.b64encode(hashlib.new(algorithm, raw).digest()).decode()


def archive(name="demo", version="1.0.0", extra=None):
    files = {"package/package.json": json.dumps({"name": name, "version": version, "scripts": {"install": "must not execute"}}).encode(),
             "package/index.js": b"throw new Error('must not execute');", **(extra or {})}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            bundle.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def instance(raw, location="node_modules/demo", name="demo", version="1.0.0", **options):
    return {"location": location, "source_location": location, "name": name, "version": version,
            "purl": f"pkg:npm/{name}@{version}", "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            "integrity": sri(raw), "source_kind": "registry_tarball", **options}


def inventory(tmp_path, instances):
    return {"root": str(tmp_path), "input_sha256": "captured-lock", "instances": instances}


def network(monkeypatch, raw, status=200):
    calls = []
    class Response:
        status_code = status
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def raise_for_status(self): pass
        def iter_content(self, size): yield raw
    def get(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        calls.append(url)
        return Response()
    monkeypatch.setattr(sources.requests, "get", get)
    return calls


def prepare(tmp_path, entries, run="run"):
    return sources.prepare_npm_sources(inventory(tmp_path, entries), tmp_path / run, archive_cache=tmp_path / "cache")


def test_verifies_integrity_identity_and_reuses_artifact_for_instances(tmp_path, monkeypatch):
    raw = archive()
    calls = network(monkeypatch, raw)
    report = prepare(tmp_path, [instance(raw), instance(raw, "node_modules/parent/node_modules/demo")])
    assert report["complete"] and len(calls) == 1
    assert len(report["sources"]) == 2
    assert report["sources"][0]["source"] == report["sources"][1]["source"]
    assert report["sources"][0]["integrity_algorithm"] == "sha512"
    assert report["metrics"]["artifacts"] == 1
    assert Path(report["sources"][0]["source"], "index.js").read_bytes().startswith(b"throw")


def test_cached_archive_is_rechecked_and_sources_are_fresh_each_scan(tmp_path, monkeypatch):
    raw = archive()
    calls = network(monkeypatch, raw)
    entries = [instance(raw)]
    first = prepare(tmp_path, entries)
    Path(first["sources"][0]["source"], "index.js").write_text("tampered", encoding="utf-8")
    second = prepare(tmp_path, entries, "second")
    assert len(calls) == 1
    assert second["metrics"]["archive_cache_hits"] == 1
    assert Path(second["sources"][0]["source"], "index.js").read_bytes().startswith(b"throw")
    next((tmp_path / "cache").glob("*.tgz")).write_bytes(b"corrupted cache")
    third = prepare(tmp_path, entries, "third")
    assert third["complete"] and len(calls) == 2


def test_sha1_lockfiles_are_explicitly_labeled(tmp_path, monkeypatch):
    raw = archive()
    network(monkeypatch, raw)
    report = prepare(tmp_path, [instance(raw, integrity=sri(raw, "sha1"))])
    assert report["complete"]
    assert report["sources"][0]["integrity_algorithm"] == "sha1"


def test_strongest_integrity_cannot_downgrade_to_matching_weak_hash(tmp_path, monkeypatch):
    raw = archive()
    network(monkeypatch, raw)
    integrity = sri(raw, "sha1") + " " + sri(b"other archive", "sha512")
    report = prepare(tmp_path, [instance(raw, integrity=integrity)])
    assert not report["complete"] and not report["sources"]
    assert report["issues"][0]["reason"] == "npm_archive_integrity_mismatch"
    assert not list((tmp_path / "cache").glob("*.tgz"))


@pytest.mark.parametrize("integrity", [None, "", "sha512-invalid!", "sha512-YQ==", "unknown-YQ=="])
def test_invalid_or_missing_integrity_prevents_download(tmp_path, monkeypatch, integrity):
    calls = network(monkeypatch, archive())
    report = prepare(tmp_path, [instance(b"", integrity=integrity)])
    assert not report["complete"] and not calls


def test_verified_archive_with_wrong_package_identity_is_rejected(tmp_path, monkeypatch):
    raw = archive(version="2.0.0")
    network(monkeypatch, raw)
    report = prepare(tmp_path, [instance(raw)])
    assert report["issues"][0]["reason"] == "npm_archive_identity_mismatch"
    assert not report["sources"]
    assert not list((tmp_path / "run").iterdir())


def test_bundled_package_uses_parent_integrity_and_its_own_identity(tmp_path, monkeypatch):
    raw = archive(extra={"package/node_modules/leaf/package.json": b'{"name":"leaf","version":"2.0.0"}',
                         "package/node_modules/leaf/index.js": b"module.exports = 1"})
    calls = network(monkeypatch, raw)
    child = instance(raw, "node_modules/demo/node_modules/leaf", "leaf", "2.0.0", source_kind="bundled", integrity=None)
    report = prepare(tmp_path, [instance(raw), child])
    assert report["complete"] and len(calls) == 1
    bundled = next(s for s in report["sources"] if s["purl"] == child["purl"])
    assert bundled["provenance"] == "npm_bundled_in_verified_archive"
    assert bundled["bundled_owner"] == "node_modules/demo"
    assert bundled["archive_sha256"] == hashlib.sha256(raw).hexdigest()
    assert Path(bundled["source"], "index.js").is_file()


def test_absent_bundled_source_cannot_claim_complete_coverage(tmp_path, monkeypatch):
    raw = archive()
    network(monkeypatch, raw)
    child = instance(raw, "node_modules/demo/node_modules/leaf", "leaf", "2.0.0", source_kind="bundled", integrity=None)
    report = prepare(tmp_path, [instance(raw), child])
    assert not report["complete"] and len(report["sources"]) == 1
    assert report["issues"][0]["location"] == child["location"]


def test_redirects_and_other_registries_are_not_silently_followed(tmp_path, monkeypatch):
    raw = archive()
    calls = network(monkeypatch, raw, status=302)
    report = prepare(tmp_path, [instance(raw)])
    assert report["issues"][0]["reason"] == "npm_archive_http_status"
    report = prepare(tmp_path, [instance(raw, resolved="https://elsewhere.test/demo.tgz")], "second")
    assert len(calls) == 1 and report["issues"][0]["reason"] == "npm_registry_source_unsupported"


def test_malformed_archive_or_traversal_is_a_source_issue(tmp_path, monkeypatch):
    for index, raw in enumerate((b"not an archive", archive(extra={"../escape": b"bad"}))):
        network(monkeypatch, raw)
        report = prepare(tmp_path, [instance(raw)], f"run{index}")
        assert not report["complete"] and not report["sources"]
    assert not (tmp_path / "escape").exists()


def test_workspace_is_local_identity_not_registry_verified(tmp_path):
    local = tmp_path / "packages/demo"
    local.mkdir(parents=True)
    (local / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")
    entry = instance(b"", source_kind="workspace", source_location="packages/demo")
    report = prepare(tmp_path, [entry])
    assert report["complete"]
    assert report["sources"][0]["provenance"] == "local_workspace_package_json"
    assert "archive_sha256" not in report["sources"][0]


def test_workspace_cannot_escape_project(tmp_path):
    report = prepare(tmp_path, [instance(b"", source_kind="workspace", source_location="../outside")])
    assert not report["complete"] and not report["sources"]



def test_transient_publication_denial_retries_the_same_paths(tmp_path, monkeypatch):
    raw = archive()
    network(monkeypatch, raw)
    rename = sources.os.rename
    paths = []
    def retry_once(source, target):
        paths.append((source, target))
        if len(paths) == 1:
            raise PermissionError("temporary scanner handle")
        return rename(source, target)
    monkeypatch.setattr(sources.os, "rename", retry_once)
    monkeypatch.setattr(sources.time, "sleep", lambda _: None)
    report = prepare(tmp_path, [instance(raw)])
    assert report["complete"] and report["sources"][0]["source_publish_retries"] == 1
    assert paths[0] == paths[1]


def test_publication_cannot_leave_declared_output(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    extracted = root / "extracted"
    extracted.mkdir()
    with pytest.raises(ValueError, match="leaves"):
        sources._publish_source(extracted, tmp_path / "outside", root)
    assert extracted.is_dir() and not (tmp_path / "outside").exists()
