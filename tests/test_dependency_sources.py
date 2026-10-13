import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from scripts import dependency_sources as sources
from scripts import package_metadata as metadata
from scripts.analysis_session import AnalysisSession
from scripts.inventory import target_environment


class Response:
    def __init__(self, payload=None, content=b""):
        self.payload, self.content = payload, content
    def json(self): return self.payload
    def raise_for_status(self): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        for offset in range(0, len(self.content), size):
            yield self.content[offset:offset + size]


def wheel_service(monkeypatch, content, *, expected_hash=None, filename="demo-1-py3-none-any.whl"):
    url = "https://files.pythonhosted.org/packages/" + filename
    calls = []
    def get(address, **kwargs):
        calls.append(address)
        if address.endswith("/json"):
            return Response({"info": {"requires_dist": None}, "urls": [{"filename": filename, "url": url}]})
        if address.endswith("/simple/demo/"):
            return Response({"files": [{"filename": filename, "url": url,
                "core-metadata": {"sha256": expected_hash or hashlib.sha256(content).hexdigest()}}]})
        assert address == url + ".metadata"
        return Response(content=content)
    monkeypatch.setattr(metadata.requests, "get", get)
    return calls


def test_null_metadata_requires_verified_wheel_to_prove_no_dependencies(tmp_path, monkeypatch):
    calls = wheel_service(monkeypatch, b"Metadata-Version: 2.1\nName: demo\nVersion: 1\n\n")
    info = metadata.package_metadata("pkg:pypi/demo@1", tmp_path)
    assert info["requires_dist"] == []
    assert info["metadata_source"] == "verified_wheel_core_metadata"
    assert len(info["metadata_sha256"]) == 64
    assert len(calls) == 3
    assert metadata.package_metadata("pkg:pypi/demo@1", tmp_path) == info
    assert len(calls) == 3


@pytest.mark.parametrize("content, expected_hash", [
    (b"Metadata-Version: 2.1\nName: wrong\nVersion: 1\n\n", None),
    (b"Metadata-Version: 2.1\nName: demo\nVersion: 2\n\n", None),
    (b"Name: demo\nVersion: 1\n\n", None),
    (b"Metadata-Version: 2.2\nName: demo\nVersion: 1\nDynamic: Requires-Dist\n\n", None),
    (b"Metadata-Version: 2.1\nName: demo\nVersion: 1\n\n", "0" * 64),
])
def test_invalid_wheel_metadata_remains_unknown(tmp_path, monkeypatch, content, expected_hash):
    wheel_service(monkeypatch, content, expected_hash=expected_hash)
    info = metadata.package_metadata("pkg:pypi/demo@1", tmp_path)
    assert info["requires_dist"] is None
    assert info["metadata_failures"]


def test_metadata_size_limit(tmp_path, monkeypatch):
    calls = wheel_service(monkeypatch, b"x" * 100)
    monkeypatch.setattr(metadata, "MAX_METADATA_BYTES", 50)
    info = metadata.package_metadata("pkg:pypi/demo@1", tmp_path)
    assert info["requires_dist"] is None
    assert info["metadata_failures"][0]["error"] == "Wheel metadata exceeds size limit"
    assert len(calls) == 3


def test_foreign_native_wheel_is_not_downloaded(tmp_path, monkeypatch):
    # Keep a separate cache from the size-limit case: on Linux the default
    # environment equals this explicit target and would reuse its cached result.
    calls = wheel_service(monkeypatch, b"", filename="demo-1-cp310-cp310-win_amd64.whl")
    env = {"sys_platform": "linux", "os_name": "posix", "platform_system": "Linux"}
    info = metadata.package_metadata("pkg:pypi/demo@1", tmp_path, environment=env)
    assert info["requires_dist"] is None
    assert len(calls) == 1


def test_dependency_headers_and_python_requirement_are_preserved(tmp_path, monkeypatch):
    wheel_service(monkeypatch, b'Metadata-Version: 2.1\nName: demo\nVersion: 1\nRequires-Python: >=3.8\nRequires-Dist: leaf>=2; sys_platform == "win32"\nRequires-Dist: optional; extra == "socks"\n\n')
    info = metadata.package_metadata("pkg:pypi/demo@1", tmp_path)
    assert len(info["requires_dist"]) == 2
    assert info["requires_python"] == ">=3.8"


def fake_packages(tmp_path, monkeypatch, dependencies, *, python=None):
    def download(purl, directory):
        path = tmp_path / purl.rsplit("/", 1)[-1]
        path.mkdir(exist_ok=True)
        return str(path)
    def package_info(purl, directory, **kwargs):
        return {"requires_dist": dependencies[purl], "requires_python": python}
    monkeypatch.setattr(sources, "download_purl_source", download)
    monkeypatch.setattr(sources, "package_metadata", package_info)
    return {"components": [{"purl": purl} for purl in dependencies]}


def test_complete_intermediate_dependency_chain(tmp_path, monkeypatch):
    bom = fake_packages(tmp_path, monkeypatch, {"pkg:pypi/front@1": ["middle>=2,<3"],
        "pkg:pypi/middle@2": ["leaf==3"], "pkg:pypi/leaf@3": []})
    info = sources.prepare_source_context(bom, directory=tmp_path)
    assert info["complete"] and len(info["sources"]) == 3
    assert [(edge["from"], edge["to"]) for edge in info["dependency_edges"]] == [
        ("pkg:pypi/front@1", "pkg:pypi/middle@2"), ("pkg:pypi/middle@2", "pkg:pypi/leaf@3")]
    assert sources.prepare_source_context(bom, directory=tmp_path)["fingerprint"] == info["fingerprint"]


def test_missing_and_conflicting_versions_are_not_invented(tmp_path, monkeypatch):
    bom = fake_packages(tmp_path, monkeypatch, {"pkg:pypi/front@1": ["missing>=1", "leaf>=4"], "pkg:pypi/leaf@3": []})
    info = sources.prepare_source_context(bom, directory=tmp_path)
    assert not info["complete"]
    assert {i["reason"] for i in info["issues"]} == {"transitive_version_unresolved", "transitive_version_conflict"}
    assert len(info["sources"]) == 2


def test_conflicting_inventory_versions_are_not_merged(tmp_path, monkeypatch):
    bom = fake_packages(tmp_path, monkeypatch, {"pkg:pypi/demo@1": [], "pkg:pypi/demo@2": []})
    info = sources.prepare_source_context(bom, directory=tmp_path)
    assert info["sources"] == []
    assert info["issues"][0]["reason"] == "conflicting_component_versions"


@pytest.mark.parametrize("python, reason", [("not-a-specifier", "invalid_dependency_metadata"), ("<2", "incompatible_target_python")])
def test_invalid_or_incompatible_python_metadata_is_reported(tmp_path, monkeypatch, python, reason):
    bom = fake_packages(tmp_path, monkeypatch, {"pkg:pypi/demo@1": []}, python=python)
    info = sources.prepare_source_context(bom, directory=tmp_path)
    assert not info["complete"]
    assert info["issues"][0]["reason"] == reason


def test_markers_and_transitive_extras(tmp_path, monkeypatch):
    import json
    bom = fake_packages(tmp_path, monkeypatch, {"pkg:pypi/front@1": ['middle[socks]==2', 'windows; sys_platform == "win32"'],
        "pkg:pypi/middle@2": ['leaf==3; extra == "socks"'], "pkg:pypi/leaf@3": []})
    env = target_environment({"sys_platform": "linux"})
    bom["metadata"] = {"properties": [{"name": "depreach:inventory", "value": json.dumps({"environment": env})}]}
    info = sources.prepare_source_context(bom, directory=tmp_path)
    assert info["complete"] and len(info["dependency_edges"]) == 2


def test_shared_graph_concurrency_and_failed_build_retry():
    session = AnalysisSession()
    created = []
    def build():
        value = object()
        created.append(value)
        return value
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _: session.graph("same", build), range(8)))
    assert len(created) == 1 and all(value is created[0] for value in values)
    assert session.metrics() == {"graph_builds": 1, "graph_hits": 7}
    def fail(): raise ValueError("incomplete graph")
    with pytest.raises(ValueError): session.graph("failed", fail)
    assert session.graph("failed", build) is created[-1]
    assert session.metrics()["graph_builds"] == 2


def test_reachability_reuses_graph_across_findings_and_invalidates_on_content(tmp_path, monkeypatch):
    from scripts import reachability
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    source = app / "main.py"
    source.write_text("from demo import danger\ndanger()\n", encoding="utf-8")
    (lib / "demo.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    diff = "diff --git a/demo.py b/demo.py\n--- a/demo.py\n+++ b/demo.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n"
    monkeypatch.setattr(reachability, "get_diff", lambda _: diff)
    session = AnalysisSession()
    def scan(cve, context=None):
        return reachability.check_reachability(["https://github.com/example/demo/commit/a"],
            purl="pkg:pypi/demo@1", project_dir=app, library_source=lib,
            analysis_session=session, source_context=context, cve=cve)
    assert scan("CVE-A")["status"] == "reachable"
    assert scan("CVE-B")["status"] == "reachable"
    assert session.metrics() == {"graph_builds": 1, "graph_hits": 1}
    source.write_text("pass\n", encoding="utf-8")
    assert scan("CVE-A")["status"] == "no_path_found"
    assert session.metrics()["graph_builds"] == 2
    incomplete = {"fingerprint": "incomplete", "issues": [{"reason": "transitive_version_unresolved"}]}
    assert scan("CVE-A", incomplete)["status"] == "unknown"
