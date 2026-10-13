from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os

import pytest

from scripts.analysis_session import AnalysisSession
from scripts.python_graph import build_python_graph, capture_sources, source_fingerprint
from scripts import reachability

DIFF = "diff --git a/demo.py b/demo.py\n--- a/demo.py\n+++ b/demo.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n"


def project(tmp_path, monkeypatch):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir()
    lib.mkdir()
    (app / "main.py").write_text("from demo import danger\ndanger()\n", encoding="utf-8")
    (lib / "demo.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr(reachability, "get_diff", lambda _: DIFF)
    def scan(session, **kwargs):
        return reachability.check_reachability(["https://github.com/example/demo/commit/a"],
            purl="pkg:pypi/demo@1", project_dir=app, library_source=lib,
            analysis_session=session, **kwargs)
    return app, lib, scan


def test_snapshot_reused_across_parallel_findings_reads_each_file_once(tmp_path, monkeypatch):
    app, lib, scan = project(tmp_path, monkeypatch)
    original = Path.read_bytes
    reads = []
    def read(path):
        if path.suffix == ".py":
            reads.append(path)
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", read)
    session = AnalysisSession(freeze_sources=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: scan(session), range(8)))
    assert all(result["status"] == "reachable" for result in results)
    assert sorted(reads) == sorted([app / "main.py", lib / "demo.py"])
    metrics = session.metrics()
    assert metrics["source_captures"] == 2
    assert metrics["source_snapshot_hits"] == 14
    assert metrics["source_files"] == 2
    assert metrics["graph_builds"] == 1 and metrics["graph_hits"] == 7
    assert len({r["input_fingerprint"] for r in results}) == 1


def test_new_scan_reads_changed_contents_even_with_restored_timestamps(tmp_path, monkeypatch):
    app, lib, scan = project(tmp_path, monkeypatch)
    session = AnalysisSession(freeze_sources=True)
    before = scan(session)
    source = app / "main.py"
    stat = source.stat()
    source.write_text("from demo import danger\n#anger()\n", encoding="utf-8")
    os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    # Same scan keeps its declared snapshot, including after graph construction.
    during = scan(session)
    after = scan(AnalysisSession(freeze_sources=True))
    assert before["status"] == during["status"] == "reachable"
    assert before["input_fingerprint"] == during["input_fingerprint"]
    assert after["status"] == "no_path_found"
    assert before["input_fingerprint"] != after["input_fingerprint"]
    assert after["source_snapshot"]["reuse_scope"] == "scan"
    assert after["source_snapshot"]["atomic_filesystem_snapshot"] is False


def test_mutation_after_capture_cannot_change_graph_or_patch_mapping(tmp_path, monkeypatch):
    app, lib, scan = project(tmp_path, monkeypatch)
    session = AnalysisSession(freeze_sources=True)
    session.source_snapshot(app)
    session.source_snapshot(lib)
    (app / "main.py").write_text("pass\n", encoding="utf-8")
    (lib / "demo.py").write_text("def renamed():\n    return 9\n", encoding="utf-8")
    result = scan(session)
    assert result["status"] == "reachable"
    assert {m["symbol"] for m in result["mappings"]} == {"demo.danger"}
    assert result["source_snapshot"]["inputs"][0]["sha256"] != source_fingerprint(app)


def test_package_identity_and_encoded_source_are_captured(tmp_path):
    root = tmp_path / "encoded"
    root.mkdir()
    (root / "__init__.py").write_bytes(b"# coding: latin-1\r\ndef name():\r\n    return 'caf\xe9'\r\n")
    snapshot = capture_sources(root)
    (root / "__init__.py").unlink()
    root.rmdir()
    graph = build_python_graph(root, source_snapshots=(snapshot,))
    assert "encoded.name" in graph.symbols
    assert "café" in graph.modules["encoded"]["source"]
    assert "\r" not in graph.modules["encoded"]["source"]


def test_include_tests_is_a_separate_snapshot_and_graph_input(tmp_path):
    (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "test_demo.py").write_text("pass\n", encoding="utf-8")
    session = AnalysisSession(freeze_sources=True)
    normal = session.source_snapshot(tmp_path)
    full = session.source_snapshot(tmp_path, True)
    assert normal.digest != full.digest
    assert len(normal.files) == 1 and len(full.files) == 2
    with pytest.raises(ValueError, match="snapshots do not match"):
        build_python_graph(tmp_path, include_tests=True, source_snapshots=(normal,))
    assert "test_demo" in build_python_graph(tmp_path, include_tests=True, source_snapshots=(full,)).modules


def test_failed_capture_is_retried_and_never_published(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
    original = Path.read_bytes
    def fail(_):
        raise OSError("temporarily unreadable")
    session = AnalysisSession(freeze_sources=True)
    monkeypatch.setattr(Path, "read_bytes", fail)
    with pytest.raises(OSError):
        session.source_snapshot(tmp_path)
    assert session.metrics()["source_captures"] == 0
    monkeypatch.setattr(Path, "read_bytes", original)
    assert len(session.source_snapshot(tmp_path).files) == 1


def test_nonfrozen_checks_also_parse_the_hashed_bytes(tmp_path, monkeypatch):
    app, lib, scan = project(tmp_path, monkeypatch)
    from scripts import python_graph
    capture = python_graph.capture_sources
    def changing_capture(root, include_tests=False):
        snapshot = capture(root, include_tests)
        if Path(root) == app:
            (app / "main.py").write_text("pass\n", encoding="utf-8")
        return snapshot
    monkeypatch.setattr(python_graph, "capture_sources", changing_capture)
    result = scan(None)
    assert result["status"] == "reachable"
    assert result["source_snapshot"]["reuse_scope"] == "check"
    assert result["source_snapshot"]["inputs"][0]["sha256"] != source_fingerprint(app)
