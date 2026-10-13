import pytest
from scripts.python_graph import build_python_graph
from scripts.source_uncertainty import source_issue_scope
from scripts.reachability import check_reachability


def setup(tmp_path, app_source):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text(app_source, encoding="utf-8")
    (lib / "lib.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    context = {"fingerprint": "incomplete-inventory", "sources": [{"purl": "pkg:pypi/lib@1", "source": str(lib)}],
               "issues": [{"purl": "pkg:pypi/lib@1", "reason": "transitive_version_unresolved", "requirement": "missing>=1"}]}
    return app, lib, context


def test_unimported_component_does_not_poison_other_analysis(tmp_path):
    app, lib, context = setup(tmp_path, "pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    blocking, unrelated = source_issue_scope(graph, context)
    assert blocking == [] and len(unrelated) == 1


def test_imported_component_still_requires_its_dependency_closure(tmp_path):
    app, lib, context = setup(tmp_path, "import lib\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    blocking, unrelated = source_issue_scope(graph, context)
    assert len(blocking) == 1 and unrelated == []


def test_unidentified_missing_source_is_never_discarded(tmp_path):
    app, lib, context = setup(tmp_path, "pass\n")
    context["sources"] = []
    graph = build_python_graph(app, dependency_sources=[lib])
    assert source_issue_scope(graph, context)[0] == context["issues"]


@pytest.mark.parametrize("app_source, expected", [("pass\n", "no_path_found"),
    ("def run(name):\n    __import__(name)\n", "unknown")])
def test_dynamic_import_blocks_negative_even_when_metadata_gap_is_scoped(tmp_path, monkeypatch, app_source, expected):
    app, lib, context = setup(tmp_path, app_source)
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n")
    report = check_reachability(["https://github.com/example/lib/commit/a"], purl="pkg:pypi/lib@1",
        project_dir=app, library_source=lib, source_context=context)
    assert report["status"] == expected
    assert report["blocking_source_issues"] == []
    assert report["nonblocking_source_issues"]
