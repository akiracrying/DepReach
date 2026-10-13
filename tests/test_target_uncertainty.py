from scripts.python_graph import build_python_graph
from scripts.reachability import check_reachability


def prepare(tmp_path, callback_body="return 1"):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text("from lib import keep, callback\nsaved = keep(callback)\n", encoding="utf-8")
    (lib / "lib.py").write_text("def keep(cb):\n    return cb\ndef callback():\n    " + callback_body + "\ndef danger():\n    return 42\n", encoding="utf-8")
    return app, lib


def test_escaped_callback_does_not_poison_unrelated_function(tmp_path):
    app, lib = prepare(tmp_path)
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.gaps() == ["callback_escapes"]
    assert graph.gaps(["lib.callback"]) == ["callback_escapes"]
    assert graph.gaps(["lib.danger"]) == []


def test_escaped_callback_can_indirectly_reach_target(tmp_path):
    app, lib = prepare(tmp_path, "return danger()")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.gaps(["lib.danger"]) == ["callback_escapes"]


def test_unknown_callback_body_cannot_be_proven_separate(tmp_path):
    app, lib = prepare(tmp_path, "return getattr(object(), 'run')()")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.gaps(["lib.danger"]) == ["callback_escapes"]


def test_unknown_external_callback_body_cannot_be_proven_separate(tmp_path):
    app, lib = prepare(tmp_path, "missing()")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert "callback_escapes" in graph.gaps(["lib.danger"])


def test_scoped_diagnostic_propagates_to_individual_finding(tmp_path, monkeypatch):
    app, lib = prepare(tmp_path)
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -5,2 +5,2 @@\n def danger():\n-    return 42\n+    return 43\n"
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: diff)
    report = check_reachability(["https://github.com/demo/lib/commit/a"], purl="pkg:pypi/lib@1", project_dir=app, library_source=lib)
    assert report["status"] == "no_path_found"
    assert report["function_results"][0]["blocking_reasons"] == []
    assert report["analysis_gaps"] == ["callback_escapes"]
    assert "callback_escapes" not in report["reasons"]
