from scripts.python_graph import build_python_graph
from scripts.patch_mapping import map_patch
from scripts.reachability import extract_commit_links, get_diff

REF = "https://github.com/owner/repo/commit/" + "a" * 40


def prepare(tmp_path, source):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text("pass\n")
    (lib / "core.py").write_text(source)
    return build_python_graph(app, dependency_sources=[lib]), str(lib)


def test_fix_parent_recovers_qualified_method_not_same_name(tmp_path, monkeypatch):
    before = "class A:\n    def call(self):\n        return 10\nclass B:\n    def call(self):\n        return 20\n"
    graph, lib = prepare(tmp_path, before.replace("return 10", "return 11"))
    diff = "diff --git a/core.py b/core.py\n--- a/core.py\n+++ b/core.py\n@@ -1,3 +1,3 @@\n class A:\n     def call(self):\n-        return 10\n+        return 30\n"
    monkeypatch.setattr("scripts.patch_evidence.get_parent_source", lambda *a: {"source": before, "url": "https://example/parent", "sha256": "abc"})
    evidence = []
    mappings, gaps = map_patch(diff, graph, lib, reference=REF, evidence=evidence)
    assert {m["symbol"] for m in mappings} == {"core.A.call"}
    assert mappings[0]["method"] == "qualified_symbol_from_fix_parent"
    assert mappings[0]["body_matches_fix_parent"] is False
    assert not gaps
    assert evidence[0]["parent_sha256"] == "abc"


def test_mismatching_parent_is_not_used(tmp_path, monkeypatch):
    graph, lib = prepare(tmp_path, "def call():\n    return 1\n")
    diff = "diff --git a/core.py b/core.py\n--- a/core.py\n+++ b/core.py\n@@ -1,2 +1,2 @@\n def call():\n-    return 2\n+    return 3\n"
    monkeypatch.setattr("scripts.patch_evidence.get_parent_source", lambda *a: {"source": "def call():\n    return 999\n", "url": "x", "sha256": "abc"})
    mappings, gaps = map_patch(diff, graph, lib, reference=REF)
    assert not mappings
    assert "fix_parent_context_mismatch" in gaps


def test_patch_and_diff_references_are_one_commit():
    assert extract_commit_links([REF, REF + ".patch", REF + ".diff#anchor"]) == [REF]


def test_patch_url_does_not_get_double_extension(monkeypatch):
    seen = []
    class Response:
        text = "diff"
        def raise_for_status(self): pass
    monkeypatch.setattr("scripts.reachability.requests.get", lambda url, **kw: (seen.append(url) or Response()))
    assert get_diff(REF + ".patch") == "diff"
    assert seen == [REF + ".diff"]
