import pytest
from scripts.reachability import (
    extract_commit_links,
    extract_repo_name,
    extract_functions_from_diff,
    is_func_reachable,
)


def test_extract_commit_links_empty():
    assert extract_commit_links([]) == []
    assert extract_commit_links(["https://example.com/issue/1"]) == []


def test_extract_commit_links_filters_commit_urls():
    refs = [
        "https://github.com/owner/repo/commit/abc123",
        "https://gitlab.com/x/y/-/commit/def",
        "https://example.com/not-commit",
    ]
    got = extract_commit_links(refs)
    assert len(got) == 2
    assert "commit" in got[0] and "commit" in got[1]


def test_extract_repo_name():
    assert extract_repo_name("https://github.com/owner/repo/commit/abc") == "repo"
    assert extract_repo_name("https://github.com/a/b/") == "b"
    assert extract_repo_name("https://github.com/a") is None
    assert extract_repo_name("https://github.com/") is None


def test_extract_functions_from_diff_python():
    diff = """
diff --git a/b/foo.py b/b/foo.py
index 123..456 100644
--- a/b/foo.py
+++ b/b/foo.py
@@ -1,3 +1,4 @@
+def new_func():
+    pass
 def bar():
     x = 1
-    return x
+    return x + 1
"""
    funcs = extract_functions_from_diff(diff)
    assert "new_func" in funcs
    assert len(funcs) >= 1


def test_extract_functions_from_diff_empty():
    assert extract_functions_from_diff("") == set()
    assert extract_functions_from_diff("diff --git a/x.txt b/x.txt") == set()


def test_is_func_reachable_direct():
    graph = {"a": {"b"}, "b": set()}
    assert is_func_reachable({"a"}, "b", graph) is True
    assert is_func_reachable({"a"}, "a", graph) is True


def test_is_func_reachable_indirect():
    graph = {"a": {"b"}, "b": {"c"}, "c": set()}
    assert is_func_reachable({"a"}, "c", graph) is True
    assert is_func_reachable({"b"}, "c", graph) is True


def test_is_func_reachable_not_reachable():
    graph = {"a": {"b"}, "b": set(), "c": set()}
    assert is_func_reachable({"a"}, "c", graph) is False
    assert is_func_reachable(set(), "a", graph) is False
