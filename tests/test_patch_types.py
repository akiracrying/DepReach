import pytest

from scripts.patch_changes import parse_patch_files, change_kind
from scripts.reachability import check_reachability
from scripts.python_graph import build_python_graph

REF = "https://github.com/example/lib/commit/a"


def diff_for(file, before, after):
    old, new = before.splitlines(), after.splitlines()
    return f"diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -1,{len(old)} +1,{len(new)} @@\n" + "\n".join([*("-" + line for line in old), *("+" + line for line in new)]) + "\n"


def scan(tmp_path, monkeypatch, app_source, lib_source, diff, *, name="lib.py"):
    app, lib = tmp_path / "app", tmp_path / "library"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text(app_source, encoding="utf-8")
    (lib / name).write_text(lib_source, encoding="utf-8")
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: diff)
    return check_reachability([REF], purl="pkg:pypi/lib@1", project_dir=app, library_source=lib)


@pytest.mark.parametrize("file, kind", [
    ("native/core.c", "native_code_or_extension"),
    ("native/core.rs", "native_code_or_extension"),
    ("lib/cacert.pem", "certificate_or_trust_data"),
    ("pyproject.toml", "package_or_build_configuration"),
    ("lib/settings.json", "data_or_configuration"),
])
def test_unsupported_change_has_explicit_kind_not_false(tmp_path, monkeypatch, file, kind):
    report = scan(tmp_path, monkeypatch, "pass\n", "pass\n", diff_for(file, "old\n", "new\n"))
    assert report["status"] == "unsupported" and report["is_reachable"] is None
    assert report["unsupported_changes"][0]["change_kind"] == kind
    assert not report["mappings"]


def test_binary_only_change_is_not_invisible(tmp_path, monkeypatch):
    diff = "diff --git a/lib/resource.bin b/lib/resource.bin\nBinary files a/lib/resource.bin and b/lib/resource.bin differ\n"
    report = scan(tmp_path, monkeypatch, "pass\n", "pass\n", diff)
    assert report["status"] == "unsupported"
    assert report["unsupported_changes"][0]["change_kind"] == "binary_resource"


def test_mixed_native_and_python_patch_blocks_negative(tmp_path, monkeypatch):
    source = "def danger():\n    return 1\n"
    diff = diff_for("lib.py", source, source.replace("1", "2")) + diff_for("core.c", "old\n", "new\n")
    report = scan(tmp_path, monkeypatch, "pass\n", source, diff)
    assert report["status"] == "unknown" and report["mappings"]
    assert report["unsupported_changes"]


def test_malformed_hunk_is_not_mapped(tmp_path, monkeypatch):
    source = "def danger():\n    return 1\n"
    diff = diff_for("lib.py", source, source.replace("1", "2")).replace("-1,2 +1,2", "-1,3 +1,3")
    report = scan(tmp_path, monkeypatch, "from lib import danger\ndanger()\n", source, diff)
    assert report["status"] == "unknown" and not report["mappings"]
    assert "malformed_or_truncated_hunk" in report["reasons"]


@pytest.mark.parametrize("app", ["import lib\nvalue = lib.LIMIT\n", "from lib import LIMIT\n", "from lib import run\nrun()\n"])
def test_module_literal_data_reference(tmp_path, monkeypatch, app):
    source = "LIMIT = 100\ndef run():\n    return LIMIT\n"
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1 +1 @@\n-LIMIT = 100\n+LIMIT = 10\n"
    report = scan(tmp_path, monkeypatch, app, source, diff)
    assert report["status"] == "reachable"
    assert {item["symbol"] for item in report["mappings"]} == {"lib.LIMIT"}
    assert report["target_kind"] == "patch_associated_code_or_data"
    assert report["paths"][0][-2]["edge_kind"] == "data_reference"


def test_module_import_alone_is_not_a_reference_to_unused_data(tmp_path, monkeypatch):
    source = "LIMIT = 100\n"
    report = scan(tmp_path, monkeypatch, "import lib\n", source, diff_for("lib.py", source, source.replace("100", "10")))
    assert report["status"] == "no_path_found"
    assert report["function_results"][0]["target_kind"] == "data"


def test_later_declared_constant_still_reached_from_function(tmp_path, monkeypatch):
    source = "def run():\n    return LIMIT\nLIMIT = 100\n"
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -3 +3 @@\n-LIMIT = 100\n+LIMIT = 10\n"
    report = scan(tmp_path, monkeypatch, "from lib import run\nrun()\n", source, diff)
    assert report["status"] == "reachable"
    assert report["paths"][0][-1]["symbol"] == "lib.LIMIT"


def test_parameter_shadow_does_not_read_module_constant(tmp_path, monkeypatch):
    source = "LIMIT = 100\ndef run(LIMIT):\n    return LIMIT\n"
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1 +1 @@\n-LIMIT = 100\n+LIMIT = 10\n"
    report = scan(tmp_path, monkeypatch, "from lib import run\nrun(2)\n", source, diff)
    assert report["status"] == "no_path_found"


def test_class_literal_data_reference(tmp_path, monkeypatch):
    source = "class Config:\n    LIMIT = 100\n"
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n class Config:\n-    LIMIT = 100\n+    LIMIT = 10\n"
    report = scan(tmp_path, monkeypatch, "from lib import Config\nvalue = Config.LIMIT\n", source, diff)
    assert report["status"] == "reachable"
    assert report["paths"][0][-1]["symbol"] == "lib.Config.LIMIT"


def test_repeated_literal_definition_is_ambiguous(tmp_path, monkeypatch):
    source = "LIMIT = 100\nLIMIT = 200\n"
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1 +1 @@\n-LIMIT = 100\n+LIMIT = 10\n"
    report = scan(tmp_path, monkeypatch, "import lib\nvalue = lib.LIMIT\n", source, diff)
    assert report["status"] == "unknown"
    assert report["is_reachable"] is None


def test_renamed_file_matches_old_context_in_new_path(tmp_path, monkeypatch):
    source = "def danger():\n    return 1\n"
    diff = "diff --git a/old.py b/lib.py\nsimilarity index 80%\nrename from old.py\nrename to lib.py\n--- a/old.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n"
    report = scan(tmp_path, monkeypatch, "from lib import danger\ndanger()\n", source, diff)
    assert report["status"] == "reachable"
    assert report["patch_evidence"][0]["new_file"] == "lib.py"


def test_quoted_paths_and_unchanged_no_newline_marker():
    diff = 'diff --git "a/some file.py" "b/some file.py"\n--- "a/some file.py"\n+++ "b/some file.py"\n@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n'
    files = parse_patch_files(diff)
    assert files[0]["old_file"] == "some file.py"
    assert files[0]["hunks"][0]["valid"]


@pytest.mark.parametrize("binding", ["alias = None\nalias = danger\n", "alias = danger\nalias = None\n"])
def test_constant_function_rebinding_does_not_prove_absence(tmp_path, monkeypatch, binding):
    source = "def danger():\n    return 1\n" + binding
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n"
    report = scan(tmp_path, monkeypatch, "import lib\nlib.alias()\n", source, diff)
    assert report["status"] == "unknown"
    assert "duplicate_definition" in report["reasons"]
