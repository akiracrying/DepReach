from pathlib import Path

from scripts.python_graph import build_python_graph, source_fingerprint
from scripts.reachability import check_reachability


def write(root, file, source):
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_import_alias_reexport_wrapper_and_evidence(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from external import public as alias\ndef route():\n    alias()\n")
    write(lib, "src/external/__init__.py", "from .core import public\n")
    write(lib, "src/external/core.py", "def public():\n    danger()\ndef danger():\n    return 1\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    path = graph.path(["external.core.danger"])
    assert path == ["app.route", "external.core.public", "external.core.danger"]
    assert graph.evidence(path)[0]["call_line"] == 3


def test_same_named_methods_and_instance_resolution(tmp_path):
    write(tmp_path, "app.py", "class A:\n    def run(self):\n        first()\nclass B:\n    def run(self):\n        second()\ndef first(): pass\ndef second(): pass\ndef main():\n    a = A()\n    a.run()\n")
    graph = build_python_graph(tmp_path)
    assert graph["app.A.run"] == {"app.first"}
    assert graph["app.B.run"] == {"app.second"}
    assert "app.A.run" in graph["app.main"]
    assert "app.B.run" not in graph["app.main"]


def test_aliases_do_not_leak_between_files_and_parameters_shadow(tmp_path):
    write(tmp_path, "a.py", "import external as e\ndef main(e):\n    e.danger()\n")
    write(tmp_path, "b.py", "def main():\n    e.danger()\n")
    graph = build_python_graph(tmp_path)
    assert "external.danger" not in graph["a.main"]
    assert "external.danger" not in graph["b.main"]
    assert "unresolved_call" in graph.gaps()


def test_nested_function_body_not_attached_to_parent(tmp_path):
    write(tmp_path, "app.py", "def outer():\n    def inner():\n        danger()\ndef danger(): pass\n")
    graph = build_python_graph(tmp_path)
    assert not graph["app.outer"]
    assert graph["app.outer.inner"] == {"app.danger"}


def test_transitive_dependency_path(tmp_path):
    app, a, b = [tmp_path / name for name in ("app", "a", "b")]
    write(app, "app.py", "import first\nfirst.call()\n")
    write(a, "first.py", "from second import danger\ndef call():\n    danger()\n")
    write(b, "second.py", "def danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[a, b])
    assert graph.path(["second.danger"]) == ["app.<module>", "first.call", "second.danger"]


def test_excludes_environments_tests_outputs_and_fingerprints_content(tmp_path):
    write(tmp_path, "app.py", "def main(): pass\n")
    for folder in ("venv", ".venv", "tests", "data", "reports", "tests_local"):
        write(tmp_path, f"{folder}/junk.py", "invalid syntax!!")
    before = source_fingerprint(tmp_path)
    graph = build_python_graph(tmp_path)
    assert set(graph.modules) == {"app"}
    assert not graph.diagnostics
    write(tmp_path, "app.py", "def main(): return 1\n")
    assert before != source_fingerprint(tmp_path)
    assert "parse_error" in build_python_graph(tmp_path, include_tests=True).gaps()


def test_parse_failure_and_dynamic_dispatch_are_visible(tmp_path):
    write(tmp_path, "broken.py", "bad syntax!")
    write(tmp_path, "app.py", "def main(obj, name):\n    getattr(obj, name)()\n")
    graph = build_python_graph(tmp_path)
    assert {"parse_error", "dynamic_dispatch", "unresolved_call"} <= set(graph.gaps())


DIFF = """diff --git a/src/external/core.py b/src/external/core.py
--- a/src/external/core.py
+++ b/src/external/core.py
@@ -1,2 +1,2 @@
 def danger():
-    return 1
+    return 2
"""


def scan(tmp_path, monkeypatch, app_source="from external.core import danger as alias\nalias()\n", lib_source="def danger():\n    return 1\n", diff=DIFF):
    app, lib = tmp_path / "app", tmp_path / "library"
    write(app, "app.py", app_source)
    write(lib, "src/external/core.py", lib_source)
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: diff)
    return check_reachability(["https://github.com/owner/different-repo-name/commit/abc"],
                              purl="pkg:pypi/different-distribution-name@1.0",
                              project_dir=app, library_source=lib)


def test_mapping_uses_source_paths_not_distribution_or_repo_name(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch)
    assert report["status"] == "reachable"
    assert report["paths"][0][-1]["symbol"] == "external.core.danger"
    assert report["mappings"][0]["method"] == "exact_old_context"


def test_patch_line_number_changes_do_not_break_exact_context(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch, lib_source="# unrelated earlier release lines\n\ndef danger():\n    return 1\n")
    assert report["status"] == "reachable"
    assert report["mappings"][0]["line"] == 4


def test_no_path_is_not_unknown_when_simple_model_is_complete(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch, app_source="def main():\n    return 5\n")
    assert report["status"] == "no_path_found"
    assert report["is_reachable"] is False


def test_unmapped_patch_never_becomes_false(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch, lib_source="def danger():\n    return 999\n")
    assert report["status"] == "unknown"
    assert report["is_reachable"] is None
    assert "patch_context_not_uniquely_matched" in report["reasons"]


def test_missing_transitive_body_is_unknown(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch, app_source="import intermediary\nintermediary.call()\n")
    assert report["status"] == "unknown"
    assert "unresolved_external_calls" in report["reasons"]


def test_fix_fetch_failure_is_unknown(tmp_path, monkeypatch):
    report = scan(tmp_path, monkeypatch, diff=None)
    assert report["status"] == "unknown"
    assert "fix_diff_unavailable" in report["reasons"]


def test_inherited_method_and_context_manager_path(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from client import Session\ndef run():\n    with Session() as session:\n        session.send()\n")
    write(lib, "client.py", "class Mixin:\n    def send(self):\n        danger()\nclass Session(Mixin):\n    def __enter__(self):\n        return self\n    def __exit__(self, *args): pass\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.path(["client.danger"]) == ["app.run", "client.Mixin.send", "client.danger"]


def test_expanding_module_alias_terminates():
    from scripts.python_graph import PythonGraph
    graph = PythonGraph()
    graph.aliases["pkg.version"] = "pkg.version.version"
    assert graph.resolve("pkg.version.unknown") is None
    assert "cyclic_alias" in graph.gaps()


def test_duplicate_definition_is_not_unambiguous_evidence(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import call\ncall()\n")
    write(lib, "lib.py", "def call():\n    danger()\ndef call():\n    return 1\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.path(["lib.danger"]) == []
    assert "ambiguous_call_identity" in graph.gaps()


def test_comprehension_local_does_not_resolve_to_import(tmp_path):
    write(tmp_path, "app.py", "from external import danger\ndef run(values):\n    return [danger() for danger in values]\n")
    graph = build_python_graph(tmp_path)
    assert "external.danger" not in graph["app.run"]
    assert "comprehension_dispatch" in graph.gaps()


def test_qualified_function_assignment_alias(tmp_path):
    write(tmp_path, "app.py", "from external import danger\ndef run():\n    alias = danger\n    alias()\n")
    graph = build_python_graph(tmp_path)
    assert "external.danger" in graph["app.run"]


def test_patch_uses_innermost_class_method_not_same_name(tmp_path, monkeypatch):
    source = "class A:\n    def danger(self):\n        return 1\nclass B:\n    def danger(self):\n        return 2\n"
    diff = "diff --git a/src/external/core.py b/src/external/core.py\n--- a/src/external/core.py\n+++ b/src/external/core.py\n@@ -1,3 +1,3 @@\n class A:\n     def danger(self):\n-        return 1\n+        return 3\n"
    report = scan(tmp_path, monkeypatch, app_source="from external.core import B\nB().danger()\n", lib_source=source, diff=diff)
    assert report["status"] == "no_path_found"
    assert {m["symbol"] for m in report["mappings"]} == {"external.core.A.danger"}


def test_cache_invalidates_when_project_library_or_diff_changes(tmp_path, monkeypatch):
    from scripts.cache import init_cache
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from external.core import danger\ndanger()\n")
    write(lib, "src/external/core.py", "def danger():\n    return 1\n")
    init_cache(tmp_path / "cache.db")
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: DIFF)
    kwargs = dict(purl="pkg:pypi/demo@1", cve="CVE-X", project_dir=app, library_source=lib, use_cache=True)
    refs = ["https://github.com/x/y/commit/z"]
    first = check_reachability(refs, **kwargs)
    assert first["status"] == "reachable" and not first["cache_hit"]
    assert check_reachability(refs, **kwargs)["cache_hit"]
    write(app, "app.py", "def unrelated():\n    return 1\n")
    changed = check_reachability(refs, **kwargs)
    assert changed["status"] == "no_path_found" and not changed["cache_hit"]
    write(lib, "src/external/core.py", "def danger():\n    return 999\n")
    assert check_reachability(refs, **kwargs)["status"] == "unknown"


def test_new_function_not_assigned_to_previous_function(tmp_path, monkeypatch):
    diff = "diff --git a/src/external/core.py b/src/external/core.py\n--- a/src/external/core.py\n+++ b/src/external/core.py\n@@ -1,2 +1,5 @@\n def danger():\n     return 1\n+\n+def new_helper():\n+    return 2\n"
    report = scan(tmp_path, monkeypatch, diff=diff)
    assert report["status"] == "unknown"
    assert not report["mappings"]


def test_unknown_base_constructor_prevents_negative_conclusion(tmp_path):
    write(tmp_path, "app.py", "from missing import Base\nclass Child(Base):\n    pass\nChild()\n")
    graph = build_python_graph(tmp_path)
    assert "inheritance_or_metaclass" in graph.gaps()


def test_implicit_attribute_dispatch_is_not_silent(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import Object\no = Object()\nvalue = o.dynamic\n")
    write(lib, "lib.py", "class Object:\n    def __getattr__(self, name):\n        return danger()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert "implicit_object_protocol" in graph.gaps()


def test_while_bindings_are_not_treated_as_complete(tmp_path):
    write(tmp_path, "app.py", "from external import danger\ndef run(flag):\n    alias = danger\n    while flag:\n        alias = None\n    alias()\n")
    graph = build_python_graph(tmp_path)
    assert "loop_control_flow" in graph.gaps()


def test_passed_function_has_explicit_possible_callback_edge(tmp_path):
    write(tmp_path, "app.py", "from missing import invoke\nfrom lib import danger\ndef run():\n    invoke(danger)\n")
    lib = tmp_path / "dependency"
    write(lib, "lib.py", "def danger(): pass\n")
    # Avoid nested dependency indexing as first-party.
    app = tmp_path / "application"
    write(app, "app.py", (tmp_path / "app.py").read_text())
    graph = build_python_graph(app, dependency_sources=[lib])
    path = graph.path(["lib.danger"])
    assert path == ["app.run", "lib.danger"]
    assert graph.evidence(path)[0]["edge_kind"] == "passed_callable_may_be_invoked"
    assert "callback_argument" in graph.gaps()


def test_class_passed_as_value_is_not_instance_call(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import Client\nfrom missing import register\nregister(Client)\n")
    write(lib, "lib.py", "class Client:\n    def __call__(self): danger()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert not graph.path(["lib.danger"])


def test_factory_parameter_shadow_is_not_global_class(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import factory\nobj = factory(None)\nobj.send()\n")
    write(lib, "lib.py", "class Client:\n    def send(self): danger()\ndef factory(Client):\n    return Client()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert not graph.path(["lib.danger"])


def test_registry_return_and_class_attribute_paths(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import Session\ndef run():\n    s = Session()\n    s.send()\n")
    write(lib, "lib.py", "class Adapter:\n    def send(self): danger()\nclass Session:\n    def __init__(self):\n        self.adapters = {}\n        self.mount('https', Adapter())\n    def mount(self, key, value):\n        self.adapters[key] = value\n    def get_adapter(self):\n        for key, value in self.adapters.items():\n            return value\n    def send(self):\n        adapter = self.get_adapter()\n        adapter.send()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.path(["lib.danger"]) == ["app.run", "lib.Session.send", "lib.Adapter.send", "lib.danger"]
    assert "possible_return_type_dispatch" in graph.gaps()
    assert graph.dispatch_models[0]["completeness"] == "not_claimed"


def test_dependency_setup_files_do_not_collide(tmp_path):
    app, a, b = tmp_path / "app", tmp_path / "a", tmp_path / "b"
    write(app, "app.py", "pass\n")
    write(a, "setup.py", "raise Exception()\n")
    write(b, "setup.py", "raise Exception()\n")
    write(a, "first.py", "pass\n")
    write(b, "second.py", "pass\n")
    graph = build_python_graph(app, dependency_sources=[a,b])
    assert "setup" not in graph.modules
    assert "duplicate_module" not in graph.gaps()


def test_literal_getattr_resolves_but_variable_getattr_does_not(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "import lib\ndef run():\n    getattr(lib, 'danger')()\n")
    write(lib, "lib.py", "def danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.path(["lib.danger"]) == ["app.run", "lib.danger"]


def test_unimported_broken_module_does_not_poison_negative(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "def run(): return 1\n")
    write(lib, "safe.py", "def danger(): return 2\n")
    write(lib, "unused.py", "this is invalid syntax !\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert any(d["reason"] == "parse_error" for d in graph.diagnostics)
    assert not graph.path(["safe.danger"])
    assert not graph.gaps()
    write(app, "app.py", "import unused\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert "parse_error" in graph.gaps()


def test_imported_duplicate_module_blocks_positive_evidence(tmp_path):
    app, a, b = tmp_path / "app", tmp_path / "a", tmp_path / "b"
    write(app, "app.py", "from shared import danger\ndanger()\n")
    write(a, "shared.py", "def danger(): return 1\n")
    write(b, "shared.py", "def danger(): return 2\n")
    graph = build_python_graph(app, dependency_sources=[a,b])
    assert not graph.path(["shared.danger"])
    assert "ambiguous_call_identity" in graph.gaps()


def test_callable_instance_passed_to_consumer_has_possible_edge(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import Client\nfrom missing import register\nclient = Client()\nregister(client)\n")
    write(lib, "lib.py", "class Client:\n    def __call__(self): danger()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    path = graph.path(["lib.danger"])
    assert path == ["app.<module>", "lib.Client.__call__", "lib.danger"]
    assert graph.evidence(path)[0]["edge_kind"] == "passed_callable_may_be_invoked"


def test_known_instance_class_attribute_resolves_method(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    write(app, "app.py", "from lib import App\nApp().run()\n")
    write(lib, "lib.py", "class Interface:\n    def save(self): danger()\nclass App:\n    interface = Interface()\n    def run(self): self.interface.save()\ndef danger(): pass\n")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.path(["lib.danger"])[-3:] == ["lib.App.run", "lib.Interface.save", "lib.danger"]
