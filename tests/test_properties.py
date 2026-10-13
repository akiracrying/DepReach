import pytest
from scripts.python_graph import build_python_graph


def graph_for(tmp_path, app_source, lib_source):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text(app_source, encoding="utf-8")
    (lib / "lib.py").write_text(lib_source + "\ndef danger(): return 1\n", encoding="utf-8")
    return build_python_graph(app, dependency_sources=[lib])


SOURCE = "class Client:\n    @property\n    def value(self):\n        return danger()\n"


@pytest.mark.parametrize("app", ["from lib import Client\nvalue = Client().value\n", "from lib import Client\nclient = Client()\nvalue = client.value\n"])
def test_instance_property_read_invokes_getter(tmp_path, app):
    graph = graph_for(tmp_path, app, SOURCE)
    path = graph.path(["lib.danger"], include_speculative=False)
    assert path == ["app.<module>", "lib.Client.value", "lib.danger"]
    assert graph.evidence(path)[0]["edge_kind"] == "property_getter_access"


def test_inherited_property_is_resolved_after_dependency_visit(tmp_path):
    graph = graph_for(tmp_path, "from lib import Child\nvalue = Child().value\n", SOURCE + "class Child(Client): pass\n")
    assert graph.path(["lib.danger"], include_speculative=False)


def test_class_attribute_is_descriptor_object_not_getter_invocation(tmp_path):
    graph = graph_for(tmp_path, "from lib import Client\nvalue = Client.value\n", SOURCE)
    assert not graph.path(["lib.danger"])


def test_calling_descriptor_object_does_not_invoke_getter(tmp_path):
    graph = graph_for(tmp_path, "from lib import Client\nvalue = Client.value\nvalue()\n", SOURCE)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert "property_result_call" in graph.gaps()


def test_custom_attribute_dispatch_stays_unknown(tmp_path):
    source = SOURCE + "    def __getattribute__(self, name):\n        return 3\n"
    graph = graph_for(tmp_path, "from lib import Client\nvalue = Client().value\n", source)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert "custom_descriptor_dispatch" in graph.gaps()


def test_shadowed_property_decorator_is_not_builtin_descriptor(tmp_path):
    graph = graph_for(tmp_path, "from lib import Client\nvalue = Client().value\n", "from missing import property\n" + SOURCE)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert "decorator_dispatch" in graph.gaps()


def test_returned_callable_is_not_assumed_to_be_getter_function(tmp_path):
    source = SOURCE.replace("return danger()", "return danger")
    graph = graph_for(tmp_path, "from lib import Client\nf = Client().value\nf()\n", source)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert "property_result_type_unknown" in graph.gaps()


def test_overriding_method_does_not_inherit_parent_property_behavior(tmp_path):
    source = SOURCE + "class Child(Client):\n    def value(self): return 4\n"
    graph = graph_for(tmp_path, "from lib import Child\nf = Child().value\n", source)
    assert not graph.path(["lib.danger"], include_speculative=False)


def test_callable_instance_invokes_call_not_constructor_again(tmp_path):
    source = "class Client:\n    def __init__(self): pass\n    def __call__(self): return danger()\n"
    graph = graph_for(tmp_path, "from lib import Client\ndef run():\n    obj = Client()\n    obj()\n", source)
    path = graph.path(["lib.danger"], include_speculative=False)
    assert path == ["app.run", "lib.Client.__call__", "lib.danger"]


def test_class_instantiation_alone_does_not_invoke_call(tmp_path):
    source = "class Client:\n    def __call__(self): return danger()\n"
    graph = graph_for(tmp_path, "from lib import Client\nobj = Client()\n", source)
    assert not graph.path(["lib.danger"], include_speculative=False)
