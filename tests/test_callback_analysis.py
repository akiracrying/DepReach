import pytest
from scripts.python_graph import build_python_graph
from scripts.reachability import check_reachability
from scripts.sarif_report import vulns_to_sarif


def graph_for(tmp_path, consumer, invocation="consume(danger)"):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(exist_ok=True); lib.mkdir(exist_ok=True)
    (app / "app.py").write_text("from lib import consume, danger\n" + invocation + "\n", encoding="utf-8")
    (lib / "lib.py").write_text(consumer + "\ndef danger():\n    return 1\n", encoding="utf-8")
    return build_python_graph(app, dependency_sources=[lib])


def test_direct_consumer_invocation_has_source_evidence(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb()\n")
    path = graph.path(["lib.danger"], include_speculative=False)
    assert path == ["app.<module>", "lib.danger"]
    edge = graph.evidence(path)[0]
    assert edge["edge_kind"] == "callback_invocation"
    assert edge["callback_evidence"]["consumer"] == "lib.consume"
    assert edge["callback_evidence"]["parameter"] == "cb"
    assert edge["callback_evidence"]["invocation_lines"] == [2]


@pytest.mark.parametrize("consumer, invocation", [
    ("def consume(*, cb):\n    cb()", "consume(cb=danger)"),
    ("def consume(value, cb=None):\n    cb()", "consume(1, cb=danger)"),
    ("def consume(cb, /):\n    cb()", "consume(danger)"),
])
def test_callback_parameter_binding(tmp_path, consumer, invocation):
    graph = graph_for(tmp_path, consumer, invocation)
    assert graph.path(["lib.danger"], include_speculative=False)


@pytest.mark.parametrize("consumer, invocation", [
    ("def consume(cb):\n    cb = lambda: None\n    cb()", "consume(danger)"),
    ("def consume(cb):\n    pass", "consume(danger, cb=danger)"),
    ("def consume(cb, /):\n    cb()", "consume(cb=danger)"),
    ("def consume(required, cb):\n    cb()", "consume(cb=danger)"),
    ("def consume(cb):\n    cb()", "consume(*[], cb=danger)"),
    ("async def consume(cb):\n    cb()", "consume(danger)"),
    ("def consume(cb):\n    yield cb()", "consume(danger)"),
    ("@decorator\ndef consume(cb):\n    cb()", "consume(danger)"),
    ("def consume(cb):\n    def nested():\n        cb()", "consume(danger)"),
])
def test_unsupported_dispatch_or_invalid_binding_is_not_verified(tmp_path, consumer, invocation):
    graph = graph_for(tmp_path, consumer, invocation)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert graph.callback_models[0]["disposition"] == "unresolved"


@pytest.mark.parametrize("body, disposition", [
    ("    return None", "unused"),
    ("    registry.append(cb)", "escaped"),
    ("    return cb", "returned"),
])
def test_ignored_or_stored_callback_is_not_an_invocation(tmp_path, body, disposition):
    graph = graph_for(tmp_path, "def consume(cb):\n" + body)
    assert not graph.path(["lib.danger"])
    assert graph.callback_models[0]["disposition"] == disposition
    if disposition == "unused":
        assert not graph.gaps()


def test_argument_does_not_leak_from_unreachable_dependency_call(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    cb()\ndef unused():\n    consume(danger)\ndef safe(): pass", "from lib import safe\nconsume(safe)")
    assert not graph.path(["lib.danger"])
    assert graph.path(["lib.safe"], include_speculative=False)


def test_non_speculative_alternative_path_is_preferred(tmp_path):
    graph = graph_for(tmp_path, "from missing import consume\ndef wrapper():\n    danger()", "consume(danger)\nfrom lib import wrapper\nwrapper()")
    path = graph.path(["lib.danger"], include_speculative=False)
    assert path == ["app.<module>", "lib.wrapper", "lib.danger"]


def test_speculative_callback_does_not_export_reachable(tmp_path, monkeypatch):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text("from missing import consume\nfrom lib import danger\nconsume(danger)\n", encoding="utf-8")
    (lib / "lib.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    diff = "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n"
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: diff)
    report = check_reachability(["https://github.com/demo/lib/commit/a"], purl="pkg:pypi/lib@1", project_dir=app, library_source=lib)
    assert report["status"] == "unknown" and report["is_reachable"] is None
    assert report["paths"] == [] and len(report["speculative_paths"]) == 1
    assert "speculative_callback_path" in report["reasons"]
    finding = vulns_to_sarif([{"cve": "TEST", "reachability": report}])["runs"][0]["results"][0]
    assert finding["properties"]["isReachable"] is None
    assert not finding.get("codeFlows")


def test_html_keeps_speculation_separate(tmp_path):
    import json
    from scripts.html_report import generate_html_report
    from scripts.reachability_result import result
    report = result("unknown", reasons=["speculative_callback_path"],
        speculative_paths=[[{"symbol": "app.run"}, {"symbol": "lib.danger"}]])
    (tmp_path / "sbom.json").write_text(json.dumps({"components": []}), encoding="utf-8")
    (tmp_path / "report.json").write_text(json.dumps([{"cve": "TEST", "reachability": report}]), encoding="utf-8")
    generate_html_report("sample", tmp_path / "sbom.json", tmp_path / "report.json", tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Speculative callback path (invocation unverified)" in html
    assert ">unknown</span>" in html


def test_direct_call_wins_over_same_pair_speculation(tmp_path):
    graph = graph_for(tmp_path, "from missing import consume", "consume(danger)\ndanger()")
    path = graph.path(["lib.danger"], include_speculative=False)
    assert path and graph.evidence(path)[0]["edge_kind"] == "static_call"


@pytest.mark.parametrize("invocation", ["consume(danger)()", "cb = consume(danger)\ncb()",
    "cb = consume(cb=danger)\ncb()", "consume(consume(danger))()"])
def test_returned_callback_is_invoked_at_the_caller(tmp_path, invocation):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb", invocation)
    assert graph.path(["lib.danger"], include_speculative=False)
    assert all(model["disposition"] == "returned" for model in graph.callback_models)
    assert all(model["basis"] == "unchanged_parameter_return" for model in graph.callback_models)


def test_discarded_return_does_not_expose_unknown_callback_body(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb\ndef hidden():\n    mystery()", "from lib import hidden\nconsume(hidden)")
    assert not graph.path(["lib.hidden"])
    assert not graph.gaps(["lib.danger"])
    assert graph.callback_models[0]["result_usage"] == "discarded"


@pytest.mark.parametrize("body", [
    "    registry.append(cb)\n    return cb",
    "    cb()\n    return cb",
    "    cb = lambda: None\n    return cb",
    "    if flag:\n        return cb\n    return lambda: None",
])
def test_nonidentity_returns_keep_their_other_effects(tmp_path, body):
    graph = graph_for(tmp_path, "def consume(cb):\n" + body)
    assert "lib.consume" not in graph.parameter_returns
    assert graph.path(["lib.danger"], include_speculative=False) or graph.gaps(["lib.danger"])


@pytest.mark.parametrize("invocation", ["cb = consume(danger)\ncb = None\ncb()",
    "cb = consume(*[danger])\ncb()", "cb = consume(danger, cb=danger)\ncb()"])
def test_return_alias_is_not_invented_after_rebinding_or_invalid_arguments(tmp_path, invocation):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb", invocation)
    assert not graph.path(["lib.danger"], include_speculative=False)
    assert graph.gaps(["lib.danger"])


def test_stored_return_is_not_assumed_discarded(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb", "registry['cb'] = consume(danger)")
    assert not graph.path(["lib.danger"])
    assert "callback_escapes" in graph.gaps(["lib.danger"])


def test_returned_function_does_not_cross_call_sites(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    return cb\ndef safe(): pass\ndef unused():\n    cb = consume(danger)\n    cb()", "from lib import safe\ncb = consume(safe)\ncb()")
    assert graph.path(["lib.safe"], include_speculative=False)
    assert not graph.path(["lib.danger"])



def test_known_safe_argument_scopes_formal_call_away_from_unreachable_supply(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    cb()\ndef unused():\n    consume(danger)\ndef safe(): pass", "from lib import safe\nconsume(safe)")
    assert not graph.path(["lib.danger"])
    assert not graph.gaps(["lib.danger"])
    diagnostic = next(d for d in graph.diagnostics if d["caller"] == "lib.consume")
    assert diagnostic["possible_targets"] == ["lib.safe"]
    assert diagnostic["scope_basis"] == "all_modeled_reachable_callback_bindings"


@pytest.mark.parametrize("invocation", [
    "from lib import safe\nconsume(safe); consume(missing)",
    "from lib import safe\nconsume(missing); consume(safe)",
    "from lib import safe\nconsume(safe)\nconsume(missing)",
    "from lib import safe\nconsume(safe)\nconsume(*unknown)",
    "from lib import safe\nconsume(safe)\nexternal(consume)",
])
def test_unknown_incoming_call_preserves_formal_uncertainty(tmp_path, invocation):
    graph = graph_for(tmp_path, "def consume(cb):\n    cb()\ndef safe(): pass", invocation)
    assert graph.gaps(["lib.danger"])
    diagnostic = next(d for d in graph.diagnostics if d["caller"] == "lib.consume")
    assert "possible_targets" not in diagnostic


def test_bound_callback_with_unknown_body_still_blocks_negative(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    cb()\ndef safe():\n    missing()", "from lib import safe\nconsume(safe)")
    assert graph.gaps(["lib.danger"])


def test_unknown_call_on_same_consumer_line_is_not_scoped_away(tmp_path):
    graph = graph_for(tmp_path, "def consume(cb):\n    cb(); mystery()\ndef safe(): pass", "from lib import safe\nconsume(safe)")
    diagnostic = next(d for d in graph.diagnostics if d["caller"] == "lib.consume")
    assert "possible_targets" not in diagnostic
    assert graph.gaps(["lib.danger"])


def test_first_party_consumer_can_have_unmodeled_external_arguments(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "app.py").write_text("def consume(cb):\n    cb()\ndef safe(): pass\nconsume(safe)\n", encoding="utf-8")
    (lib / "lib.py").write_text("def danger(): pass\n", encoding="utf-8")
    graph = build_python_graph(app, dependency_sources=[lib])
    assert graph.gaps(["lib.danger"])
    diagnostic = next(d for d in graph.diagnostics if d["caller"] == "app.consume")
    assert "possible_targets" not in diagnostic


def test_multiple_parameters_and_same_line_calls_preserve_all_candidates(tmp_path):
    graph = graph_for(tmp_path, "def consume(a, b):\n    a(); b()\ndef safe(): pass", "from lib import safe\nconsume(safe, danger)")
    assert graph.path(["lib.danger"], include_speculative=False)
    diagnostic = next(d for d in graph.diagnostics if d["caller"] == "lib.consume")
    assert diagnostic["possible_targets"] == ["lib.danger", "lib.safe"]
