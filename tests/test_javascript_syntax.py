import hashlib
import json

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from scripts.javascript_syntax import parse_javascript, audit_javascript_sources, javascript_files


def facts(source, suffix="js"):
    return parse_javascript("captured." + suffix, source.encode("utf-8")).facts()


def test_functions_and_calls_have_captured_byte_spans_and_lexical_owners():
    source = "const label = '雪'; function outer(){ function inner(){ danger(); } inner(); } outer();"
    report = facts(source)
    assert report["parse_complete"]
    functions = {f["qualified_name"]: f for f in report["functions"]}
    assert set(functions) == {"outer", "outer.inner"}
    inner = functions["outer.inner"]
    raw = source.encode("utf-8")[inner["start_byte"]:inner["end_byte"]]
    assert raw.decode("utf-8") == "function inner(){ danger(); }"
    assert inner["source_sha256"] == hashlib.sha256(raw).hexdigest()
    calls = {call["target_name"]: call for call in report["calls"]}
    assert calls["danger"]["owner"] == inner["symbol"]
    assert calls["inner"]["owner"] == functions["outer"]["symbol"]
    assert calls["outer"]["owner"] == "<module>"


def test_comments_strings_and_regex_are_not_function_definitions():
    report = facts("// function fake() {}\nconst str = 'function fake() {}'; const re = /function fake/; function real() {}")
    assert [f["qualified_name"] for f in report["functions"]] == ["real"]
    assert not report["calls"]


def test_arrow_class_method_and_exported_function_are_distinct():
    report = facts("export const go = () => danger(); class Client { go(){ danger(); } } export default function run() { go(); }")
    assert report["parse_complete"]
    assert {f["qualified_name"] for f in report["functions"]} == {"go", "Client.go", "run"}
    assert len(report["exports"]) == 2
    assert all(call["resolution"] == "not_resolved" for call in report["calls"])


def test_shadowed_require_and_exports_remain_syntax_candidates():
    report = facts("function f(require, exports) { const lib = require('demo'); exports.run = () => lib.run(); }")
    assert report["imports"][0]["kind"] == "commonjs_candidate"
    assert report["imports"][0]["requires_binding_resolution"]
    assert report["exports"][0]["requires_binding_resolution"]
    assert report["call_resolution"] == "not_performed"


def test_esm_dynamic_imports_and_nonliteral_require_are_separate():
    report = facts("import main, {parse as run} from 'demo'; import('other'); require(variable); export {go} from './file.js';")
    assert [(i["kind"], i["specifier"]) for i in report["imports"]] == [
        ("esm", "demo"), ("dynamic_import", "other"), ("commonjs_candidate", None)]
    assert report["exports"][0]["source"] == "./file.js"


@pytest.mark.parametrize("suffix,source", [
    ("ts", "import type {Options} from 'demo'; export function go(x: Options): void { run(x); }"),
    ("tsx", "export const View = (p: {value:string}) => <div>{format(p.value)}</div>;"),
    ("jsx", "const View = () => <div>{format(value)}</div>;"),
    ("mts", "export const go = <T>(x: T): T => x;"),
    ("cts", "const go = (x: number) => x + 1;"),
])
def test_typed_and_jsx_grammars_are_selected(suffix, source):
    report = facts(source, suffix)
    assert report["parse_complete"] and len(report["functions"]) == 1
    if suffix == "ts":
        assert report["imports"][0]["type_only"] is True


def test_recovered_parse_errors_cannot_be_reported_complete():
    report = facts("function broken( { const = ; }")
    assert not report["parse_complete"]
    assert any(i["reason"] == "syntax_error" for i in report["issues"])


def test_snapshot_input_and_new_read_are_distinguished(tmp_path):
    source = tmp_path / "main.js"
    source.write_bytes(b"function old() {}")
    captured = source.read_bytes()
    source.write_bytes(b"function changed() {}")
    before = parse_javascript(source, captured).facts()
    after = parse_javascript(source).facts()
    assert before["functions"][0]["qualified_name"] == "old"
    assert after["functions"][0]["qualified_name"] == "changed"
    assert before["source_sha256"] != after["source_sha256"]


def test_invalid_encoding_and_type_declarations_are_explicit():
    report = parse_javascript("bad.js", b"const x='\xff';").facts()
    assert not report["parse_complete"] and report["issues"][0]["reason"] == "source_encoding_unsupported"
    declaration = parse_javascript("types.d.ts", b"export declare function run(x: string): void;").facts()
    assert declaration["parse_complete"] and declaration["runtime_source"] is False


def test_same_named_functions_keep_distinct_identifiers_on_one_line():
    report = facts("function a(){ function f(){} } function b(){ function f(){} }")
    assert len({f["symbol"] for f in report["functions"]}) == 4
    assert {f["qualified_name"] for f in report["functions"]} == {"a", "b", "a.f", "b.f"}


def test_audit_reuses_syntax_but_retains_dependency_instances(tmp_path):
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "main.js").write_text("require('demo').go();", encoding="utf-8")
    (lib / "index.js").write_text("exports.go = function go(){}", encoding="utf-8")
    context = {"complete": True, "sources": [{"source": str(lib), "location": loc} for loc in ("node_modules/demo", "node_modules/other/node_modules/demo")]}
    summary = audit_javascript_sources(app, context, tmp_path / "audit")
    assert summary["counts"]["modules"] == 2
    assert summary["syntax_complete"] and summary["call_graph_implemented"] is False
    module = next(m for m in summary["modules"] if m["root"] == str(lib))
    assert len(module["instances"]) == 2
    assert json.loads((tmp_path / "audit/summary.json").read_text(encoding="utf-8"))["counts"] == summary["counts"]


def test_dependency_distribution_sources_are_included_but_nested_instances_are_separate(tmp_path):
    for name in ("dist", "node_modules", "tests"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "index.js").write_text("run();", encoding="utf-8")
    assert [p.relative_to(tmp_path).as_posix() for p in javascript_files(tmp_path)] == ["dist/index.js"]



def test_unsupported_native_parser_version_fails_before_parsing(monkeypatch):
    from scripts import javascript_syntax
    javascript_syntax._language.cache_clear()
    monkeypatch.setattr(javascript_syntax.importlib.metadata, "version", lambda _: "0.26.0")
    with pytest.raises(RuntimeError, match="0.26.0"):
        parse_javascript("main.js", b"run();")



def test_long_expression_text_is_bounded_without_losing_source_ranges():
    source = "send('" + "x" * 5000 + "');"
    report = facts(source)
    argument = report["calls"][0]["arguments"][0]
    assert len(argument["text"]) == report["text_excerpt_limit"] == 512
    assert argument["text_truncated"]
    assert argument["end_byte"] - argument["start_byte"] == 5002
    assert report["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
