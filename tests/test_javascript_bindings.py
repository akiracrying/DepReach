import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from scripts.javascript_bindings import JavaScriptBindings
from scripts.javascript_syntax import parse_javascript

V = "verified_commonjs_wrapper"
S = "shadowed_commonjs_identifier"
U = "unresolved_commonjs_binding"


def analyze(code, module_format="commonjs", suffix="cjs"):
    syntax = parse_javascript("captured." + suffix, code.encode())
    facts = syntax.facts()
    engine = JavaScriptBindings(syntax, facts)
    refs = [ref for ref in facts["imports"] if ref["kind"] == "commonjs_candidate"]
    return engine, [engine.commonjs_reference(ref, module_format) for ref in refs]


@pytest.mark.parametrize("code,expected", [
    ("require('0');", [V]),
    (r"function f(r\u0065quire){require('0');}require('1');", [S,V]),
    (r"function f(\u{72}equire){require('0');}", [S]),
    (r"r\u0065quire('0');", [V]),
    (r"r\u0065quire=other;require('0');", [U]),
    ("function f(require){require('0');} require('1');", [S,V]),
    ("function f(){require('0');var require;} require('1');", [S,V]),
    ("{ require('0'); let require; } require('1');", [S,V]),
    ("{ let other; require('0'); } require('1');", [V,V]),
    ("for(let require of list){require('0');} require('1');", [S,V]),
    ("for(var require of list){require('0');} require('1');", [S,S]),
    ("for(let require=other; false;){require('0');} require('1');", [S,V]),
    ("try{}catch(require){require('0');} require('1');", [S,V]),
    ("try{}catch({message:require}){require('0');} require('1');", [S,V]),
    ("const f=function require(){require('0');}; require('1');", [S,V]),
    ("const C=class require{m(){require('0');}}; require('1');", [S,V]),
    ("class C { static {var require;require('0');}} require('1');", [S,V]),
    ("function f(a=require('0')){var require;require('1');}", [V,S]),
    ("function f(a=()=>require('0')){let require;}", [V]),
    ("function f(a=require('0')){function require(){}}", [V]),
    ("function f(require=require('0')){require('1');}", [S,S]),
    ("function f({require: alias}){require('0');}", [V]),
    ("function f({name: require = other}){require('0');}", [S]),
    ("function f({require}){require('0');}", [S]),
    ("function f([require,...rest]){require('0');}", [S]),
    ("function f(...require){require('0');}", [S]),
    ("(require=>require('0'))(other);require('1');", [S,V]),
    ("var require; require('0');", [V]),
    ("var require=other;require('0');", [S]),
    ("function require(){} require('0');", [S]),
    ("require=other; require('0');", [U]),
    ("require('0');function change(){require=other;}", [U]),
    ("function change(require){require=other;} require('0');", [V]),
    ("({require}=other); require('0');", [U]),
    ("[require]=other; require('0');", [U]),
    ("for(require of list){} require('0');", [U]),
    ("require++;require('0');", [U]),
    ("with(other){require('0');} require('1');", [U,V]),
    ("with(other){function f(){require('0');}}", [U]),
    ("eval(code);require('0');", [U]),
    ("(eval)(code);require('0');", [U]),
    ("(0,eval)(code);require('0');", [V]),
    ("const args=arguments;require('0');", [U]),
    ("var arguments;const args=arguments;require('0');", [U]),
    ("const args=arguments;var arguments={};args[1]=()=>{};require('0');", [U]),
    ("let arguments={};require('0');", [V]),
    ("let require; with(other){require('0');}", [U]),
    ("function f(){const args=arguments;} require('0');", [V]),
    ("const f=()=>arguments;require('0');", [U]),
    ("if(false){function require(){}}require('0');", [U]),
])
def test_lexical_binding_and_mutation_boundaries(code, expected):
    _, records = analyze(code)
    assert [r["status"] for r in records] == expected
    assert all(r["resolution_is_invocation"] is False for r in records)


@pytest.mark.parametrize("code,profile,expected", [
    ("require('0');", "commonjs", V),
    ("import('x');require('0');", "commonjs", V),
    ("export const x=1;require('0');", "esm", U),
    ("import './x.js';require('0');", "esm", U),
    ("const meta=import.meta;require('0');", "esm", U),
    ("await other;require('0');", "esm", U),
    ("for await(const x of list){}require('0');", "unsupported", U),
    ("async function f(){await other;}require('0');", "commonjs", V),
    ("const require=other;require('0');", "esm", S),
    (r"const r\u0065quire=other;require('0');", "esm", S),
    ("class module{}require('0');", "esm", U),
    ("let __filename;require('0');", "esm", U),
    ("{let require; } require('0');", "commonjs", V),
])
def test_ambiguous_javascript_profile_uses_syntax_not_import_candidates(code, profile, expected):
    engine, records = analyze(code, "javascript_auto", "js")
    assert engine.module_profile("javascript_auto")[0] == profile
    assert records[-1]["status"] == expected


@pytest.mark.parametrize("code", ["import './x.js';require('0');", "let module;require('0');"])
def test_explicit_commonjs_syntax_conflicts_are_not_verified(code):
    engine, records = analyze(code)
    assert engine.module_profile("commonjs")[0] == "unsupported"
    assert records[-1]["status"] == U


@pytest.mark.parametrize("code", ["import require from 'other';require('0');",
    "import {loader as require} from 'other';require('0');", "import * as require from 'other';require('0');"])
def test_esm_imports_are_lexical_bindings_not_commonjs_globals(code):
    _, records = analyze(code,"esm","mjs")
    assert records[-1]["status"] == S
    assert records[-1]["declarations"][0]["kind"] == "import"


@pytest.mark.parametrize("suffix", ["ts","mts","cts","tsx","jsx"])
def test_compiler_boundaries_are_not_treated_as_runtime_loader_proofs(suffix):
    _, records = analyze("require('0');", "commonjs", suffix)
    assert records[0]["status"] == U
    assert records[0]["module_profile"] == "unsupported"


def test_recovered_syntax_cannot_supply_binding_proof():
    _, records = analyze("require('0'); function broken( {")
    assert records[0]["status"] == U


def test_declaration_evidence_preserves_unicode_byte_offsets():
    code = "const label='雪'; function f(require){require('0');}"
    _, records = analyze(code)
    declaration=records[0]["declarations"][0]
    assert code.encode()[declaration["start_byte"]:declaration["end_byte"]] == b"require"


ORACLE_CASES = [
    r"function f(\u{00000000000072}equire){require('0');}f(()=>{});require('1');",
    r"function f(r\u0065quire){require('0');}f(()=>{});require('1');",
    r"function f(\u{72}equire){require('0');}f(()=>{});require('1');",
    "require('0');",
    "function f(require){require('0');} f(()=>{});require('1');",
    "for(let require of [()=>{}]){require('0');} require('1');",
    "for(var require of [()=>{}]){require('0');} require('1');",
    "try{throw ()=>{}}catch(require){require('0');}require('1');",
    "try{throw {message:()=>{}}}catch({message:require}){require('0');}require('1');",
    "function f(a=require('0')){var require;}f();require('1');",
    "function f({require:alias}){require('0');}f({require:()=>{}});require('1');",
    "function f({name:require=()=>{}}){require('0');}f({});require('1');",
    "function f({require}){require('0');}f({require:()=>{}});require('1');",
    "function f([require]){require('0');}f([()=>{}]);require('1');",
    "(require=>require('0'))(()=>{});require('1');",
    "var require;require('0');",
    "function f(a=()=>require('0')){let require;a();}f();",
    "class C {static {var require=()=>{};require('0');}}require('1');",
]


def node_fixture_runtime():
    node=os.environ.get("DEPREACH_NODE_BINARY") or shutil.which("node")
    if node:
        version=subprocess.check_output([node,"--version"],text=True).strip()
        major,minor=map(int,version.lstrip("v").split(".")[:2])
        if major in {22,24} and (major!=22 or minor>=12):
            env={k:v for k,v in os.environ.items() if k not in {"NODE_OPTIONS","NODE_PATH","NODE_V8_COVERAGE","NODE_REDIRECT_WARNINGS","NODE_COMPILE_CACHE"}}
            env["NODE_DISABLE_COMPILE_CACHE"]="1"
            return node,version,env
    if os.environ.get("DEPREACH_REQUIRE_NODE_ORACLE"): pytest.fail("Required Node 22>=12/24 fixture oracle unavailable")
    pytest.skip("Node 22>=12/24 unavailable; explicit CI jobs exercise these fixture oracles")


def retain_fixture_oracle(value):
    if os.environ.get("DEPREACH_NODE_BINDING_ORACLE_REPORT"):
        file=Path(os.environ["DEPREACH_NODE_BINDING_ORACLE_REPORT"])
        file.parent.mkdir(parents=True,exist_ok=True)
        with file.open('a',encoding='utf-8') as stream: stream.write(json.dumps(value)+'\n')


def test_verified_bindings_agree_with_node_on_executed_synthetic_scope_cases(tmp_path):
    node,version,env=node_fixture_runtime()
    # Only these authored synthetic fixtures run, in vm.compileFunction with an
    # injected sentinel require. No application/dependency file is loaded.
    helper=Path(__file__).with_name("node_binding_oracle.mjs").resolve()
    result=json.loads(subprocess.check_output([node,str(helper)],input=json.dumps(ORACLE_CASES),cwd=tmp_path,env=env,text=True,timeout=20))
    retain_fixture_oracle({"kind":"lexical_scope","node":version,"cases":ORACLE_CASES,"hits":result["hits"]})
    assert len(result["hits"]) == len(ORACLE_CASES)
    if os.environ.get("DEPREACH_REQUIRE_NODE_ORACLE"):
        assert int(result["node"].lstrip("v").split(".")[0]) in {22,24}
    for code,hits in zip(ORACLE_CASES,result["hits"]):
        syntax=parse_javascript("fixture.cjs",code.encode())
        facts=syntax.facts()
        engine=JavaScriptBindings(syntax,facts)
        verified={r["specifier"] for r in facts["imports"] if engine.commonjs_reference(r,"commonjs")["status"]==V}
        assert set(hits)==verified, (code,hits,verified)


def test_declaration_output_is_bounded_and_omission_explicit():
    code="function f(){"+"var require=other;"*100+"require('0');}"
    _,records=analyze(code)
    record=records[0]
    assert record['status']==S and len(record['declarations'])==8
    assert record['omitted_declarations']==92


def test_binding_node_limit_is_not_reported_as_verified(monkeypatch):
    import scripts.javascript_bindings as binding_module
    monkeypatch.setattr(binding_module,'MAX_NODES',2)
    engine,records=analyze("require('0');")
    assert not engine.complete and records[0]['status']==U


def test_default_javascript_profile_matches_node_for_authored_syntax_fixtures(tmp_path):
    node,version,env=node_fixture_runtime()
    comparisons=[]
    sources=[
        "require('node:fs');", "import('node:fs');", "export const x=1;", "import 'node:fs';",
        "const meta=import.meta;", "await Promise.resolve();",
        "async function f(){await 1;}", "const require=()=>{};", "class module{}",
        "let __filename;", "{let require;}", r"const r\u0065quire=()=>{};"
    ]
    probe=";console.log(JSON.stringify({commonjs:typeof module==='object' && module!==null && typeof module.id==='string'}));"
    (tmp_path/'package.json').write_text('{}',encoding='utf-8')
    # Both application and dependency package scopes; these are authored test
    # programs using built-ins only, never captured real application sources.
    for parent in (tmp_path,tmp_path/'node_modules/fixture'):
        parent.mkdir(parents=True,exist_ok=True)
        (parent/'package.json').write_text('{"name":"fixture","version":"1.0.0"}',encoding='utf-8')
        for index,source in enumerate(sources):
            file=parent/('case'+str(index)+'.js')
            file.write_text(source+probe,encoding='utf-8')
            observed=json.loads(subprocess.check_output([node,str(file)],cwd=tmp_path,env=env,text=True,stderr=subprocess.PIPE,timeout=10))
            engine,_=analyze(source,'javascript_auto','js')
            expected=engine.module_profile('javascript_auto')[0]
            comparisons.append({'code':source,'in_node_modules':parent!=tmp_path,'actual_commonjs':observed['commonjs'],'expected_profile':expected})
            assert (expected=='commonjs')==observed['commonjs'], (source,str(parent),observed)
    retain_fixture_oracle({'kind':'syntax_profile','node':version,'comparisons':comparisons})


def test_explicit_esm_for_await_is_separate_from_ambiguous_node_detection():
    engine,_=analyze("for await(const x of []){}require('0');",'esm','mjs')
    assert engine.module_profile('esm')[0]=='esm'
    assert engine.module_profile('javascript_auto')==('unsupported','ambiguous_for_await_requires_runtime_check')
