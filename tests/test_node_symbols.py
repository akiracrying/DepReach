import json
from pathlib import Path

import pytest

pytest.importorskip('tree_sitter')
pytest.importorskip('tree_sitter_javascript')
pytest.importorskip('tree_sitter_typescript')

from scripts.javascript_bindings import JavaScriptBindings
from scripts.javascript_syntax import parse_javascript
from scripts.javascript_values import ModuleValues
from scripts.node_symbols import NodeSymbols
from tests.test_node_resolution import Fixture,write


def analyze(fixture):
    resolver=fixture.resolver()
    modules=[];templates={}
    for instance,root in sorted(resolver.roots.items()):
        template=resolver.templates[root]
        for relative,raw in sorted(template['contents'].items()):
            if not relative.endswith(('.js','.cjs','.mjs','.ts','.tsx','.jsx')): continue
            syntax=parse_javascript(Path(root,relative),raw)
            facts=syntax.facts();bindings=JavaScriptBindings(syntax,facts)
            virtual=instance+'/'+relative if instance else relative
            module_format=resolver._file(virtual)['module_format']
            profile,reason=bindings.module_profile(module_format)
            templates[root,relative]=ModuleValues(syntax,bindings,facts).ir()
            modules.append({'instance':instance,'relative_file':relative,'binding_profile':profile,'binding_profile_reason':reason})
    return NodeSymbols(resolver,modules,templates)


def call(engine,name,file='main.cjs',instance=''):
    key=instance,file
    matches=[c for c in engine.modules[key]['ir']['calls'] if c['target_name']==name]
    assert len(matches)==1,(name,matches)
    return engine.resolve_call(key,matches[0])


def target(record):
    assert record['status']=='modeled_function_target',record
    return record['target']['relative_file'],record['target']['qualified_name']


@pytest.mark.parametrize('exporter,importer,name,expected',[
    ('function run(){};exports.run=run;', "const lib=require('dep');lib.run();",'lib.run','run'),
    ('function run(){};module.exports.run=run;', "const go=require('dep').run;go();",'go','run'),
    ('function run(){};module.exports={run};', "const {run:go}=require('dep');go();",'go','run'),
    ('function run(){};module.exports={run};', "const {run}=require('dep');run();",'run','run'),
    ('module.exports=function run(){};', "const go=require('dep');go();",'go','run'),
    ('function run(){};module.exports=run;', "const go=require('dep');go();",'go','run'),
    ('module.exports={run:()=>1};', "require('dep').run();",'require','IGNORED'),
])
def test_commonjs_named_default_and_destructured_values(tmp_path,exporter,importer,name,expected):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':exporter})
    write(tmp_path/'main.cjs',importer)
    engine=analyze(f)
    if expected=='IGNORED':
        matches=[engine.resolve_call(('', 'main.cjs'),c) for c in engine.modules['','main.cjs']['ir']['calls']]
        result=next(r for r in matches if r['status']=='modeled_function_target')
        assert result['target']['relative_file']=='index.js'
    else:
        result=call(engine,name)
        assert target(result)==('index.js',expected)
    assert result['entrypoint_reachable'] is None and result['vulnerability_reachable'] is None
    assert result['target_is_runtime_proven'] is False


@pytest.mark.parametrize('source,expected',[
    ("function f(){};f();",'f'),
    ("const f=()=>1;const alias=f;alias();",'f'),
    ("function outer(){function f(){};f();}",'outer.f'),
    ("function f(){};{function f(){};f();}",'f'),
])
def test_local_function_binding_preserves_scope_and_aliases(tmp_path,source,expected):
    f=Fixture(tmp_path);write(tmp_path/'main.cjs',source)
    engine=analyze(f)
    name='alias' if 'alias()' in source else 'f'
    result=call(engine,name)
    assert result['target']['qualified_name']==expected
    if source.count('function f()')==2:
        assert result['target']['start_byte']==source.index('function f()',1)


@pytest.mark.parametrize('source,reason',[
    ("const lib=require('dep');lib.run=()=>1;lib.run();",'object_binding_mutated_or_escaped'),
    ("const lib=require('dep');const alias=lib;alias.run=()=>1;lib.run();",'object_binding_mutated_or_escaped'),
    ("const lib=require('dep');consume(lib);lib.run();",'object_binding_mutated_or_escaped'),
    ("let go=require('dep').run;go=()=>1;go();",'binding_may_be_reassigned'),
    ("go();const go=()=>1;",'binding_initialization_order_not_modeled'),
    ("function f(require){require('dep').run();}",'lexical_require_declaration'),
    ("eval(code);const lib=require('dep');lib.run();",'direct_eval_may_change_bindings'),
])
def test_mutations_shadowing_and_initialization_remain_unresolved(tmp_path,source,reason):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'})
    write(tmp_path/'main.cjs',source)
    engine=analyze(f)
    values=[engine.resolve_call(('', 'main.cjs'),c) for c in engine.modules['','main.cjs']['ir']['calls']]
    assert any(r.get('reason')==reason for r in values),values
    assert not any(r['status']=='modeled_function_target' for r in values)


@pytest.mark.parametrize('exporter',[
    'exports={run:()=>1};',
    'exports.run=()=>1;module.exports={};',
    'module={exports:{}};module.exports.run=()=>1;',
    'function f(module){module.exports.run=()=>1;}',
    'if(flag){exports.run=()=>1;}',
    'function later(){exports.run=()=>1;} exports.run=()=>2;',
    'const alias=exports;alias.run=()=>1;',
    'Object.defineProperty(exports,"run",{get:()=>()=>1});',
    'exports[key]=()=>1;',
])
def test_detached_shadowed_escaped_and_conditional_exports_do_not_borrow_targets(tmp_path,exporter):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':exporter})
    write(tmp_path/'main.cjs',"const {run}=require('dep');run();")
    result=call(analyze(f),'run')
    assert result['status']=='unresolved',result


def test_commonjs_reexport_forwarding_and_nested_object_values(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':"module.exports=require('./inner');",'inner.js':'module.exports={api:{run:()=>1}};'})
    write(tmp_path/'main.cjs',"const {api:{run:go}}=require('dep');go();")
    assert target(call(analyze(f),'go'))==('inner.js','run')


def test_exports_alias_is_detached_when_module_exports_is_replaced(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.old=()=>1;module.exports={run:()=>1};exports.run=()=>2;'})
    write(tmp_path/'main.cjs',"const lib=require('dep');lib.run();")
    result=call(analyze(f),'lib.run')
    assert result['target']['start_byte']==(tmp_path/'node_modules/dep/index.js').read_bytes().index(b'()=>1',30)


def test_cyclic_commonjs_initialization_is_an_explicit_boundary(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':"require('./other');exports.run=()=>1;",'other.js':"const lib=require('./index');lib.run();"})
    result=call(analyze(f),'lib.run','other.js','node_modules/dep')
    assert result['status']=='unresolved' and result['reason']=='cyclic_module_initialization_not_modeled'


@pytest.mark.parametrize('exporter,importer,expected',[
    ('export function run(){}',"import {run as go} from 'dep';go();",'run'),
    ('export const run=()=>1;',"import * as lib from 'dep';lib.run();",'run'),
    ('function run(){};export {run};',"import {run as go} from 'dep';go();",'run'),
    ('export default function run(){}',"import go from 'dep';go();",'run'),
    ('export default ()=>1;',"import go from 'dep';go();",'<default>'),
])
def test_esm_named_namespace_and_default_exports(tmp_path,exporter,importer,expected):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':exporter})
    write(tmp_path/'main.mjs',importer)
    name='lib.run' if '* as lib' in importer else 'go'
    assert target(call(analyze(f),name,'main.mjs'))==('index.js',expected)


def test_esm_reexports_and_namespace_reexports(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':"export {run as go} from './inner.js';export * as api from './inner.js';",'inner.js':'export function run(){}'})
    write(tmp_path/'main.mjs',"import {go,api} from 'dep';go();api.run();")
    engine=analyze(f)
    assert target(call(engine,'go','main.mjs'))==('inner.js','run')
    assert target(call(engine,'api.run','main.mjs'))==('inner.js','run')


def test_esm_star_ambiguity_is_not_resolved_by_first_match(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':"export * from './a.js';export * from './b.js';",'a.js':'export function run(){}','b.js':'export function run(){}'})
    write(tmp_path/'main.mjs',"import {run} from 'dep';run();")
    result=call(analyze(f),'run','main.mjs')
    assert result['status']=='unresolved' and result['reason']=='ambiguous_esm_star_export'


def test_passing_function_does_not_create_a_call_edge(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'})
    write(tmp_path/'main.cjs',"const {run}=require('dep');consume(run);")
    engine=analyze(f)
    values=[engine.resolve_call(('', 'main.cjs'),c) for c in engine.modules['','main.cjs']['ir']['calls']]
    assert not any(r['status']=='modeled_function_target' for r in values)


def test_constructor_and_generator_creation_have_distinct_semantics(tmp_path):
    f=Fixture(tmp_path);write(tmp_path/'main.cjs','function DAO(){};function* gen(){yield 1;}new DAO();gen();')
    engine=analyze(f)
    assert call(engine,'DAO')['invocation_semantics']=='constructor_call'
    assert call(engine,'gen')['invocation_semantics']=='generator_creation'


def test_async_functions_are_not_modeled_as_constructors(tmp_path):
    f=Fixture(tmp_path);write(tmp_path/'main.cjs','async function go(){};new go();')
    result=call(analyze(f),'go')
    assert result['status']=='unresolved' and result['reason']=='constructor_semantics_not_modeled'


@pytest.mark.parametrize('exporter',[
    'exports.run=()=>1;delete exports.run;',
    'exports.run=()=>1;({x:exports.run}=other);',
    'exports.run={go:()=>1};mutate(exports.run);',
])
def test_export_deletion_destructured_assignment_and_escaped_property_are_not_static_targets(tmp_path,exporter):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':exporter})
    write(tmp_path/'main.cjs',"const lib=require('dep');lib.run();")
    assert call(analyze(f),'lib.run')['status']=='unresolved'


def test_dynamic_subscript_is_not_a_literal_property_name(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.key=()=>1;exports.other=()=>2;'})
    write(tmp_path/'main.cjs',"const lib=require('dep');const key='other';lib[key]();")
    engine=analyze(f)
    values=[engine.resolve_call(('', 'main.cjs'),c) for c in engine.modules['','main.cjs']['ir']['calls']]
    assert not any(r['status']=='modeled_function_target' for r in values)
    assert any(r.get('reason')=='computed_property_value_not_modeled' for r in values)


def test_esm_default_object_preserves_shape_taint_from_its_local_binding(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':'const api={run:()=>1};mutate(api);export default api;'})
    write(tmp_path/'main.mjs',"import api from 'dep';api.run();")
    result=call(analyze(f),'api.run','main.mjs')
    assert result['status']=='unresolved' and result['reason']=='object_binding_mutated_or_escaped'


def test_cross_module_export_object_mutations_affect_other_importers(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'})
    write(tmp_path/'main.cjs',"require('dep').run=()=>2;")
    write(tmp_path/'other.cjs',"const lib=require('dep');lib.run();")
    result=call(analyze(f),'lib.run','other.cjs')
    assert result['status']=='unresolved' and result['reason']=='module_export_object_mutated_or_escaped'


def test_reassigned_named_default_esm_function_stays_unresolved(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':'export default function run(){};run=()=>1;'})
    write(tmp_path/'main.mjs',"import go from 'dep';go();")
    result=call(analyze(f),'go','main.mjs')
    assert result['status']=='unresolved' and result['reason']=='binding_may_be_reassigned'


VALUE_ORACLES=[
    ('module',{'index.js':"function run(){};export {run as ''};"},"import {'' as go} from 'dep';"),
    ('module',{'index.js':"export * as 'api' from './inner.js';",'inner.js':'export function run(){}'},"import {api} from 'dep';const go=api.run;"),
    ('commonjs',{'index.js':r'exports.r\u0075n=function r\u0075n(){};'},r"const go=r\u0065quire('dep').run;"),
    ('module',{'index.js':r'export function r\u0075n(){}'},"import {run as go} from 'dep';"),
    ('commonjs',{'index.js':'function run(){};exports.run=run;'},"const go=require('dep').run;"),
    ('commonjs',{'index.js':'module.exports=()=>1;'},"const go=require('dep');"),
    ('commonjs',{'index.js':'exports=module.exports=create;exports.extra=()=>2;function create(){}'},"const go=require('dep');"),
    ('commonjs',{'index.js':'module.exports=function create(){};module.exports.run=()=>1;'},"const go=require('dep').run;"),
    ('commonjs',{'index.js':'exports=module.exports=create;Object.defineProperty(exports,"extra",{value:()=>2});function create(){}'},"const go=require('dep');"),
    ('commonjs',{'index.js':'function run(){};module.exports={run};'},"const {run:go}=require('dep');"),
    ('commonjs',{'index.js':'module.exports={api:{run:()=>1}};'},"const {api:{run:go}}=require('dep');"),
    ('commonjs',{'index.js':"module.exports=require('./inner');",'inner.js':'exports.run=()=>1;'},"const go=require('dep').run;"),
    ('commonjs',{'index.js':'exports.old=()=>1;module.exports={run:()=>2};exports.run=()=>3;'},"const go=require('dep').run;"),
    ('commonjs',{'index.js':'exports.run=()=>1;exports.run=()=>2;'},"const go=require('dep').run;"),
    ('commonjs',{'index.js':'const label="雪";function run(){return "雪";}module.exports={run};'},"const {run:go}=require('dep');"),
    ('commonjs',{'index.js':'module.exports={run(){return 1;}};'},"const go=require('dep').run;"),
    ('module',{'index.js':'export function run(){}'},"import {run as go} from 'dep';"),
    ('module',{'index.js':'export const run=()=>1;'},"import * as lib from 'dep';const go=lib.run;"),
    ('module',{'index.js':'export default function run(){}'},"import go from 'dep';"),
    ('module',{'index.js':'export default ()=>1;'},"import go from 'dep';"),
    ('module',{'index.js':"export {run} from './inner.js';",'inner.js':'export function run(){}'},"import {run as go} from 'dep';"),
    ('module',{'index.js':"export * from './inner.js';",'inner.js':'export function run(){}'},"import {run as go} from 'dep';"),
    ('module',{'index.js':"export * as api from './inner.js';",'inner.js':'export function run(){}'},"import {api} from 'dep';const go=api.run;"),
]


def test_function_value_candidates_match_node_function_source_identity(tmp_path):
    import os,subprocess
    from tests.test_javascript_bindings import node_fixture_runtime,retain_fixture_oracle
    node,version,env=node_fixture_runtime()
    helper=Path(__file__).with_name('node_value_oracle.mjs').resolve()
    comparisons=[]
    for index,(kind,files,importer) in enumerate(VALUE_ORACLES):
        root=tmp_path/str(index);root.mkdir()
        f=Fixture(root);f.package('node_modules/dep',manifest={'type':kind},files=files)
        mode='import' if kind=='module' else 'require'
        suffix='mjs' if mode=='import' else 'cjs'
        export='export {go as selected};' if mode=='import' else 'module.exports.selected=go;'
        file=root/('main.'+suffix)
        # Expose the same local callee without invoking it. Only these authored
        # fixture module initializers run; captured real applications never do.
        write(file,importer+export+'function invoke(){go();}')
        result=call(analyze(f),'go',file.name)
        assert result['status']=='modeled_function_target',result
        observed=json.loads(subprocess.check_output([node,str(helper)],input=json.dumps({'file':str(file),'mode':mode}),cwd=root,env=env,text=True,timeout=15))
        comparisons.append({'fixture':index,'node':version,'expected_sha256':result['target']['source_sha256'],'actual':observed})
        assert observed['status']=='function' and observed['sha256']==result['target']['source_sha256'],comparisons[-1]
    retain_fixture_oracle({'kind':'function_value_targets','node':version,'comparisons':comparisons})


def test_nested_installation_contexts_keep_distinct_function_identities(tmp_path):
    f=Fixture(tmp_path)
    source="const {run}=require('dep');run();"
    f.package('node_modules/a',name='shared',files={'index.js':source})
    f.package('node_modules/b',name='shared',files={'index.js':source})
    f.sources[1]['source']=f.sources[0]['source']
    f.package('node_modules/a/node_modules/dep',version='1.0.0',files={'index.js':'exports.run=()=>1;'})
    f.package('node_modules/b/node_modules/dep',version='2.0.0',files={'index.js':'exports.run=()=>2;'})
    engine=analyze(f)
    first=call(engine,'run','index.js','node_modules/a')
    second=call(engine,'run','index.js','node_modules/b')
    assert first['target']['instance']=='node_modules/a/node_modules/dep'
    assert second['target']['instance']=='node_modules/b/node_modules/dep'
    assert first['target']['source_sha256']!=second['target']['source_sha256']
    assert first['target']['purl']=='pkg:npm/dep@1.0.0' and second['target']['purl']=='pkg:npm/dep@2.0.0'


def test_nested_argument_escape_does_not_preserve_old_function_shape(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'module.exports={api:{run:()=>1}};'})
    write(tmp_path/'main.cjs',"const lib=require('dep');mutate(lib.api);lib.api.run();")
    assert call(analyze(f),'lib.api.run')['status']=='unresolved'


def test_export_function_identity_survives_unmodeled_property_changes(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports=module.exports=create;Object.defineProperty(exports,"run",{value:()=>1});function create(){}'})
    write(tmp_path/'main.cjs',"const factory=require('dep');factory();factory.run();")
    engine=analyze(f)
    assert target(call(engine,'factory'))==('index.js','create')
    assert call(engine,'factory.run')['status']=='unresolved'


@pytest.mark.parametrize('exporter',[
    'module.exports=function create(){};if(flag){module.exports=()=>1;}',
    'module.exports=function create(){};function later(){module.exports=()=>1;}',
    'module.exports=function create(){};delete module.exports;',
    'module.exports=function create(){};({value:module.exports}=other);',
    'module.exports=function create(){};const escaped=module;consume(escaped);',
])
def test_export_identity_changes_are_not_confused_with_property_changes(tmp_path,exporter):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':exporter})
    write(tmp_path/'main.cjs',"const factory=require('dep');factory();")
    assert call(analyze(f),'factory')['status']=='unresolved'


def test_value_limits_and_trace_omissions_are_explicit(tmp_path,monkeypatch):
    import scripts.node_symbols as symbols
    f=Fixture(tmp_path)
    source='function f(){};const a0=f;'+''.join('const a'+str(i)+'=a'+str(i-1)+';' for i in range(1,32))+'a31();'
    write(tmp_path/'main.cjs',source)
    engine=analyze(f);result=call(engine,'a31')
    assert result['status']=='modeled_function_target' and result['omitted_evidence']>0
    assert len(result['evidence'])==symbols.MAX_TRACE
    monkeypatch.setattr(symbols,'MAX_VALUE_STEPS',1)
    assert call(engine,'a31')['reason']=='symbol_resolution_resource_limit'


def test_scc_partition_handles_deep_graphs_without_recursion():
    from scripts.node_symbols import components
    graph={i:{i+1} if i<4999 else {0} for i in range(5000)}
    partition,sizes=components(graph)
    assert len(set(partition.values()))==1 and list(sizes.values())==[5000]


def test_generator_methods_do_not_establish_body_execution(tmp_path):
    f=Fixture(tmp_path);write(tmp_path/'main.cjs','const obj={*gen(){yield 1}};obj.gen();')
    result=call(analyze(f),'obj.gen')
    assert result['status']=='modeled_function_target'
    assert result['invocation_semantics']=='generator_creation'
    assert result['target']['generator'] is True and result['entrypoint_reachable'] is None


@pytest.mark.parametrize('mutation',[
    '({value:lib.run}=other);',
    '[lib.run]=other;',
    'for(lib.run of list){}',
    'for({value:lib.run} of list){}',
    'delete lib.run;',
])
def test_assignment_pattern_and_loop_member_mutations_are_not_reads(tmp_path,mutation):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'})
    write(tmp_path/'main.cjs',"const lib=require('dep');"+mutation+'lib.run();')
    result=call(analyze(f),'lib.run')
    assert result['status']=='unresolved' and result['reason']=='object_binding_mutated_or_escaped'


@pytest.mark.parametrize('mutation',['for(exports.run of list){}','for({value:exports.run} of list){}'])
def test_export_writes_in_loop_headers_are_not_static_exports(tmp_path,mutation):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'+mutation})
    write(tmp_path/'main.cjs',"const lib=require('dep');lib.run();")
    assert call(analyze(f),'lib.run')['status']=='unresolved'


def test_default_cjs_import_is_distinct_from_unmodeled_named_interop(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'function run(){};module.exports=run;'})
    write(tmp_path/'main.mjs',"import go,{run} from 'dep';go();run();")
    engine=analyze(f)
    assert target(call(engine,'go','main.mjs'))==('index.js','run')
    assert call(engine,'run','main.mjs')['reason']=='esm_named_commonjs_interop_not_modeled'


def test_require_esm_namespace_remains_an_explicit_interop_boundary(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':'export function run(){}'})
    write(tmp_path/'main.cjs',"const lib=require('dep');lib.run();")
    result=call(analyze(f),'lib.run')
    assert result['status']=='unresolved' and result['reason']=='require_esm_interop_not_modeled'


@pytest.mark.parametrize('source,reason',[
    ('module.exports=function run(){};eval(code);','direct_eval_may_change_bindings'),
    ('module.exports=function run(){};const args=arguments;args[2].exports=()=>1;','commonjs_wrapper_arguments_exposed'),
])
def test_dynamic_module_effects_also_block_literal_export_values(tmp_path,source,reason):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':source})
    write(tmp_path/'main.cjs',"const go=require('dep');go();")
    result=call(analyze(f),'go')
    assert result['status']=='unresolved' and result['reason']==reason


@pytest.mark.parametrize('filename,reason',[('data.json','target_json_data_not_modeled'),('native.node','target_native_addon_not_modeled')])
def test_non_javascript_targets_keep_their_runtime_boundary(tmp_path,filename,reason):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'main':filename},files={filename:'{}'})
    write(tmp_path/'main.cjs',"const lib=require('dep');lib.run();")
    result=call(analyze(f),'lib.run')
    assert result['status']=='unresolved' and result['reason']==reason


def test_unicode_escaped_require_parameters_do_not_borrow_node_exports(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep',files={'index.js':'exports.run=()=>1;'})
    write(tmp_path/'main.cjs',r"function f(r\u0065quire){const go=require('dep').run;go();}")
    result=call(analyze(f),'go')
    assert result['status']=='unresolved' and result['reason']=='lexical_require_declaration'


@pytest.mark.parametrize('exporter',[
    "function run(){};export {run as ''};",
    r'function run(){};export {run as "\u0067o"};',
])
def test_esm_alias_names_do_not_fall_back_to_the_original_name(tmp_path,exporter):
    f=Fixture(tmp_path);f.package('node_modules/dep',manifest={'type':'module'},files={'index.js':exporter})
    write(tmp_path/'main.mjs',"import {run as go} from 'dep';go();")
    assert call(analyze(f),'go','main.mjs')['status']=='unresolved'
