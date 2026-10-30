import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip('tree_sitter')
pytest.importorskip('tree_sitter_javascript')
pytest.importorskip('tree_sitter_typescript')

from scripts import node_imports as audit
from scripts import npm_inventory


def fixture(tmp_path, code):
    app=tmp_path/'app'; app.mkdir()
    (app/'package.json').write_text('{"name":"app","version":"1.0.0"}',encoding='utf-8')
    (app/'main.js').write_bytes(code.encode())
    dep=app/'node_modules/dep';dep.mkdir(parents=True)
    (dep/'package.json').write_text('{"name":"dep","version":"1.0.0"}',encoding='utf-8')
    (dep/'index.js').write_text('exports.run = () => 1;',encoding='utf-8')
    inventory={'root':str(app),'project_name':'app','input_sha256':'fixture', 'selection':{'target_os':'linux'},
        'instances':[{'location':'node_modules/dep','source_location':'node_modules/dep','name':'dep','version':'1.0.0','purl':'pkg:npm/dep@1.0.0'}]}
    sources={'inventory_sha256':'fixture','complete':True,'issues':[],'sources':[{'location':'node_modules/dep',
        'source':str(dep),'purl':'pkg:npm/dep@1.0.0','package_json_sha256':hashlib.sha256((dep/'package.json').read_bytes()).hexdigest()}]}
    return app, inventory, sources


def records(summary):
    return [json.loads(line) for line in Path(summary['records']).read_text(encoding='utf-8').splitlines()]


def test_audit_distinguishes_wrapper_binding_from_shadowed_and_nonliteral_lookup(tmp_path):
    app,inventory,sources=fixture(tmp_path,"require('dep'); function f(require){ require('dep'); } require(variable); import('dep');")
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    values=records(summary)
    assert len(values)==4
    assert sum(v['module_lookup']['status']=='resolved' for v in values)==3
    assert values[2]['module_lookup']['reason']=='nonliteral_module_specifier'
    assert [v['binding_resolution'] for v in values[:3]] == ['verified_commonjs_wrapper', 'shadowed_commonjs_identifier', 'verified_commonjs_wrapper']
    assert values[1]['binding_evidence']['declarations'][0]['kind']=='parameter'
    assert summary['counts']['verified_commonjs_candidates']==2
    assert summary['counts']['shadowed_commonjs_candidates']==1
    assert not summary['call_graph_implemented'] and summary['binding_resolution_implemented']
    assert summary['binding_resolution_scope']=='direct_commonjs_require_identity_only'
    assert not summary['exported_value_resolution_implemented']
    assert not summary['candidate_lookup_complete']
    assert all(v['resolution_is_invocation'] is False for v in values)
    assert all(v['importer_source_sha256']==hashlib.sha256((app/'main.js').read_bytes()).hexdigest() for v in values)


def test_reexports_type_only_and_declaration_files_are_distinguished(tmp_path):
    app,inventory,sources=fixture(tmp_path,"export {run} from 'dep';")
    (app/'types.ts').write_text("import type {Foo} from 'missing'; export type {Bar} from 'missing';",encoding='utf-8')
    (app/'types.d.ts').write_text("import {Foo} from 'missing';",encoding='utf-8')
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    values=records(summary)
    assert len(values)==4
    assert sum(v['module_lookup']['status']=='type_only' for v in values)==3
    assert values[0]['kind']=='esm_reexport' and values[0]['module_lookup']['status']=='resolved'
    assert summary['candidate_lookup_complete']
    assert summary['counts']['by_status']['type_only']==3


def test_source_capture_and_syntax_use_same_bytes(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    original=(app/'main.js').read_bytes()
    parse=audit.parse_javascript
    def mutate(path,raw):
        if Path(path)==app/'main.js': (app/'main.js').write_text("require('changed');",encoding='utf-8')
        return parse(path,raw)
    monkeypatch.setattr(audit,'parse_javascript',mutate)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    value=records(summary)[0]
    assert value['specifier']=='dep' and value['module_lookup']['status']=='resolved'
    assert value['importer_source_sha256']==hashlib.sha256(original).hexdigest()


def test_same_source_artifact_is_parsed_once_but_resolved_per_instance(tmp_path):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    inventory['instances'].append({**inventory['instances'][0],'location':'node_modules/alias','source_location':'node_modules/alias'})
    sources['sources'].append({**sources['sources'][0],'location':'node_modules/alias'})
    (app/'node_modules/dep/index.js').write_text("require('fs');",encoding='utf-8')
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    assert summary['counts']['module_instances']==3
    assert summary['counts']['physical_modules_parsed']==2
    values=records(summary)
    assert {v['importer_instance'] for v in values if v['specifier']=='fs'}=={'node_modules/dep','node_modules/alias'}


def test_record_and_module_caps_keep_explicit_incompleteness(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"require('dep');require('fs');")
    monkeypatch.setattr(audit,'MAX_IMPORT_RECORDS',1)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    assert len(records(summary))==1 and summary['counts']['omitted_records']==1
    assert not summary['candidate_lookup_complete']
    monkeypatch.setattr(audit,'MAX_IMPORT_RECORDS',100)
    monkeypatch.setattr(audit,'MAX_MODULES',1)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out2')
    assert summary['counts']['omitted_modules']==1 and not summary['candidate_lookup_complete']


def test_generated_report_inside_app_is_not_reclassified_as_application_code(tmp_path):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    output=app/'reports/current'
    output.mkdir(parents=True)
    (output/'accidental.js').write_text("require('must-not-be-scanned');",encoding='utf-8')
    inventory['scan_output_root']=str(output)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    assert summary['counts']['module_instances']==2
    assert not any(v['specifier']=='must-not-be-scanned' for v in records(summary))
    assert str(output) in summary['scope']['excluded_application_roots']


def test_cli_resolve_imports_includes_sources_syntax_and_preserves_unsupported_sca(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    package={'name':'app','version':'1.0.0','dependencies':{'dep':'1.0.0'}}
    (app/'package.json').write_text(json.dumps(package),encoding='utf-8')
    lock={'lockfileVersion':3,'packages':{'':package,'node_modules/dep':{'version':'1.0.0'}}}
    (app/'package-lock.json').write_text(json.dumps(lock),encoding='utf-8')
    import scripts.npm_sources as source_module
    def prepare(i,*a,**k): return {**sources,'inventory_sha256':i['input_sha256'],'metrics':{'instances':1}}
    monkeypatch.setattr(source_module,'prepare_npm_sources',prepare)
    output=app/'reports/scan'
    assert npm_inventory.main(['--input',str(app),'--output',str(output),'--resolve-imports','--target-os','linux'])==0
    saved=json.loads((output/'inventory.json').read_text(encoding='utf-8'))
    assert Path(saved['module_resolution_manifest']).is_file()
    assert Path(saved['syntax_manifest']).is_file()
    import scripts.composition_analysis as composition
    monkeypatch.setattr(composition,'check_vulnerabilities_from_sbom',lambda *a:[{'cve':'CVE-TEST','package':'dep','purl':'pkg:npm/dep@1.0.0'}])
    resolution=json.loads(Path(saved['module_resolution_manifest']).read_text(encoding='utf-8'))
    findings=npm_inventory.scan_npm_inventory(saved,output,sources,module_resolution=resolution)
    assert findings[0]['reachability']['status']=='unsupported'
    assert findings[0]['reachability']['is_reachable'] is None
    assert findings[0]['reachability']['module_resolution_manifest']==saved['module_resolution_manifest']
    assert findings[0]['reachability']['module_lookup_summary']['scope']=='scan_wide_candidates'
    html=(output/'report.html').read_text(encoding='utf-8')
    assert 'JS/TS module lookup' in html and 'Node require binding verified: 1' in html
    assert 'Exported values, call paths and vulnerability reachability are pending' in html


def test_same_source_has_distinct_bindings_for_explicit_package_profiles(tmp_path):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    (app/'node_modules/dep/index.js').write_text("require('fs');",encoding='utf-8')
    nested=app/'esm';nested.mkdir()
    (nested/'package.json').write_text('{"type":"module"}',encoding='utf-8')
    (nested/'entry.js').write_text("require('fs');",encoding='utf-8')
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    values=records(summary)
    esm=next(v for v in values if v['importer_file']=='esm/entry.js')
    cjs=next(v for v in values if v['importer_instance']=='node_modules/dep')
    assert esm['binding_resolution']=='unresolved_commonjs_binding'
    assert esm['binding_evidence']['reason']=='require_not_a_node_esm_binding'
    assert cjs['binding_resolution']=='verified_commonjs_wrapper'
    assert not summary['commonjs_binding_complete']


def test_mutating_the_disk_does_not_change_binding_evidence_from_capture(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"require('dep');")
    parse=audit.parse_javascript
    def mutate(path,raw):
        (app/'main.js').write_text("function f(require){require('dep');}",encoding='utf-8')
        return parse(path,raw)
    monkeypatch.setattr(audit,'parse_javascript',mutate)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    assert records(summary)[0]['binding_resolution']=='verified_commonjs_wrapper'


def test_cli_binding_gap_does_not_return_a_complete_audit_code(tmp_path):
    app,inventory,sources=fixture(tmp_path,"eval(code);require('dep');")
    input_file=tmp_path/'inventory.json';sources_file=tmp_path/'sources.json'
    input_file.write_text(json.dumps(inventory),encoding='utf-8')
    sources_file.write_text(json.dumps(sources),encoding='utf-8')
    out=tmp_path/'out'
    assert audit.main(['--inventory',str(input_file),'--sources',str(sources_file),'--output',str(out)])==3
    summary=json.loads((out/'summary.json').read_text(encoding='utf-8'))
    assert summary['candidate_lookup_complete'] and not summary['commonjs_binding_complete']
    assert records(summary)[0]['binding_evidence']['reason']=='direct_eval_may_change_bindings'


def test_symbol_pipeline_adds_candidates_but_preserves_unsupported_sca(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();")
    output=tmp_path/'out';output.mkdir()
    summary=audit.audit_node_imports(inventory,sources,output/'modules',resolve_symbols=True)
    assert summary['call_target_resolution_implemented'] and not summary['call_graph_implemented']
    assert summary['symbol_summary']['counts']['by_status']['modeled_function_target']==1
    values=[json.loads(line) for line in Path(summary['symbol_summary']['calls']).read_text(encoding='utf-8').splitlines()]
    target=next(v for v in values if v['status']=='modeled_function_target')
    assert target['target']['relative_file']=='index.js' and target['entrypoint_reachable'] is None
    (output/'sbom.json').write_text(json.dumps(npm_inventory.npm_sbom({**inventory,'edges':[],'selection':{}})),encoding='utf-8')
    import scripts.composition_analysis as composition
    monkeypatch.setattr(composition,'check_vulnerabilities_from_sbom',lambda *a:[{'cve':'CVE-TEST','package':'dep','purl':'pkg:npm/dep@1.0.0'}])
    findings=npm_inventory.scan_npm_inventory({**inventory,'selection':{}},output,sources,module_resolution=summary)
    assert findings[0]['reachability']['status']=='unsupported'
    assert findings[0]['reachability']['is_reachable'] is None
    assert 'JS function target candidates' in (output/'report.html').read_text(encoding='utf-8')


def test_symbol_output_cap_preserves_explicit_omissions(tmp_path,monkeypatch):
    import scripts.node_symbols as symbols
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();lib.run();")
    monkeypatch.setattr(symbols,'MAX_CALL_RECORDS',1)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out',resolve_symbols=True)
    s=summary['symbol_summary']
    assert s['counts']['calls']==3 and s['counts']['omitted_records']==2
    assert len(Path(s['calls']).read_text(encoding='utf-8').splitlines())==1
    assert not summary['symbol_audit_complete']


def test_symbol_analysis_uses_captured_dependency_bytes_after_disk_change(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();")
    original=(app/'node_modules/dep/index.js').read_bytes()
    parse=audit.parse_javascript
    def mutate(path,raw):
        (app/'node_modules/dep/index.js').write_text('exports.run=()=>2;',encoding='utf-8')
        return parse(path,raw)
    monkeypatch.setattr(audit,'parse_javascript',mutate)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out',resolve_symbols=True)
    values=[json.loads(line) for line in Path(summary['symbol_summary']['calls']).read_text(encoding='utf-8').splitlines()]
    target=next(r['target'] for r in values if r['status']=='modeled_function_target')
    assert target['module_source_sha256']==hashlib.sha256(original).hexdigest()
    assert original[target['start_byte']:target['end_byte']].startswith(b'() =>')
    assert target['source_sha256']==hashlib.sha256(original[target['start_byte']:target['end_byte']]).hexdigest()


def test_npm_symbol_flag_implies_all_previous_source_stages(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();")
    package={'name':'app','version':'1.0.0','dependencies':{'dep':'1.0.0'}}
    (app/'package.json').write_text(json.dumps(package),encoding='utf-8')
    (app/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':package,'node_modules/dep':{'version':'1.0.0'}}}),encoding='utf-8')
    import scripts.npm_sources as source_module
    def prepare(i,*a,**k): return {**sources,'inventory_sha256':i['input_sha256'],'metrics':{'instances':1}}
    monkeypatch.setattr(source_module,'prepare_npm_sources',prepare)
    out=app/'reports/symbol-run'
    assert npm_inventory.main(['--input',str(app),'--output',str(out),'--resolve-symbols','--condition','development','--target-os','linux'])==0
    saved=json.loads((out/'inventory.json').read_text(encoding='utf-8'))
    summary=json.loads(Path(saved['module_resolution_manifest']).read_text(encoding='utf-8'))
    assert summary['symbol_audit_complete'] and summary['symbol_summary']['counts']['by_status']['modeled_function_target']==1
    assert 'development' in summary['conditions']
    assert Path(saved['source_manifest']).is_file() and Path(saved['syntax_manifest']).is_file()


def test_function_example_labels_are_escaped_in_html(tmp_path,monkeypatch):
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();")
    out=tmp_path/'out';out.mkdir()
    summary=audit.audit_node_imports(inventory,sources,out/'modules',resolve_symbols=True)
    summary['symbol_summary']['application_examples'][0]['target_name']='<img src=x onerror=bad()>'
    (out/'sbom.json').write_text(json.dumps(npm_inventory.npm_sbom({**inventory,'edges':[],'selection':{}})),encoding='utf-8')
    import scripts.composition_analysis as composition
    monkeypatch.setattr(composition,'check_vulnerabilities_from_sbom',lambda *a:[{'cve':'CVE-TEST','package':'dep','purl':'pkg:npm/dep@1.0.0'}])
    npm_inventory.scan_npm_inventory({**inventory,'selection':{}},out,sources,module_resolution=summary)
    html=(out/'report.html').read_text(encoding='utf-8')
    assert '&lt;img src=x onerror=bad()&gt;' in html
    assert '<code><img src=x onerror=bad()>' not in html


def test_symbol_large_name_metadata_does_not_expand_unbounded_records(tmp_path):
    app,inventory,sources=fixture(tmp_path,"const go=require('dep');go();")
    (app/'node_modules/dep/index.js').write_text('module.exports=function '+('f'*10000)+'(){};',encoding='utf-8')
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out',resolve_symbols=True)
    counts=summary['symbol_summary']['counts']
    assert counts['by_status']['modeled_function_target']==1
    assert counts['omitted_records']==1 and counts['omission_reasons']=={'call_record_text_limit':1}
    assert Path(summary['symbol_summary']['calls']).stat().st_size<10000
    assert not summary['symbol_audit_complete'] and not summary['symbol_summary']['application_examples']


@pytest.mark.parametrize('setting,reason',[('MAX_CALL_RECORD_BYTES','call_record_byte_limit'),('MAX_CALL_OUTPUT_BYTES','call_output_byte_limit')])
def test_symbol_output_byte_limits_are_explicit(tmp_path,monkeypatch,setting,reason):
    import scripts.node_symbols as symbols
    app,inventory,sources=fixture(tmp_path,"const lib=require('dep');lib.run();")
    monkeypatch.setattr(symbols,setting,1)
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out',resolve_symbols=True)
    counts=summary['symbol_summary']['counts']
    assert counts['omitted_records']==counts['calls']==2
    assert counts['omission_reasons']=={reason:2}
    assert counts['output_bytes']==Path(summary['symbol_summary']['calls']).stat().st_size==0
    assert not summary['symbol_audit_complete']
