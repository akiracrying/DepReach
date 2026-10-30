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


def test_audit_preserves_unverified_commonjs_and_nonliteral_boundaries(tmp_path):
    app,inventory,sources=fixture(tmp_path,"require('dep'); function f(require){ require('dep'); } require(variable); import('dep');")
    summary=audit.audit_node_imports(inventory,sources,tmp_path/'out')
    values=records(summary)
    assert len(values)==4
    assert sum(v['module_lookup']['status']=='resolved' for v in values)==3
    assert values[2]['module_lookup']['reason']=='nonliteral_module_specifier'
    assert all(v['binding_resolution']=='unverified_commonjs_candidate' for v in values[:3])
    assert not summary['call_graph_implemented'] and not summary['binding_resolution_implemented']
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
    assert 'JS/TS module lookup' in html and 'CommonJS bindings are unverified' in html
