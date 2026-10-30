import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.node_resolution import NodeResolver


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value) if isinstance(value, dict) else value).encode())


class Fixture:
    def __init__(self, root, package=None):
        self.root = root
        self.instances = []
        self.sources = []
        write(root / 'package.json', {'name':'fixture-app', 'version':'1.0.0', **(package or {})})
        write(root / 'app.cjs', 'throw Error("Target must never execute");')
        write(root / 'app.mjs', 'throw Error("Target must never execute");')
    def package(self, location, *, name='dep', version='1.0.0', manifest=None, files=None):
        source = self.root / location
        record = {'location':location, 'source_location':location, 'name':name, 'version':version, 'purl':f'pkg:npm/{name}@{version}'}
        self.instances.append(record)
        write(source / 'package.json', {'name':name, 'version':version, **(manifest or {})})
        for file, code in (files or {'index.js':'throw Error("Target must never execute");'}).items():
            write(source / file, code)
        self.sources.append({'location':location, 'purl':record['purl'], 'source':str(source)})
        return record
    def resolver(self, **kwargs):
        return NodeResolver({'root':str(self.root), 'project_name':'fixture-app', 'instances':self.instances},
                            {'sources':self.sources, 'complete':True}, **kwargs)


def oracle(root, requests, conditions=()):
    node = os.environ.get('DEPREACH_NODE_BINARY') or shutil.which('node')
    if not node:
        if os.environ.get('DEPREACH_REQUIRE_NODE_ORACLE'): pytest.fail('Required Node oracle missing')
        pytest.skip('Node runtime unavailable; explicit Node 22/24 CI jobs cover oracle checks')
    version = subprocess.check_output([node, '--version'], text=True).strip()
    major, minor = map(int, version.lstrip('v').split('.')[:2])
    if major not in {22,24} or (major == 22 and minor < 12):
        if os.environ.get('DEPREACH_REQUIRE_NODE_ORACLE'): pytest.fail('Unsupported required oracle version: '+version)
        pytest.skip('Oracle profile requires Node >=22.12 or Node 24')
    env = {k:v for k,v in os.environ.items() if k not in {'NODE_OPTIONS','NODE_PATH','NODE_PRESERVE_SYMLINKS','NODE_V8_COVERAGE','NODE_REDIRECT_WARNINGS','NODE_COMPILE_CACHE'}}
    env['NODE_DISABLE_COMPILE_CACHE']='1'
    helper = Path(__file__).with_name('node_resolve_oracle.mjs').resolve()
    command = [node, '--experimental-import-meta-resolve', *['--conditions='+c for c in conditions], str(helper), json.dumps(requests)]
    return json.loads(subprocess.check_output(command,cwd=root,env=env,text=True,timeout=20))


def compare(fixture, requests, *, conditions=()):
    resolver = fixture.resolver(conditions=conditions)
    checks=[]
    for instance,file,specifier,mode in requests:
        source = fixture.root / instance / file
        checks.append({'file':str(source),'specifier':specifier,'mode':mode})
    oracle_result = oracle(fixture.root, checks, conditions)
    expected = oracle_result['results']
    actual = [resolver.resolve(instance,file,specifier,mode=mode) for instance,file,specifier,mode in requests]
    if os.environ.get('DEPREACH_NODE_ORACLE_REPORT'):
        report=Path(os.environ['DEPREACH_NODE_ORACLE_REPORT'])
        report.parent.mkdir(parents=True,exist_ok=True)
        with report.open('a',encoding='utf-8') as stream:
            stream.write(json.dumps({'node':oracle_result['node'],'conditions':list(conditions),
                'requests':checks,'actual':actual,'expected':expected})+'\n')
    for request, result, target in zip(requests,actual,expected):
        if target['status']=='resolved':
            assert result['status']=='resolved', (request,result,target)
            assert Path(result['file']).resolve()==Path(target['file']).resolve(), (request,result,target)
        elif target['status']=='builtin': assert result['status']=='builtin', (request,result,target)
        else: assert result['status'] in {'unresolved','blocked','unsupported'}, (request,result,target)
        assert result.get('resolution_is_invocation',False) is False
    return actual


@pytest.mark.parametrize('mode', ['require','import'])
def test_exports_conditions_match_node_and_order(tmp_path, mode):
    f=Fixture(tmp_path)
    for index, exports in enumerate([
        {'require':'./require.cjs','import':'./import.mjs','default':'./default.js'},
        {'module-sync':'./sync.mjs','import':'./import.mjs','require':'./require.cjs'},
        {'node-addons':'./native.js','node':'./node.js','default':'./default.js'},
        {'default':'./default.js','node':'./node.js'},
        {'node':{'browser':'./browser.js'},'default':'./default.js'},
        {'development':'./dev.js','default':'./default.js'},
    ]):
        f.package('node_modules/dep'+str(index),name='dep'+str(index),manifest={'exports':exports},
                  files={s:'throw Error("DO NOT EXECUTE")' for s in ('require.cjs','import.mjs','default.js','sync.mjs','native.js','node.js','browser.js','dev.js')})
    compare(f,[('', 'app.cjs' if mode=='require' else 'app.mjs','dep'+str(i),mode) for i in range(6)])
    compare(f,[('', 'app.cjs' if mode=='require' else 'app.mjs','dep5',mode)],conditions=['development'])


@pytest.mark.parametrize('mode', ['require','import'])
def test_exports_arrays_null_blocks_wildcards_and_no_fallback(tmp_path,mode):
    f=Fixture(tmp_path)
    exports={'.':'./index.js','./feature/*':'./lib/*.js','./feature/private/*':None,'./exact':'./exact.js',
             './array':[None,'./array.js'], './invalid-first':['../outside.js','./array.js'],
             './missing-first':['./absent.js','./array.js'],'./empty':[], './blocked':None}
    f.package('node_modules/dep',manifest={'exports':exports},files={s:'throw Error("DO NOT EXECUTE")' for s in ('index.js','lib/a.js','lib/private/a.js','exact.js','array.js','hidden.js')})
    compare(f,[('', 'app.cjs' if mode=='require' else 'app.mjs',s,mode) for s in
               ('dep','dep/feature/a','dep/feature/private/a','dep/exact','dep/array','dep/invalid-first','dep/missing-first','dep/empty','dep/blocked','dep/hidden.js')])


def test_commonjs_file_extension_main_and_nested_versions(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/dep',files={'lib/start.js':'throw Error("NEVER")'},manifest={'main':'./lib/start'})
    f.package('node_modules/consumer',name='consumer',files={'index.js':'throw Error("NEVER")'})
    f.package('node_modules/consumer/node_modules/dep',version='2.0.0')
    f.package('node_modules/folder',name='folder',manifest={'main':'./lib'},files={'lib/index.json':'{}'})
    write(tmp_path/'local.js','throw Error("NEVER")')
    write(tmp_path/'directory/index.js','throw Error("NEVER")')
    actual=compare(f,[('', 'app.cjs','dep','require'),('node_modules/consumer','index.js','dep','require'),
                     ('','app.cjs','folder','require'),('','app.cjs','./local','require'),('','app.cjs','./directory','require'),
                     ('','app.mjs','./local','import'),('','app.mjs','./directory','import'),('','app.mjs','./local.js','import')])
    assert actual[0]['purl']=='pkg:npm/dep@1.0.0'
    assert actual[1]['purl']=='pkg:npm/dep@2.0.0'


@pytest.mark.parametrize('mode',['require','import'])
def test_imports_and_package_self_reference(tmp_path, mode):
    f=Fixture(tmp_path,{'exports':{'.':'./app.cjs','./feature':'./feature.js'},
                        'imports':{'#local':'./local.js','#dep':'dep','#pattern/*':'./lib/*.js','#blocked':None}})
    f.package('node_modules/dep')
    for file in ('feature.js','local.js','lib/a.js'): write(tmp_path/file,'throw Error("NEVER")')
    compare(f,[('', 'app.cjs' if mode=='require' else 'app.mjs',s,mode) for s in
               ('fixture-app','fixture-app/feature','#local','#dep','#pattern/a','#blocked','#unknown')])


def test_builtins_do_not_alias_bare_user_packages(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/test',name='test')
    values=compare(f,[('','app.cjs',s,'require') for s in ('fs','node:fs','node:test','node:sqlite','test','node:unknown')])
    assert values[4]['purl']=='pkg:npm/test@1.0.0'


def test_missing_source_and_unsupported_loader_specs_remain_explicit(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep');f.sources=[]
    resolver=f.resolver()
    assert resolver.resolve('','app.cjs','dep')['reason']=='dependency_source_unavailable'
    for spec in ('https://example.org/code.js','file:///tmp/x.js','./file.js?query','./%2e%2e/x','C:/file.js'):
        assert resolver.resolve('','app.cjs',spec)['status']=='unsupported'


def test_captured_bytes_do_not_change_when_file_is_edited_after_capture(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep')
    resolver=f.resolver();before=resolver.resolve('','app.cjs','dep')
    write(tmp_path/'node_modules/dep/index.js','CHANGED')
    assert resolver.resolve('','app.cjs','dep')==before
    assert f.resolver().resolve('','app.cjs','dep')['source_sha256']!=before['source_sha256']


def test_esm_requires_exact_export_target_and_cjs_main_is_legacy(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/dep',manifest={'exports':'./entry'},files={'entry.js':'throw Error("NEVER")'})
    f.package('node_modules/legacy',name='legacy',manifest={'main':'./entry'},files={'entry.js':'throw Error("NEVER")'})
    compare(f,[('','app.cjs','dep','require'),('','app.mjs','dep','import'),('','app.cjs','legacy','require'),('','app.mjs','legacy','import')])


@pytest.mark.parametrize('mode',['require','import'])
def test_alias_scopes_and_parent_relative_imports(tmp_path,mode):
    f=Fixture(tmp_path)
    f.package('node_modules/alias',name='real-package',manifest={'exports':{'.':'./index.js','./feature':'./feature.js'}},
              files={'index.js':'throw Error("NEVER")','feature.js':'throw Error("NEVER")'})
    f.package('node_modules/@scope/dep',name='@scope/dep')
    write(tmp_path/'nested/importer.js','throw Error("NEVER")')
    values=compare(f,[('','nested/importer.js','alias',mode),('','nested/importer.js','@scope/dep',mode),
                      ('node_modules/alias','index.js','real-package/feature',mode),
                      ('node_modules/alias','index.js','../../app.cjs',mode)])
    assert values[0]['purl']=='pkg:npm/real-package@1.0.0'
    assert values[2]['instance']=='node_modules/alias'


@pytest.mark.parametrize('mode',['require','import'])
def test_self_conditions_and_imports_external_builtins(tmp_path,mode):
    f=Fixture(tmp_path,{'exports':{'.':{'module-sync':'./sync.mjs','node-addons':'./native.js','default':'./app.cjs'}},
                        'imports':{'#fs':'fs','#prefixed':'node:fs'}})
    write(tmp_path/'sync.mjs','throw Error("NEVER")')
    write(tmp_path/'native.js','throw Error("NEVER")')
    compare(f,[('','app.cjs','fixture-app',mode),('','app.cjs','#fs',mode),('','app.cjs','#prefixed',mode)])


def test_same_artifact_instances_keep_independent_lookup_context(tmp_path):
    f=Fixture(tmp_path)
    a=f.package('node_modules/a',name='shared')
    b=f.package('node_modules/b',name='shared')
    f.package('node_modules/a/node_modules/dep',version='1.0.0')
    f.package('node_modules/b/node_modules/dep',version='2.0.0')
    f.sources[1]['source']=f.sources[0]['source']
    resolver=f.resolver()
    assert resolver.resolve(a['location'],'index.js','dep')['purl']=='pkg:npm/dep@1.0.0'
    assert resolver.resolve(b['location'],'index.js','dep')['purl']=='pkg:npm/dep@2.0.0'
    assert resolver.resolve('','app.cjs','a')['instance']!=resolver.resolve('','app.cjs','b')['instance']


def test_workspace_alias_resolves_from_real_workspace_location(tmp_path):
    f=Fixture(tmp_path)
    work=f.package('packages/work',name='work')
    f.instances.append({**work,'location':'node_modules/work','source_location':'packages/work','source_kind':'workspace'})
    f.sources.append({'location':'node_modules/work','purl':work['purl'],'source':str(tmp_path/'packages/work')})
    f.package('packages/work/node_modules/dep',version='2.0.0')
    f.package('node_modules/work/node_modules/dep',version='3.0.0')
    f.package('node_modules/dep',version='1.0.0')
    resolver=f.resolver()
    assert resolver.resolve('node_modules/work','index.js','dep')['purl']=='pkg:npm/dep@2.0.0'
    assert resolver.resolve('','app.cjs','work')['instance']=='packages/work'


def test_workspace_symlink_matches_node_realpath_lookup(tmp_path):
    f=Fixture(tmp_path)
    work=f.package('packages/work',name='work')
    alias=tmp_path/'node_modules/work'
    alias.parent.mkdir(parents=True,exist_ok=True)
    try: alias.symlink_to(tmp_path/'packages/work',target_is_directory=True)
    except OSError: pytest.skip('Directory symlink requires privileges on this host; Linux CI exercises this case')
    f.instances.append({**work,'location':'node_modules/work','source_location':'packages/work','source_kind':'workspace'})
    f.sources.append({'location':'node_modules/work','purl':work['purl'],'source':str(tmp_path/'packages/work')})
    f.package('packages/node_modules/dep',version='2.0.0')
    f.package('node_modules/dep',version='1.0.0')
    compare(f,[('node_modules/work','index.js','dep','require'),('','app.cjs','work','require')])


def test_package_json_verification_and_capture_limits(tmp_path,monkeypatch):
    from scripts import node_resolution as module
    f=Fixture(tmp_path);f.package('node_modules/dep')
    file=tmp_path/'node_modules/dep/package.json'
    f.sources[0]['package_json_sha256']=hashlib.sha256(file.read_bytes()).hexdigest()
    write(file,{'name':'dep','version':'2.0.0'})
    with pytest.raises(ValueError,match='package_json_changed'): f.resolver()
    f.sources[0].pop('package_json_sha256')
    monkeypatch.setattr(module,'MAX_CAPTURE_BYTES',1)
    with pytest.raises(ValueError,match='capture_byte_limit'): f.resolver()


def test_invalid_package_json_and_numeric_export_keys_are_not_guessed(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/dep',manifest={'exports':{'1':'./index.js','default':'./index.js'}})
    compare(f,[('','app.cjs','dep','require'),('','app.mjs','dep','import')])
    write(tmp_path/'node_modules/dep/package.json','{broken json')
    assert f.resolver().resolve('','app.cjs','dep')['reason']=='invalid_package_json'


def test_format_evidence_does_not_claim_typescript_is_executable(tmp_path):
    f=Fixture(tmp_path,{'type':'module'})
    for file in ('explicit.mjs','explicit.cjs','ambiguous.js','code.ts','unknown.Js'):
        write(tmp_path/file,'throw Error("NEVER")')
    resolver=f.resolver()
    expected={'explicit.mjs':'esm','explicit.cjs':'commonjs','ambiguous.js':'esm',
              'code.ts':'typescript_requires_runtime_profile','unknown.Js':'unsupported_extension'}
    for file,kind in expected.items():
        assert resolver.resolve('','app.cjs','./'+file)['module_format']==kind


@pytest.mark.parametrize('mode',['require','import'])
def test_trailing_slashes_and_dot_directory_requests_match_node(tmp_path,mode):
    f=Fixture(tmp_path)
    f.package('node_modules/dep',manifest={'exports':{'.':'./index.js'}})
    f.package('node_modules/legacy',name='legacy')
    for file in ('local.js','directory/index.js','index.js','directory/importer.js'):
        write(tmp_path/file,'throw Error("NEVER")')
    compare(f,[('','app.cjs',s,mode) for s in ('./local.js/','./directory/','dep/','legacy/','.')]
              +[('','directory/importer.js','..',mode)])


def test_nested_conditions_have_an_explicit_depth_limit(tmp_path):
    f=Fixture(tmp_path)
    target='./index.js'
    for i in range(40): target={'default':target}
    f.package('node_modules/dep',manifest={'exports':target})
    value=f.resolver().resolve('','app.cjs','dep')
    assert value['status']=='unsupported' and value['reason']=='package_target_depth_limit'


def test_conflicting_instance_and_source_identities_are_rejected(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep')
    f.instances.append({**f.instances[0],'version':'2.0.0','purl':'pkg:npm/dep@2.0.0'})
    with pytest.raises(ValueError,match='duplicate_instance'): f.resolver()
    f.instances.pop()
    f.sources.append(dict(f.sources[0]))
    with pytest.raises(ValueError,match='duplicate_source'): f.resolver()
    f.sources.pop();f.sources[0]['purl']='pkg:npm/dep@2.0.0'
    with pytest.raises(ValueError,match='identity_mismatch'): f.resolver()


def test_duplicate_package_json_fields_follow_node_last_value_semantics(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/dep',files={'index.js':'throw Error("NEVER")','other.js':'throw Error("NEVER")'})
    write(tmp_path/'node_modules/dep/package.json','{"name":"dep","version":"1.0.0","author":"old","author":"new","main":"./other.js","main":"./index.js"}')
    compare(f,[('','app.cjs','dep','require'),('','app.mjs','dep','import')])
    resolver=f.resolver()
    captured=resolver.templates[resolver.roots['node_modules/dep']]
    assert captured['warnings']['package.json']==['author','main']


def test_version_identity_mismatch_cannot_borrow_another_packages_sources(tmp_path):
    f=Fixture(tmp_path);f.package('node_modules/dep')
    write(tmp_path/'node_modules/dep/package.json',{'name':'other','version':'1.0.0'})
    with pytest.raises(ValueError,match='version_identity_mismatch'): f.resolver()


def test_missing_workspace_realpath_is_not_resolved_like_a_registry_copy(tmp_path):
    f=Fixture(tmp_path)
    f.package('node_modules/work',name='work')
    f.instances[0].update(source_location='packages/work',source_kind='workspace')
    value=f.resolver().resolve('node_modules/work','index.js','dep')
    assert value['status']=='unsupported' and value['reason']=='workspace_realpath_source_unavailable'
