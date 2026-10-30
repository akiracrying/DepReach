"""Audit Node path candidates and lexical identity of direct CommonJS require.

Exported values, invocation and vulnerability reachability remain unmodeled.
"""
import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath

from scripts.node_resolution import NodeResolver, ResolutionError
from scripts.javascript_syntax import EXTENSIONS, parse_javascript
from scripts.javascript_bindings import JavaScriptBindings

MAX_MODULES = 20000
MAX_IMPORT_RECORDS = 50000


def _in_scope(relative, include_tests):
    path = PurePosixPath(relative)
    if path.suffix.lower() not in EXTENSIONS: return False
    if any(p.startswith('.') or p in {'node_modules','venv','__pycache__'} for p in path.parts[:-1]): return False
    if not include_tests and (any(p in {'test','tests','examples','docs'} for p in path.parts[:-1])
                              or any(mark in path.name for mark in ('.test.','.spec.'))): return False
    return True


def audit_node_imports(inventory, source_context, output_dir, *, conditions=(), include_tests=False, resolve_symbols=False):
    resolver = NodeResolver(inventory, source_context, conditions=conditions)
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    records_path = destination / 'imports.jsonl'
    modules, issues, counts, reasons = [], [], Counter(), Counter()
    parsed, module_seen, symbol_templates = {}, set(), {}
    omitted_modules = omitted_records = total_records = 0
    binding_counts, binding_reasons = Counter(), Counter()
    with records_path.open('x', encoding='utf-8') as output:
        for instance in sorted(resolver.roots):
            try:
                canonical = resolver.canonical_instance(instance)
            except ResolutionError as exc:
                issues.append({'instance':instance,'reason':exc.reason})
                continue
            root = resolver.roots[canonical]
            template = resolver.templates[root]
            for relative in sorted(template['contents']):
                if not _in_scope(relative, include_tests): continue
                identity = (canonical, relative)
                if identity in module_seen: continue
                module_seen.add(identity)
                # A nested workspace root owns its own modules, even when its
                # physical files are also beneath the captured application.
                virtual = canonical + '/' + relative if canonical else relative
                owner = resolver._physical(virtual)
                if not owner or owner[0] != canonical: continue
                if len(modules) >= MAX_MODULES:
                    omitted_modules += 1
                    continue
                key = (root, relative)
                if key not in parsed:
                    syntax = parse_javascript(Path(root, relative), template['contents'][relative])
                    facts = syntax.facts()
                    bindings = JavaScriptBindings(syntax, facts)
                    references = list(facts['imports'])
                    references.extend({'kind':'esm_reexport','owner':e['owner'],'specifier':e.get('source'),
                        'type_only':e.get('type_only',False), 'line':e['line'], 'column':e['column'],
                        'start_byte':e['start_byte'],'end_byte':e['end_byte']}
                        for e in facts['exports'] if e.get('has_source'))
                    for ref in references:
                        if ref['kind'] == 'commonjs_candidate':
                            ref['_bindings'] = {profile:bindings.commonjs_reference(ref, profile)
                                for profile in ('commonjs','esm','javascript_auto','unsupported')}
                    if resolve_symbols:
                        from scripts.javascript_values import ModuleValues
                        symbol_templates[key] = ModuleValues(syntax, bindings, facts).ir()
                    # Retain compact results, not trees/scopes for the entire source tree.
                    profiles = {profile:bindings.module_profile(profile) for profile in ('commonjs','esm','javascript_auto','unsupported')}
                    del bindings, syntax
                    parsed[key] = {'references':references, 'profiles':profiles, 'parse_complete':facts['parse_complete'],
                                   'issues':facts['issues'], 'runtime_source':facts['runtime_source'],
                                   'source_sha256':facts['source_sha256']}
                facts = parsed[key]
                try:
                    module_format = resolver._file(virtual)['module_format']
                    format_issue = None
                except ResolutionError as exc:
                    module_format, format_issue = 'unsupported', exc.reason
                profile_key = module_format if module_format in facts['profiles'] else 'unsupported'
                profile, profile_reason = facts['profiles'][profile_key]
                modules.append({'instance':canonical,'relative_file':relative, 'source_sha256':facts['source_sha256'],
                                'module_format':module_format, 'binding_profile':profile,
                                'binding_profile_reason':format_issue or profile_reason,
                                'parse_complete':facts['parse_complete'],'references':len(facts['references'])})
                issues.extend({'instance':canonical,'relative_file':relative,**issue} for issue in facts['issues'])
                for ref in facts['references']:
                    kind = ref['kind']
                    mode = 'require' if kind == 'commonjs_candidate' else 'import'
                    if ref.get('type_only') or not facts['runtime_source']:
                        resolution = {'status':'type_only','reason':'no_runtime_module_lookup'}
                    elif not facts['parse_complete']:
                        resolution = {'status':'unsupported','reason':'importer_syntax_incomplete'}
                    else:
                        resolution = resolver.resolve(canonical,relative,ref.get('specifier'),mode=mode)
                    binding_evidence = ref.get('_bindings', {}).get(profile_key)
                    binding = binding_evidence['status'] if binding_evidence else 'not_performed'
                    if kind == 'commonjs_candidate':
                        binding_counts[binding] += 1
                        binding_reasons[binding_evidence['reason']] += 1
                    record = {'importer_instance':canonical,'importer_file':relative,
                        'importer_source_sha256':facts['source_sha256'],'owner':ref['owner'],
                        'line':ref['line'],'column':ref.get('column',0),'start_byte':ref['start_byte'],'end_byte':ref['end_byte'],
                        'kind':kind,'specifier':ref.get('specifier'),'mode':mode,
                        'binding_resolution':binding,'resolution_is_invocation':False,'module_lookup':resolution}
                    if binding_evidence is not None: record['binding_evidence'] = binding_evidence
                    if PurePosixPath(relative).suffix.lower() in {'.ts','.tsx','.mts','.cts','.jsx'}:
                        record['runtime_boundary'] = 'compiler_or_typescript_runtime_profile_not_modeled'
                    total_records += 1
                    counts[resolution['status']] += 1
                    if resolution.get('reason'): reasons[resolution['reason']] += 1
                    if total_records > MAX_IMPORT_RECORDS:
                        omitted_records += 1
                        continue
                    output.write(json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n')
    if omitted_modules: issues.append({'reason':'module_audit_count_limit','omitted_modules':omitted_modules})
    if omitted_records: issues.append({'reason':'import_record_output_limit','omitted_records':omitted_records})
    warnings = [{'instance':loc,'relative_file':relative,'reason':'duplicate_package_json_keys_last_value_used','keys':keys}
                for loc,path in sorted(resolver.roots.items()) for relative,keys in resolver.templates[path]['warnings'].items()]
    captures = [{'instance':loc,'sha256':resolver.templates[path]['sha256']} for loc,path in sorted(resolver.roots.items())]
    engine = hashlib.sha256()
    for name in ('node_imports.py','node_resolution.py','javascript_syntax.py','javascript_bindings.py','javascript_values.py','node_symbols.py'):
        engine.update(name.encode()+b'\0'+Path(__file__).with_name(name).read_bytes().replace(b'\r\n',b'\n')+b'\0')
    parser_versions = {name:importlib.metadata.version(name) for name in ('tree-sitter','tree-sitter-javascript','tree-sitter-typescript')}
    fingerprint = hashlib.sha256(json.dumps([inventory.get('input_sha256'),captures,engine.hexdigest(),parser_versions,
        sorted(resolver.conditions),resolver.target_os,include_tests,resolve_symbols,'node-imports-v3'],sort_keys=True).encode()).hexdigest()
    complete = not issues and not (counts['unresolved'] or counts['unsupported']) and source_context.get('complete',False) and inventory.get('tree_complete',True)
    summary = {'schema_version':1,'analyzer_version':'node-imports-v3','profile':'node22_24_default',
        'engine_source_sha256':engine.hexdigest(),'parser_versions':parser_versions,
        'target_os':resolver.target_os,'conditions':sorted(resolver.conditions),'input_sha256':fingerprint,
        'source_captures':captures, 'sources_complete':source_context.get('complete',False),
        'inventory_complete':inventory.get('tree_complete',True),
        'records':str(records_path),'modules':modules,'issues':issues,'manifest_warnings':warnings,
        'candidate_lookup_complete':complete,'binding_resolution_implemented':True,
        'binding_resolution_scope':'direct_commonjs_require_identity_only',
        'commonjs_binding_complete':not binding_counts['unresolved_commonjs_binding'] and not issues
            and source_context.get('complete',False) and inventory.get('tree_complete',True),
        'exported_value_resolution_implemented':False, 'call_graph_implemented':False,'resolution_is_invocation':False,
        'scope':{'include_tests':include_tests,'custom_loaders':False,'node_path':False,
                 'typescript_compiler_paths':False,'filesystem_paths':'captured_lock_instances',
                 'excluded_application_roots':[str(p) for p in resolver.excluded_application_roots]},
        'counts':{'module_instances':len(modules),'physical_modules_parsed':len(parsed),
                  'references':total_records,'by_status':dict(sorted(counts.items())),
                  'by_reason':dict(sorted(reasons.items())), 'commonjs_bindings':dict(sorted(binding_counts.items())),
                  'commonjs_binding_reasons':dict(sorted(binding_reasons.items())),
                  'verified_commonjs_candidates':binding_counts['verified_commonjs_wrapper'],
                  'shadowed_commonjs_candidates':binding_counts['shadowed_commonjs_identifier'],
                  'unverified_commonjs_candidates':binding_counts['unresolved_commonjs_binding'],
                  'omitted_modules':omitted_modules,'omitted_records':omitted_records}}
    if resolve_symbols:
        from scripts.node_symbols import audit_node_symbols
        symbols = audit_node_symbols(resolver, modules, symbol_templates, destination/'symbols', provenance={
            'input_sha256':fingerprint, 'engine_source_sha256':engine.hexdigest(),
            'module_manifest':str((destination/'summary.json').resolve())})
        summary['symbol_manifest'] = str((destination/'symbols/summary.json').resolve())
        summary['symbol_summary'] = symbols
        summary['exported_value_resolution_implemented'] = True
        summary['exported_value_resolution_scope'] = 'stable_value_candidates'
        summary['call_target_resolution_implemented'] = True
        summary['symbol_audit_complete'] = complete and summary['commonjs_binding_complete'] and not (
            symbols['counts']['by_status'].get('unresolved') or symbols['counts']['omitted_records']
            or symbols['counts']['incomplete_value_modules'])
    (destination/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit Node module path candidates and direct CommonJS require identity without loading target code.')
    parser.add_argument('--inventory',required=True)
    parser.add_argument('--sources',required=True)
    parser.add_argument('--output',required=True,help='New directory for imports.jsonl and summary.json')
    parser.add_argument('--condition',action='append',default=[])
    parser.add_argument('--include-tests',action='store_true')
    parser.add_argument('--resolve-symbols',action='store_true',help='Also audit stable function target candidates; no vulnerability verdicts')
    args=parser.parse_args(argv)
    try:
        inventory=json.loads(Path(args.inventory).read_text(encoding='utf-8'))
        sources=json.loads(Path(args.sources).read_text(encoding='utf-8'))
        summary=audit_node_imports(inventory,sources,args.output,conditions=args.condition,include_tests=args.include_tests,resolve_symbols=args.resolve_symbols)
    except (ValueError,OSError,RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary['counts'],indent=2))
    if summary.get('symbol_summary'): print(json.dumps(summary['symbol_summary']['counts'],indent=2))
    print('Module/value target candidates only; entrypoint paths and JS/TS vulnerability reachability remain unsupported.')
    return 0 if summary['candidate_lookup_complete'] and summary['commonjs_binding_complete'] and summary.get('symbol_audit_complete',True) else 3


if __name__=='__main__':
    raise SystemExit(main())
