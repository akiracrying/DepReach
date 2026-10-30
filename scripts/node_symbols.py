"""Resolve stable JS function target candidates over contextual captured modules.

Only call/new expressions create records. Root execution, receiver/callback flow,
loadability and vulnerability target mapping are separate, unfinished stages.
"""
from collections import Counter
import json
from pathlib import Path

MAX_VALUE_DEPTH = 64
MAX_VALUE_STEPS = 256
MAX_TRACE = 24
MAX_CALL_RECORDS = 100000
MAX_CALL_RECORD_TEXT = 16384
MAX_CALL_RECORD_BYTES = 65536
MAX_CALL_OUTPUT_BYTES = 128 * 1024 * 1024


def record_text_within_limit(record):
    remaining=MAX_CALL_RECORD_TEXT
    stack=[record]
    while stack:
        value=stack.pop()
        if isinstance(value,str):
            remaining-=len(value)
            if remaining<0: return False
        elif isinstance(value,dict): stack.extend(value.keys());stack.extend(value.values())
        elif isinstance(value,list): stack.extend(value)
    return True


def missing(reason):
    return {"kind":"unknown","reason":reason}


def components(graph):
    """Iterative SCC partition; recursion depth does not depend on input graph."""
    visited,order=set(),[]
    for start in graph:
        if start in visited: continue
        stack=[(start,False)]
        while stack:
            node,done=stack.pop()
            if done: order.append(node);continue
            if node in visited: continue
            visited.add(node);stack.append((node,True))
            stack.extend((child,False) for child in graph[node] if child not in visited)
    reverse={key:set() for key in graph}
    for node,children in graph.items():
        for child in children: reverse[child].add(node)
    result,sizes={},Counter()
    for start in reversed(order):
        if start in result: continue
        component=len(sizes);stack=[start]
        while stack:
            node=stack.pop()
            if node in result: continue
            result[node]=component;sizes[component]+=1
            stack.extend(child for child in reverse[node] if child not in result)
    return result,sizes


class NodeSymbols:
    def __init__(self,resolver,modules,templates):
        self.resolver=resolver
        self.modules={}
        for module in modules:
            key=(module['instance'],module['relative_file'])
            physical=(resolver.roots[key[0]],key[1])
            if physical in templates:
                self.modules[key]={**module,'ir':templates[physical],'function_index':{f['symbol']:f for f in templates[physical]['functions']}}
        self.lookup_cache={}
        self.graph={key:set() for key in self.modules}
        for key,module in self.modules.items():
            for ref in module['ir']['imports']:
                target=self.module_target(key,ref)
                if target['kind']=='module': self.graph[key].add(target['key'])
        self.component,self.component_sizes=components(self.graph)
        self.mutated_modules=set()
        for key,module in self.modules.items():
            for expr in module['ir']['mutations']:
                terminal=self._namespace_alias(key,expr,set())
                if terminal is not None: self.mutated_modules.add(terminal)

    def module_target(self,key,ref):
        cache=(key,ref['mode'],ref.get('specifier'))
        if cache in self.lookup_cache: return self.lookup_cache[cache]
        result=self.resolver.resolve(*key,ref.get('specifier'),mode=ref['mode'])
        if result['status']=='resolved':
            target=(result['instance'],result['relative_file'])
            if target in self.modules: value={'kind':'module','key':target}
            elif result.get('module_format') in {'native_addon','json_data','unsupported_extension'}:
                value=missing('target_'+result['module_format']+'_not_modeled')
            else: value=missing('target_module_outside_symbol_scope')
        elif result['status']=='builtin': value={'kind':'builtin','name':result.get('module',ref.get('specifier'))}
        else: value=missing(result.get('reason','module_lookup_unresolved'))
        self.lookup_cache[cache]=value
        return value

    def _namespace_alias(self,key,expr,seen):
        if len(seen)>=MAX_VALUE_DEPTH: return None
        if expr['kind']=='module':
            target=self.module_target(key,expr)
            return target.get('key') if target['kind']=='module' else None
        if expr['kind']=='binding':
            token=(key,expr['id'])
            if token in seen: return None
            item=self.modules[key]['ir']['bindings'].get(expr['id'])
            return self._namespace_alias(key,item['value'],seen|{token}) if item else None
        return None

    @staticmethod
    def trace(state,value):
        if len(state['trace'])<MAX_TRACE: state['trace'].append(value)
        else: state['omitted_trace']+=1

    def _export(self,key,name,state,seen,depth):
        module=self.modules[key]
        ir=module['ir']
        if ir['dynamic_reasons']: return missing(ir['dynamic_reasons'][0])
        if module['binding_profile']=='commonjs':
            if name!='default': return missing('esm_named_commonjs_interop_not_modeled')
            return self._commonjs_value(key,(),state,seen,depth+1)
        if name in ir['esm_exports']:
            self.trace(state,{'kind':'esm_export','instance':key[0],'file':key[1],'name':name})
            return self.value(key,ir['esm_exports'][name],(),state,seen,depth+1)
        if name is None or ir['esm_unknown_export_names']: return missing('esm_export_name_not_modeled')
        if name=='default': return missing('esm_export_missing')
        candidates=[];unknown=False
        for ref in ir['esm_stars']:
            candidate=self.value(key,ref,(name,),state,seen,depth+1)
            if candidate['kind']=='unknown':
                if candidate['reason']!='esm_export_missing': unknown=True
            else: candidates.append(candidate)
        if unknown: return missing('esm_star_export_unresolved_branch')
        if not candidates: return missing('esm_export_missing')
        identities={(v.get('kind'),v.get('key'),v.get('symbol'),v.get('id'),v.get('name')) for v in candidates}
        if len(identities)!=1: return missing('ambiguous_esm_star_export')
        return candidates[0]

    def _commonjs_value(self,key,projection,state,seen,depth):
        ir=self.modules[key]['ir']
        if ir['dynamic_reasons']: return missing(ir['dynamic_reasons'][0])
        if ir['cjs_identity_issues']: return missing(ir['cjs_identity_issues'][0])
        value=self.value(key,ir['cjs_default'],(),state,seen,depth+1)
        if ir['cjs_export_issues'] and value['kind']!='unknown':
            value={**value,'shape_unknown':True,'shape_reason':ir['cjs_export_issues'][0]}
        return self.project(value,projection,state,seen,depth+1)

    def project(self,resolved,projection,state,seen,depth):
        if not projection or resolved['kind']=='unknown': return resolved
        if resolved.get('shape_unknown'): return missing(resolved.get('shape_reason','object_binding_mutated_or_escaped'))
        key=resolved.get('key')
        if resolved['kind']=='builtin': return {**resolved,'name':resolved['name']+'.'+'.'.join(projection)}
        if resolved['kind']=='object':
            if key in self.mutated_modules: return missing('module_export_object_mutated_or_escaped')
            props=self.modules[key]['ir']['objects'].get(resolved['id'],{})
            name,*rest=projection
            if name not in props: return missing('property_not_in_modeled_object')
            return self.value(key,props[name],tuple(rest),state,seen,depth+1)
        if resolved['kind']=='namespace':
            if key in self.mutated_modules: return missing('module_namespace_mutated_or_escaped')
            name,*rest=projection
            return self.project(self._export(key,name,state,seen,depth+1),tuple(rest),state,seen,depth+1)
        if resolved['kind']=='function':
            if key in self.mutated_modules: return missing('module_export_object_mutated_or_escaped')
            props=self.modules[key]['ir']['objects'].get('function@'+resolved['symbol'],{})
            name,*rest=projection
            if name in props: return self.value(key,props[name],tuple(rest),state,seen,depth+1)
            return missing('function_properties_not_modeled')
        return missing('property_value_not_modeled')

    def value(self,key,expr,projection,state,seen,depth=0):
        state['steps']+=1
        if depth>=MAX_VALUE_DEPTH or state['steps']>MAX_VALUE_STEPS: return missing('symbol_resolution_resource_limit')
        token=(key,id(expr),projection)
        if token in seen: return missing('cyclic_value_binding')
        seen=seen|{token}
        kind=expr['kind']
        module=self.modules[key];ir=module['ir']
        if not ir['complete']: return missing('symbol_ir_incomplete_or_limit')
        if module['binding_profile']=='unsupported': return missing(module['binding_profile_reason'])
        if kind=='unknown': return expr
        if kind=='property': return self.value(key,expr['base'],(expr['name'],*projection),state,seen,depth+1)
        if kind=='binding':
            item=ir['bindings'].get(expr['id'])
            if item is None: return missing('binding_identity_unavailable')
            if ir['dynamic_reasons']: return missing(ir['dynamic_reasons'][0])
            if item['written']: return missing('binding_may_be_reassigned')
            if not item['hoisted'] and not expr.get('after_initialization') and expr['at_byte']<item['ready_after']: return missing('binding_initialization_order_not_modeled')
            if item['object_mutated'] and projection: return missing('object_binding_mutated_or_escaped')
            self.trace(state,{'kind':'lexical_binding','instance':key[0],'file':key[1],'name':item['name'],
                              'scope_kind':item['scope_kind'],'scope_start_byte':item['scope_start_byte']})
            value=self.value(key,item['value'],projection,state,seen,depth+1)
            return {**value,'shape_unknown':True} if item['object_mutated'] and value['kind']!='unknown' else value
        if kind=='function': return self.project({'kind':'function','key':key,'symbol':expr['symbol']},projection,state,seen,depth+1)
        if kind=='object': return self.project({'kind':'object','key':key,'id':expr['id']},projection,state,seen,depth+1)
        if kind=='module':
            if expr['mode']=='require' and module['binding_profile']!='commonjs': return missing('require_not_a_node_esm_binding')
            target=self.module_target(key,expr)
            if target['kind']!='module': return self.project(target,projection,state,seen,depth+1)
            target_key=target['key'];target_module=self.modules[target_key]
            self.trace(state,{'kind':'module_lookup','instance':key[0],'file':key[1],'specifier':expr.get('specifier'),
                              'target_instance':target_key[0],'target_file':target_key[1],'mode':expr['mode']})
            component=self.component[key]
            if self.component[target_key]==component and (self.component_sizes[component]>1 or key in self.graph[key]):
                return missing('cyclic_module_initialization_not_modeled')
            if target_module['binding_profile']=='unsupported': return missing('target_runtime_profile_not_modeled')
            if expr['mode']=='require':
                if target_module['binding_profile']!='commonjs': return missing('require_esm_interop_not_modeled')
                self.trace(state,{'kind':'commonjs_export','instance':target_key[0],'file':target_key[1]})
                return self._commonjs_value(target_key,projection,state,seen,depth+1)
            return self.project({'kind':'namespace','key':target_key},projection,state,seen,depth+1)
        if kind=='builtin': return self.project(expr,projection,state,seen,depth+1)
        return missing('non_function_value')

    def resolve_call(self,key,call):
        state={'steps':0,'trace':[],'omitted_trace':0}
        resolved=self.value(key,call['value'],(),state,set())
        record={k:v for k,v in call.items() if k!='value'}
        record.update(importer_instance=key[0],importer_file=key[1],source_sha256=self.modules[key]['ir']['source_sha256'],
                      evidence=state['trace'],omitted_evidence=state['omitted_trace'],
                      entrypoint_reachable=None,vulnerability_reachable=None,target_is_runtime_proven=False)
        if resolved['kind']=='function':
            target=self.modules[resolved['key']]
            function=target['function_index'][resolved['symbol']]
            if call['kind']=='new_expression' and (function.get('async') or function['kind'] not in {'function_declaration','function_expression'}):
                return {**record,'status':'unresolved','reason':'constructor_semantics_not_modeled'}
            semantics='generator_creation' if function.get('generator') or 'generator' in function['kind'] else 'constructor_call' if call['kind']=='new_expression' else 'direct_call'
            return {**record,'status':'modeled_function_target','invocation_semantics':semantics,
                'target':{'instance':resolved['key'][0],'relative_file':resolved['key'][1],
                          'purl':self.resolver.instances[resolved['key'][0]].get('purl'),
                          'module_source_sha256':target['ir']['source_sha256'],**function}}
        if resolved['kind']=='builtin': return {**record,'status':'builtin','builtin':resolved['name']}
        return {**record,'status':'unresolved','reason':resolved.get('reason','value_is_not_a_modeled_function')}


def audit_node_symbols(resolver,modules,templates,output_dir,*,provenance=None):
    output=Path(output_dir);output.mkdir(exist_ok=False)
    engine=NodeSymbols(resolver,modules,templates)
    counts,reasons,application_counts,application_reasons=Counter(),Counter(),Counter(),Counter()
    examples=[];omission_reasons=Counter()
    total=omitted=written_bytes=0
    path=output/'calls.jsonl'
    with path.open('x',encoding='utf-8',newline='\n') as stream:
        for key,module in sorted(engine.modules.items()):
            for call in module['ir']['calls']:
                record=engine.resolve_call(key,call)
                total+=1;counts[record['status']]+=1
                if record.get('reason'): reasons[record['reason']]+=1
                if not key[0]:
                    application_counts[record['status']]+=1
                    if record.get('reason'): application_reasons[record['reason']]+=1
                reason=None;line=None
                if total>MAX_CALL_RECORDS: reason='call_record_count_limit'
                elif not record_text_within_limit(record): reason='call_record_text_limit'
                else:
                    line=json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n'
                    size=len(line.encode('utf-8'))
                    if size>MAX_CALL_RECORD_BYTES: reason='call_record_byte_limit'
                    elif written_bytes+size>MAX_CALL_OUTPUT_BYTES: reason='call_output_byte_limit'
                if reason:
                    omitted+=1;omission_reasons[reason]+=1
                    continue
                stream.write(line);written_bytes+=size
                if not key[0] and record['status']=='modeled_function_target' and len(examples)<8 and (record['target']['instance'],record['target']['relative_file'])!=key:
                    example={'caller_file':key[1],'caller_line':record['line'],'callee':record.get('target_name'),
                        'target_instance':record['target']['instance'],'target_file':record['target']['relative_file'],
                        'target_line':record['target']['line'],'target_name':record['target']['qualified_name'],
                        'target_source_sha256':record['target']['source_sha256'],'invocation_semantics':record['invocation_semantics']}
                    for field,value in list(example.items()):
                        if isinstance(value,str) and len(value)>512:
                            example[field]=value[:512]+'…';example[field+'_truncated']=True
                    examples.append(example)
    summary={'schema_version':1,'analyzer_version':'node-symbols-v1','scope':'stable_value_function_target_candidates',
             'calls':str(path.resolve()),'call_graph_implemented':False,'function_body_reachability_implemented':False,
             'vulnerability_reachability_implemented':False,'counts':{'module_instances':len(engine.modules),
             'calls':total,'by_status':dict(counts),'by_reason':dict(reasons),'omitted_records':omitted,
             'omission_reasons':dict(omission_reasons),'output_bytes':written_bytes,
             'mutated_module_values':len(engine.mutated_modules),
             'incomplete_value_modules':sum(not m['ir']['complete'] for m in engine.modules.values())},
             'application_counts':{'by_status':dict(application_counts),'by_reason':dict(application_reasons)},
             'application_examples':examples,
             'assumptions':['declared_default_node_profile','unmodeled_receiver_heap_and_loader_effects_may_change_values',
                            'target_identity_is_not_runtime_execution_or_loadability_proof'],
             'boundaries':['entrypoint_execution','receiver_and_return_flow','callback_forwarding','module_initialization_cycles',
                           'custom_loaders_and_compilers','immutable_vulnerability_target_mapping']}
    if provenance: summary.update(provenance)
    (output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return summary
