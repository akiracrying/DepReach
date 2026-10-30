"""Lower captured JS into bounded value expressions, without executing code.

Only stable declarations and explicit export forms are modeled. Unknown values
are retained as reasons, never used as evidence of unreachability.
"""
from scripts.javascript_bindings import JavaScriptBindings, _pattern_names
from scripts.javascript_syntax import FUNCTIONS, _literal, _span

MAX_EXPR_DEPTH = 48
MAX_OBJECT_PROPERTIES = 2000
MAX_VALUE_RECORDS = 100000


def unknown(reason):
    return {"kind": "unknown", "reason": reason}


def property_name(node, bindings):
    if node is None: return None
    if node.type in {"identifier", "property_identifier", "shorthand_property_identifier"}:
        return bindings._name(node)
    return _literal(node, bindings.syntax.raw)


def assignment_members(node):
    """Member targets in assignment patterns, excluding keys/default values."""
    stack=[node] if node is not None else []
    while stack:
        node=stack.pop()
        if node.type in {"member_expression","subscript_expression"}: yield node
        elif node.type in {"object_pattern","array_pattern","rest_pattern"}: stack.extend(node.named_children)
        elif node.type=="pair_pattern":
            value=node.child_by_field_name("value")
            if value is not None: stack.append(value)
        elif node.type in {"assignment_pattern","object_assignment_pattern"}:
            left=node.child_by_field_name("left")
            if left is not None: stack.append(left)


class ModuleValues:
    def __init__(self, syntax, bindings=None, facts=None):
        self.syntax = syntax
        self.facts = facts if facts is not None else syntax.facts()
        self.lexical = bindings if bindings is not None else JavaScriptBindings(syntax, self.facts)
        self.functions = {f["start_byte"]: dict(f) for f in self.facts["functions"]}
        for node in self.lexical.nodes.values():
            if node.type in FUNCTIONS and node.start_byte in self.functions:
                self.functions[node.start_byte]["async"]=any(c.type=="async" for c in node.children)
                self.functions[node.start_byte]["generator"]=any(c.type=="*" for c in node.children)
        self.bindings, self.binding_ids = {}, {}
        self.exports, self.stars, self.imports = {}, [], []
        self.unknown_export_names = False
        self.objects = {"cjs-initial": {}}
        self.default = {"kind": "object", "id": "cjs-initial"}
        self.exports_alias = self.default
        self.export_issues, self.recognized_export_nodes = set(), set()
        self.export_identity_issues = set()
        self.export_state = False
        self.by_span = {(n.start_byte,n.end_byte):n for n in self.lexical.nodes.values() if n.type in {"identifier","type_identifier","shorthand_property_identifier_pattern"}}
        scopes = {id(s):s for s in self.lexical.node_scopes.values()}
        for scope in scopes.values():
            for name, declarations in scope.bindings.items():
                key = f"{scope.kind}@{scope.start}:{name}"
                self.binding_ids[id(scope),name] = key
                self.bindings[key] = {"name":name,"scope_kind":scope.kind,"scope_start_byte":scope.start,
                    "declaration_count":len(declarations),"declarations":declarations[:8],"written":False,"object_mutated":False,
                    "value":unknown("declaration_value_not_modeled"),"ready_after":0,"hoisted":False}
        self.complete = self.lexical.complete and len(self.bindings)+len(self.facts["calls"])+len(self.functions) <= MAX_VALUE_RECORDS
        if not self.complete: return
        self._declarations(scopes)
        self._esm_exports()
        self._cjs_exports()
        self._effects()

    def _binding(self, node, name=None):
        name = name if name is not None else self.lexical._name(node)
        scope = self.lexical.node_scopes[node.id]
        owner, decls = self.lexical._lookup(scope,name)
        cursor = scope
        while cursor is not None:
            if cursor.dynamic: return None, "dynamic_with_binding"
            if (id(cursor),name) in self.lexical.annex_b_names: return None, "annex_b_binding_not_modeled"
            if cursor is owner: break
            cursor = cursor.parent
        return self.binding_ids.get((id(owner),name)), None

    def _wrapper(self, node, name):
        scope = self.lexical.node_scopes[node.id]
        while scope is not None:
            if scope.dynamic: return False
            scope=scope.parent
        owner, declarations=self.lexical._lookup(self.lexical.node_scopes[node.id],name)
        if name=="module" and name in self.lexical.wrapper_writes: return False
        return owner is None or (owner is self.lexical.root and all(d["kind"]=="var" and not d["initialized"] for d in declarations))

    def _module(self, specifier, mode, start):
        value={"kind":"module","specifier":specifier,"mode":mode,"start_byte":start}
        self.imports.append(value)
        return value

    def expr(self, node, depth=0):
        if node is None: return unknown("missing_expression")
        if depth>=MAX_EXPR_DEPTH: return unknown("value_expression_depth_limit")
        kind=node.type
        if kind in FUNCTIONS:
            function=self.functions.get(node.start_byte)
            return {"kind":"function","symbol":function["symbol"]} if function else unknown("function_definition_unavailable")
        if kind in {"identifier","shorthand_property_identifier"}:
            name=self.lexical._name(node)
            if self.export_state and name=="exports" and self._wrapper(node,name): return self.exports_alias
            if self.export_state and name=="module": return unknown("whole_module_object_not_modeled")
            binding,reason=self._binding(node)
            return {"kind":"binding","id":binding,"at_byte":node.start_byte} if binding else unknown(reason or "identifier_value_not_modeled")
        if kind in {"parenthesized_expression","await_expression"}:
            if kind=="await_expression": return unknown("awaited_value_flow_not_modeled")
            return self.expr(node.named_children[0],depth+1) if len(node.named_children)==1 else unknown("compound_parenthesized_value")
        if kind in {"member_expression","subscript_expression"}:
            base=node.child_by_field_name("object")
            prop=node.child_by_field_name("property") or node.child_by_field_name("index")
            key=_literal(prop,self.syntax.raw) if kind=="subscript_expression" else property_name(prop,self.lexical)
            if self.export_state and base.type=="identifier" and self.lexical._name(base)=="module" and key=="exports" and self._wrapper(base,"module"):
                return self.default
            return {"kind":"property","base":self.expr(base,depth+1),"name":key} if key is not None else unknown("computed_property_value_not_modeled")
        if kind=="call_expression":
            target=node.child_by_field_name("function")
            if target is not None and target.type=="identifier" and self.lexical._name(target)=="require":
                ref={**_span(node)}
                proof=self.lexical.commonjs_reference(ref,"commonjs")
                if proof["status"]!="verified_commonjs_wrapper": return unknown(proof["reason"])
                args=node.child_by_field_name("arguments")
                spec=_literal(args.named_children[0],self.syntax.raw) if args is not None and len(args.named_children)==1 else None
                return self._module(spec,"require",node.start_byte)
            return unknown("returned_value_flow_not_modeled")
        if kind=="new_expression": return unknown("constructed_instance_flow_not_modeled")
        if kind=="object":
            if len(node.named_children)>MAX_OBJECT_PROPERTIES: return unknown("object_property_count_limit")
            props={}
            for child in node.named_children:
                if child.type=="comment": continue
                if child.type=="shorthand_property_identifier":
                    key=self.lexical._name(child);value=self.expr(child,depth+1)
                elif child.type=="pair":
                    key=property_name(child.child_by_field_name("key"),self.lexical)
                    value=self.expr(child.child_by_field_name("value"),depth+1)
                    if key=="__proto__": return unknown("object_prototype_not_modeled")
                elif child.type=="method_definition" and not any(c.type in {"get","set"} for c in child.children):
                    key=property_name(child.child_by_field_name("name"),self.lexical);value=self.expr(child,depth+1)
                else: return unknown("object_spread_or_accessor_not_modeled")
                if key is None: return unknown("computed_object_key_not_modeled")
                props[key]=value
            identity="object@"+str(node.start_byte)
            self.objects[identity]=props
            return {"kind":"object","id":identity}
        if kind in {"string","number","true","false","null","undefined"}: return {"kind":"data"}
        return unknown("expression_"+kind+"_not_modeled")

    def _projection(self, pattern, target):
        current=pattern; path=[]
        while current is not None and current.id!=target.id:
            parent=current.parent
            if parent is None: return unknown("destructured_binding_path_unavailable")
            if parent.type=="pair_pattern":
                key=property_name(parent.child_by_field_name("key"),self.lexical)
                if key is None: return unknown("computed_destructuring_key_not_modeled")
                path.append(key)
            elif current.type=="shorthand_property_identifier_pattern": path.append(self.lexical._name(current))
            elif parent.type in {"array_pattern","rest_pattern","assignment_pattern","object_assignment_pattern"}:
                return unknown("destructuring_default_rest_or_array_not_modeled")
            current=parent
        return list(reversed(path))

    def _declarations(self, scopes):
        for scope in scopes.values():
            for name,decls in scope.bindings.items():
                item=self.bindings[self.binding_ids[id(scope),name]]
                if len(decls)!=1: item["value"]=unknown("multiple_binding_declarations"); continue
                declaration=decls[0]
                node=self.by_span.get((declaration["start_byte"],declaration["end_byte"]))
                if node is None: continue
                parent=node.parent
                if declaration["kind"] in {"function","function_name"}:
                    while parent is not None and parent.type not in FUNCTIONS: parent=parent.parent
                    item.update(value=self.expr(parent),hoisted=True)
                elif declaration["kind"] in {"lexical","var"}:
                    while parent is not None and parent.type!="variable_declarator": parent=parent.parent
                    if parent is None: continue
                    pattern=parent.child_by_field_name("name")
                    path=self._projection(node,pattern)
                    value=self.expr(parent.child_by_field_name("value"))
                    if isinstance(path,dict): value=path
                    else:
                        for key in path: value={"kind":"property","base":value,"name":key}
                    item.update(value=value,ready_after=parent.end_byte)
                    # Condition/loop-dependent initialization needs control flow.
                    control=parent.parent.parent
                    while control is not None and control.type not in FUNCTIONS and control.type!="program":
                        if control.type not in {"statement_block","export_statement"}:
                            item["value"]=unknown("conditional_or_loop_initialization_not_modeled");break
                        control=control.parent
                elif declaration["kind"]=="import":
                    statement=parent
                    while statement is not None and statement.type!="import_statement": statement=statement.parent
                    if statement is None: continue
                    if any(c.type=="type" for c in statement.children) or (parent.type=="import_specifier" and any(c.type=="type" for c in parent.children)):
                        item["value"]=unknown("type_only_import");continue
                    value=self._module(_literal(statement.child_by_field_name("source"),self.syntax.raw),"import",statement.start_byte)
                    if parent.type=="import_clause": value={"kind":"property","base":value,"name":"default"}
                    elif parent.type=="import_specifier":
                        value={"kind":"property","base":value,"name":property_name(parent.child_by_field_name("name"),self.lexical)}
                    item.update(value=value,hoisted=True)

    def _live_export(self,node):
        value=self.expr(node)
        if value["kind"]=="binding": value["after_initialization"]=True
        return value

    def _esm_exports(self):
        if self.syntax.tree is None: return
        for node in self.syntax.tree.root_node.named_children:
            if node.type!="export_statement" or any(c.type=="type" for c in node.children): continue
            source=node.child_by_field_name("source")
            remote=self._module(_literal(source,self.syntax.raw),"import",node.start_byte) if source is not None else None
            declaration=node.child_by_field_name("declaration")
            value=node.child_by_field_name("value")
            if any(c.type=="default" for c in node.children):
                default_node=value or declaration
                if declaration is not None and declaration.type in {"function_declaration","generator_function_declaration"}:
                    default_node=declaration.child_by_field_name("name") or declaration
                self.exports["default"]=self._live_export(default_node) if declaration is not None else self.expr(default_node)
                continue
            if declaration is not None:
                if declaration.type in {"function_declaration","generator_function_declaration","class_declaration"}:
                    name=declaration.child_by_field_name("name")
                    if name is not None: self.exports[self.lexical._name(name)]=self._live_export(name)
                else:
                    for variable in declaration.named_children:
                        if variable.type=="variable_declarator":
                            for name in _pattern_names(variable.child_by_field_name("name")):
                                self.exports[self.lexical._name(name)]=self._live_export(name)
                continue
            clause=next((c for c in node.named_children if c.type=="export_clause"),None)
            namespace=next((c for c in node.named_children if c.type=="namespace_export"),None)
            if clause is not None:
                for spec in clause.named_children:
                    if spec.type!="export_specifier": continue
                    name=property_name(spec.child_by_field_name("name"),self.lexical)
                    alias_node=spec.child_by_field_name("alias")
                    alias=property_name(alias_node,self.lexical) if alias_node is not None else name
                    if alias is None:
                        self.unknown_export_names=True
                        continue
                    self.exports[alias]=unknown("esm_export_name_not_modeled") if name is None else ({"kind":"property","base":remote,"name":name} if remote else self._live_export(spec.child_by_field_name("name")))
            elif namespace is not None:
                alias=property_name(namespace.named_children[0],self.lexical)
                if alias is None: self.unknown_export_names=True
                else: self.exports[alias]=remote
            elif remote is not None: self.stars.append(remote)

    def _export_target(self, node):
        path=[]; base=node
        while base is not None and base.type in {"member_expression","subscript_expression"}:
            prop=base.child_by_field_name("property") or base.child_by_field_name("index")
            key=_literal(prop,self.syntax.raw) if base.type=="subscript_expression" else property_name(prop,self.lexical)
            path.insert(0,key);base=base.child_by_field_name("object")
        if base is None or base.type!="identifier": return None
        name=self.lexical._name(base)
        if name not in {"module","exports"} or not self._wrapper(base,name): return None
        if name=="module":
            if not path or path[0]!="exports": return None
            return "default",path[1:]
        return "alias",path

    def _local_object(self,value,seen=None):
        seen=set() if seen is None else seen
        if len(seen)>=MAX_EXPR_DEPTH: return None
        if value["kind"]=="object": return value["id"]
        if value["kind"]=="function":
            key="function@"+value["symbol"]
            self.objects.setdefault(key,{})
            return key
        if value["kind"]=="binding":
            key=value["id"]
            if key in seen: return None
            item=self.bindings.get(key)
            if item is None or item["written"] or (not item["hoisted"] and value["at_byte"]<item["ready_after"]): return None
            return self._local_object(item["value"],seen|{key})
        return None

    def _apply_export_assignment(self,node,depth=0):
        if depth>=MAX_EXPR_DEPTH: return unknown("export_assignment_depth_limit")
        left=node.child_by_field_name("left")
        right=node.child_by_field_name("right")
        target=self._export_target(left)
        if target is None and left.type!="identifier": return unknown("complex_export_chain_assignment")
        value=self._apply_export_assignment(right,depth+1) if right.type=="assignment_expression" else self.expr(right)
        if target is not None:
            base,path=target
            if len(path)>1 or any(key is None for key in path):
                self.export_issues.add("conditional_delayed_or_computed_export_mutation")
                if base=="default" and not path: self.export_identity_issues.add("unmodeled_module_export_identity")
                return unknown("unmodeled_export_target")
            if not path:
                if base=="default": self.default=value
                else: self.exports_alias=value
            else:
                obj=self.default if base=="default" else self.exports_alias
                identity=self._local_object(obj)
                if identity is None: self.export_issues.add("export_alias_object_mutation_not_modeled")
                elif len(self.objects[identity])>=MAX_OBJECT_PROPERTIES: self.export_issues.add("export_property_count_limit")
                else: self.objects[identity][path[0]]=value
        self.recognized_export_nodes.add(node.id)
        return value

    def _cjs_exports(self):
        self.export_state=True
        for node in sorted(self.lexical.nodes.values(),key=lambda n:n.start_byte):
            if node.id in self.recognized_export_nodes: continue
            if node.type not in {"assignment_expression","augmented_assignment_expression","update_expression","unary_expression","for_in_statement"}: continue
            if node.type=="unary_expression" and not any(c.type=="delete" for c in node.children): continue
            left=node.child_by_field_name("left") or node.child_by_field_name("argument")
            target=self._export_target(left)
            parent=node.parent
            top_expression=parent.type=="expression_statement" and parent.parent.type=="program"
            top_initializer=parent.type=="variable_declarator" and parent.parent.parent.type=="program" and parent.child_by_field_name("value").id==node.id
            if node.type=="assignment_expression" and (top_expression or top_initializer):
                self._apply_export_assignment(node)
                continue
            if target is None: continue
            self.export_issues.add("conditional_delayed_or_computed_export_mutation")
            if target==("default",[]): self.export_identity_issues.add("unmodeled_module_export_identity")
        self.export_state=False
        # Aliasing/escaping the wrapper's export object can mutate its shape.
        for node in self.lexical.nodes.values():
            if node.type!="identifier" or self.lexical._name(node) not in {"module","exports"} or not self._wrapper(node,self.lexical._name(node)): continue
            parent=node.parent
            if parent is None: continue
            ancestor=parent
            while ancestor is not None and ancestor.type not in FUNCTIONS:
                if ancestor.id in self.recognized_export_nodes: break
                ancestor=ancestor.parent
            if ancestor is not None and ancestor.id in self.recognized_export_nodes: continue
            if parent.type in {"member_expression","subscript_expression"} and parent.child_by_field_name("object").id==node.id:
                whole=parent
                if self.lexical._name(node)=="module" and self._export_target(parent)!=("default",[]): continue
                while whole.parent is not None and whole.parent.type in {"member_expression","subscript_expression"} and whole.parent.child_by_field_name("object").id==whole.id: whole=whole.parent
                consumer=whole.parent
                mutation=consumer
                while mutation is not None and mutation.type not in FUNCTIONS:
                    left=mutation.child_by_field_name("left") if mutation.type in {"assignment_expression","augmented_assignment_expression","for_in_statement"} else None
                    if left is not None and left.start_byte<=whole.start_byte and whole.end_byte<=left.end_byte:
                        self.export_issues.add("unmodeled_export_mutation")
                        if self._export_target(whole)==("default",[]): self.export_identity_issues.add("unmodeled_module_export_identity")
                        break
                    mutation=mutation.parent
                if consumer is not None and consumer.type=="assignment_expression" and consumer.child_by_field_name("left").id==whole.id: continue
                if consumer is not None and consumer.type in {"call_expression","new_expression"} and (consumer.child_by_field_name("function") or consumer.child_by_field_name("constructor")).id==whole.id: continue
                # Reading a named exported property does not expose the export object.
                target=self._export_target(whole)
                if target and target[1] and consumer is not None and consumer.type not in {"arguments","variable_declarator","assignment_expression","return_statement"}: continue
            if parent.type=="unary_expression" and any(c.type=="typeof" for c in parent.children): continue
            if parent.type=="assignment_expression" and parent.child_by_field_name("left").id==node.id: continue
            self.export_issues.add("commonjs_export_object_escaped_or_aliased")
            if self.lexical._name(node)=="module" and parent.type not in {"member_expression","subscript_expression"}:
                self.export_identity_issues.add("module_object_escaped_or_aliased")

    def _effects(self):
        for scope,target in self.lexical.writes:
            for name in _pattern_names(target):
                owner,_=self.lexical._lookup(scope,self.lexical._name(name))
                key=self.binding_ids.get((id(owner),self.lexical._name(name)))
                if key: self.bindings[key]["written"]=True
        aliases={key:set() for key in self.bindings}
        for key,item in self.bindings.items():
            value=item["value"]
            if value["kind"]=="binding" and value["id"] in aliases:
                aliases[key].add(value["id"]);aliases[value["id"]].add(key)
        mutations=[]
        for node in self.lexical.nodes.values():
            if node.id in self.recognized_export_nodes: continue
            roots=[]
            if node.type in {"assignment_expression","augmented_assignment_expression","update_expression","unary_expression","for_in_statement"}:
                target=node.child_by_field_name("left") or node.child_by_field_name("argument")
                roots=list(assignment_members(target))
            elif node.type=="arguments":
                # Unknown callees can mutate object arguments. Function identity
                # remains usable, while projections through those objects don't.
                for arg in node.named_children:
                    while arg.type in {"member_expression","subscript_expression"}: arg=arg.child_by_field_name("object")
                    if arg.type=="identifier":
                        key,_=self._binding(arg)
                        if key: self.bindings[key]["object_mutated"]=True
                    elif arg.type=="call_expression": mutations.append(self.expr(arg))
            for root in roots:
                while root.type in {"member_expression","subscript_expression"}: root=root.child_by_field_name("object")
                mutations.append(self.expr(root))
                if root.type=="identifier":
                    key,_=self._binding(root)
                    if key: self.bindings[key]["object_mutated"]=True
        todo=[key for key,item in self.bindings.items() if item["object_mutated"]]
        seen=set(todo)
        while todo:
            key=todo.pop()
            for alias in aliases[key]-seen:
                seen.add(alias);todo.append(alias);self.bindings[alias]["object_mutated"]=True
        mutations.extend(item["value"] for item in self.bindings.values() if item["object_mutated"])
        self.mutations=mutations

    def ir(self):
        for ref in self.facts["imports"]:
            if ref["kind"]=="commonjs_candidate":
                if self.lexical.commonjs_reference(ref,"commonjs")["status"]=="verified_commonjs_wrapper":
                    self._module(ref.get("specifier"),"require",ref["start_byte"])
            elif ref["kind"]=="esm" and not ref.get("type_only"):
                self._module(ref.get("specifier"),"import",ref["start_byte"])
        calls=[]
        for call in self.facts["calls"]:
            node=self.lexical.nodes.get((call["start_byte"],call["end_byte"],call["kind"]))
            target=(node.child_by_field_name("function") or node.child_by_field_name("constructor")) if node is not None else None
            calls.append({k:call[k] for k in ("owner","kind","start_byte","end_byte","line","column","target_name")})
            value=self.expr(target) if self.complete else unknown("symbol_ir_incomplete_or_limit")
            if target is not None and target.type=="identifier" and self.lexical._name(target)=="require":
                if self.lexical.commonjs_reference(call,"commonjs")["status"]=="verified_commonjs_wrapper":
                    value={"kind":"builtin","name":"CommonJS require"}
            calls[-1]["value"]=value
        return {"source_sha256":self.facts["source_sha256"],"complete":self.complete,
                "dynamic_reasons":sorted(self.lexical.dynamic_reasons),"functions":list(self.functions.values()),
                "bindings":self.bindings,"objects":self.objects,"esm_exports":self.exports,"esm_stars":self.stars,
                "esm_unknown_export_names":self.unknown_export_names,
                "cjs_default":self.default,"cjs_export_issues":sorted(self.export_issues),
                "cjs_identity_issues":sorted(self.export_identity_issues),
                "imports":self.imports,"calls":calls,"mutations":getattr(self,"mutations",[])}
