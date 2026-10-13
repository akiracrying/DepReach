"""Positive-only possible return types for constructor and registry patterns.

Models add possible paths. They never establish completeness or safe negatives.
No package names or vulnerable function names are hardcoded.
"""
import ast


def infer_return_types(graph, visitors):
    inferred, evidence = {}, []
    symbol_index = {}
    for symbol, info in graph.symbols.items():
        symbol_index.setdefault((info["file"], info["line"], info["kind"]), []).append(symbol)
    for tree, visitor in visitors:
        module, file = visitor.module, visitor.file
        def shadows(fn):
            args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
            return {a.arg for a in args} | {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)} | {n.name for n in ast.walk(fn) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        def resolve_class(node, shadowed=()):
            if not isinstance(node, ast.Call):
                return None
            base = node.func
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in shadowed:
                return None
            name = graph.resolve(visitor.resolve_expr(node.func))
            return name if name in graph.classes else None
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.decorator_list]:
            identities = symbol_index.get((file, fn.lineno, "function"), [])
            if len(identities) != 1:
                continue
            # Only direct function returns; nested scopes have their own result.
            returns = []
            class Returns(ast.NodeVisitor):
                def visit_Return(self, node):
                    candidate = resolve_class(node.value, shadows(fn))
                    if candidate:
                        returns.append(candidate)
                def visit_FunctionDef(self, node):
                    pass
                visit_AsyncFunctionDef = visit_FunctionDef
                visit_ClassDef = visit_FunctionDef
            for statement in fn.body:
                Returns().visit(statement)
            if len(set(returns)) == 1:
                inferred[identities[0]] = returns[0]
                evidence.append({"method": identities[0], "possible_return_class": returns[0],
                                 "file": file, "line": fn.lineno,
                                 "basis": "explicit_return_of_class_constructor", "completeness": "not_claimed"})
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            identities = symbol_index.get((file, cls.lineno, "class"), [])
            if len(identities) != 1:
                continue
            identity = identities[0]
            methods = {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.decorator_list}
            stores = []
            class_shadows = set().union(*(shadows(m) for m in methods.values()))
            for name, method in methods.items():
                args = [*method.args.posonlyargs, *method.args.args]
                if not args or args[0].arg != "self":
                    continue
                for node in ast.walk(method):
                    if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
                        continue
                    parameters = [a.arg for a in args]
                    if node.value.id not in parameters:
                        continue
                    for target in node.targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and isinstance(target.value.value, ast.Name) and target.value.value.id == "self":
                            stores.append((name, target.value.attr, parameters.index(node.value.id) - 1))
            stored_types = {}
            for node in ast.walk(cls):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name) or node.func.value.id != "self":
                    continue
                for method, attribute, position in stores:
                    if node.func.attr != method or position < 0 or position >= len(node.args):
                        continue
                    candidate = resolve_class(node.args[position], class_shadows)
                    if candidate:
                        stored_types.setdefault(attribute, set()).add(candidate)
            for name, method in methods.items():
                candidates = set()
                for loop in [n for n in ast.walk(method) if isinstance(n, ast.For)]:
                    call = loop.iter
                    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute) or call.func.attr not in {"items", "values"}:
                        continue
                    owner = call.func.value
                    if not isinstance(owner, ast.Attribute) or not isinstance(owner.value, ast.Name) or owner.value.id != "self":
                        continue
                    target = loop.target
                    value = target.elts[1] if call.func.attr == "items" and isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 2 else target if call.func.attr == "values" else None
                    if not isinstance(value, ast.Name):
                        continue
                    if any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id == value.id for n in ast.walk(loop)):
                        candidates.update(stored_types.get(owner.attr, set()))
                if len(candidates) == 1:
                    symbol = identity + "." + name
                    inferred[symbol] = next(iter(candidates))
                    evidence.append({"method": symbol, "possible_return_class": inferred[symbol],
                                     "file": file, "line": method.lineno,
                                     "basis": "class_constructor_registered_in_instance_mapping",
                                     "completeness": "not_claimed"})
    return inferred, evidence
