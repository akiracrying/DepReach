"""A deliberately bounded Python call graph; never executes scanned code.

Symbols are module-qualified. Edges are possible static calls, not proof that
execution reaches a statement. Dynamic/unsupported constructs are recorded.
All first-party functions are roots: this is library-use analysis, not an
HTTP-entrypoint or exploitability analysis.
"""
from __future__ import annotations

import ast
import builtins
import hashlib
import io
import os
import tokenize
from collections import deque
from dataclasses import dataclass
from pathlib import Path

EXCLUDED = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
            "site-packages", "node_modules", "build", "dist", "data", "reports",
            "tests_local", "docs", "examples", ".tox", ".nox", ".pytest_cache"}
TEST_DIRS = {"tests", "test", "testing"}
DYNAMIC = {"getattr", "setattr", "eval", "exec", "__import__", "globals", "locals"}


def _walk_error(error):
    raise error


def python_files(directory, include_tests=False):
    directory = Path(directory).resolve()
    for root, dirs, files in os.walk(directory, followlinks=False, onerror=_walk_error):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith(".")
                         and (include_tests or d not in TEST_DIRS)
                         and not Path(root, d).is_symlink())
        for name in sorted(files):
            path = Path(root, name)
            if name.endswith(".py") and not path.is_symlink():
                if not include_tests and (name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"):
                    continue
                yield path


@dataclass(frozen=True)
class SourceSnapshot:
    """Bytes captured once for hashing, parsing and patch mapping.

    Capture is a traversal, not an atomic filesystem transaction. Later edits
    cannot change this snapshot; a new scan must capture a new one.
    """
    root: Path
    include_tests: bool
    files: tuple[tuple[Path, bytes], ...]
    digest: str
    root_is_package: bool


def capture_sources(directory, include_tests=False):
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Source directory does not exist: {root}")
    files = tuple((path, path.read_bytes()) for path in python_files(root, include_tests))
    digest = hashlib.sha256()
    for path, raw in files:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
    return SourceSnapshot(root, bool(include_tests), files, digest.hexdigest(),
                          any(path == root / "__init__.py" for path, _ in files))


def source_fingerprint(directory, include_tests=False):
    """Hash content and relative paths, not timestamps or a possibly dirty HEAD."""
    return capture_sources(directory, include_tests).digest


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _module_name(path, root, root_is_package=None):
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[0] in {"src", "lib"} and len(parts) > 1:
        parts.pop(0)
    # Scanning an import package directly is supported as well as a repo root.
    elif root_is_package if root_is_package is not None else (root / "__init__.py").is_file():
        parts.insert(0, root.name)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class PythonGraph(dict):
    def __init__(self):
        super().__init__()
        self.symbols = {}
        self.modules = {}
        self.bindings = {}
        self.calls = []
        self.diagnostics = []
        self._diagnostic_keys = set()
        self._parents_cache = None
        self._gaps_cache = None
        self.finalized = False
        self.roots = set()
        self.classes = set()
        self.data_symbols = set()
        self.property_getters = set()
        self.attribute_reads = []
        self.custom_metaclasses = set()
        self.bases = {}
        self.context_returns_self = set()
        self.aliases = {}
        self.ambiguous_symbols = set()
        self.edge_locations = {}
        self.possible_return_types = {}
        self.parameter_returns = {}
        self.dispatch_models = []
        self.callback_models = []
        self._strict_parents_cache = None

    def issue(self, reason, file="", line=0, caller=None, *, possible_targets=None):
        item = {"reason": reason, "file": file, "line": line, "caller": caller}
        if possible_targets is not None:
            item["possible_targets"] = sorted(set(possible_targets))
        key = (reason, file, line, caller, tuple(item.get("possible_targets", [])))
        if key not in self._diagnostic_keys:
            self._diagnostic_keys.add(key)
            self.diagnostics.append(item)

    def resolve(self, name):
        """Resolve explicit re-exports without collapsing same-named symbols."""
        seen = set()
        applied = set()
        while name and name not in seen:
            seen.add(name)
            if name in self.symbols:
                return name
            owner, _, method = name.rpartition(".")
            if owner in self.classes:
                for base in self.mro(owner)[1:]:
                    candidate = f"{base}.{method}"
                    if candidate in self.symbols:
                        return candidate
            replacement = self.aliases.get(name)
            alias_key = name if replacement else None
            if replacement is None:
                parts = name.split(".")
                for size in range(len(parts) - 1, 0, -1):
                    prefix = ".".join(parts[:size])
                    if prefix in self.aliases:
                        replacement = self.aliases[prefix] + "." + ".".join(parts[size:])
                        alias_key = prefix
                        break
            if not replacement or replacement == name:
                return name
            if alias_key in applied or len(applied) >= 128:
                self.issue("cyclic_alias")
                return None
            applied.add(alias_key)
            name = replacement
        if name:
            self.issue("cyclic_alias")
        return None

    def mro(self, name, visiting=()):
        """C3 linearization for statically known class bases."""
        if name in visiting:
            self.issue("unresolved_class_hierarchy")
            return [name]
        bases = self.bases.get(name, [])
        sequences = [self.mro(base, (*visiting, name))[:] for base in bases] + [bases[:]]
        order = [name]
        while any(sequences):
            sequences = [seq for seq in sequences if seq]
            candidate = next((seq[0] for seq in sequences if not any(seq[0] in other[1:] for other in sequences)), None)
            if candidate is None:
                self.issue("unresolved_class_hierarchy")
                break
            order.append(candidate)
            for seq in sequences:
                if seq[0] == candidate:
                    seq.pop(0)
        return order

    def link(self):
        for name in self.symbols:
            self.setdefault(name, set())
        for call in self.calls:
            target = self.resolve(call["target"])
            call["resolved"] = target
            if target in self.property_getters and call.get("edge_kind") != "property_getter_access":
                self.issue("property_result_call", call["file"], call["line"], call["caller"])
                continue
            if target in self.ambiguous_symbols or call["caller"] in self.ambiguous_symbols:
                self.issue("ambiguous_call_identity", call["file"], call["line"], call["caller"])
                continue
            if target in self.classes:
                # Include the class in the reachable set so unknown bases and
                # metaclasses cannot disappear from negative-result diagnostics.
                self.setdefault(call["caller"], set()).add(target)
                self.edge_locations.setdefault((call["caller"], target), call)
                # Instantiation may invoke both allocation and initialization.
                for method in ("__new__", "__init__"):
                    init = self.resolve(f"{target}.{method}")
                    if init in self.symbols:
                        self.setdefault(call["caller"], set()).add(init)
                        self.edge_locations.setdefault((call["caller"], init), call)
                continue
            if target:
                self.setdefault(call["caller"], set()).add(target)
                self.edge_locations.setdefault((call["caller"], target), call)

    def root_parents(self, include_speculative=True):
        cached = self._parents_cache if include_speculative else self._strict_parents_cache
        if self.finalized and cached is not None:
            return cached
        parents = {root: None for root in sorted(self.roots)}
        queue = deque(parents)
        while queue:
            node = queue.popleft()
            for child in sorted(self.get(node, ())):
                edge = self.edge_locations.get((node, child), {})
                if not include_speculative and edge.get("edge_kind") == "passed_callable_may_be_invoked":
                    continue
                if child not in parents:
                    parents[child] = node
                    queue.append(child)
        if self.finalized:
            if include_speculative:
                self._parents_cache = parents
            else:
                self._strict_parents_cache = parents
        return parents

    def path(self, targets, *, include_speculative=True):
        targets = set(targets)
        parents = self.root_parents(include_speculative=include_speculative)
        node = next((name for name in parents if name in targets), None)
        chain = []
        while node is not None:
            chain.append(node)
            node = parents[node]
        return list(reversed(chain))

    def evidence(self, chain):
        evidence = []
        for index, symbol in enumerate(chain):
            location = self.symbols.get(symbol, {})
            item = {"symbol": symbol, "file": location.get("file"), "line": location.get("line")}
            if index + 1 < len(chain):
                next_symbol = chain[index + 1]
                call = self.edge_locations.get((symbol, next_symbol))
                if call:
                    item["call_line"] = call["line"]
                    item["file"] = call["file"]
                    item["edge_kind"] = call.get("edge_kind", "static_call")
                    if call.get("callback_evidence"):
                        item["callback_evidence"] = call["callback_evidence"]
            evidence.append(item)
        return evidence

    def _bounded_gap_affects(self, diagnostic, targets, visiting=()):
        candidates = diagnostic.get("possible_targets")
        if candidates is None:
            return True
        identity = (diagnostic["reason"], diagnostic["file"], diagnostic["line"], diagnostic["caller"])
        if identity in visiting:
            return True
        reached, pending = set(), list(candidates)
        while pending:
            node = pending.pop()
            if node in reached:
                continue
            reached.add(node)
            if node in targets:
                return True
            if node not in self.symbols or node in self.ambiguous_symbols:
                return True
            pending.extend(self.get(node, ()))
        # A candidate with unknown behavior can still call an unrelated target.
        # A missing edge must never be used as proof of separation.
        for other in self.diagnostics:
            if other["caller"] is None or other["caller"] in reached:
                if self._bounded_gap_affects(other, targets, (*visiting, identity)):
                    return True
        return False

    def gaps(self, targets=None):
        if targets is not None:
            targets = set(targets)
            reachable = self.root_parents()
            gaps = {d["reason"] for d in self.diagnostics
                    if (d["caller"] is None or d["caller"] in reachable)
                    and self._bounded_gap_affects(d, targets)}
            for call in self.calls:
                target = call.get("resolved")
                if call["caller"] in reachable and target and target not in self.symbols and target not in self.classes:
                    gaps.add("unresolved_external_calls")
            return sorted(gaps)
        if self.finalized and self._gaps_cache is not None:
            return list(self._gaps_cache)
        reachable = self.root_parents()
        gaps = {d["reason"] for d in self.diagnostics if d["caller"] is None or d["caller"] in reachable}
        for call in self.calls:
            target = call.get("resolved")
            if call["caller"] in reachable and target and target not in self.symbols and target not in self.classes:
                gaps.add("unresolved_external_calls")
        answer = sorted(gaps)
        if self.finalized:
            self._gaps_cache = tuple(answer)
        return answer


class _Definitions(ast.NodeVisitor):
    def __init__(self, graph, module, file):
        self.graph, self.module, self.file = graph, module, file
        self.scope = module
        self.assigned_names = set()

    def define(self, node, kind):
        name = f"{self.scope}.{node.name}"
        if name in self.graph.symbols:
            self.graph.issue("duplicate_definition", self.file, node.lineno, name)
            self.graph.ambiguous_symbols.add(name)
        self.graph.symbols[name] = {"file": self.file, "line": node.lineno,
                                    "end_line": node.end_lineno, "column": node.col_offset,
                                    "kind": kind, "module": self.module}
        previous = self.scope
        self.scope = name
        self.generic_visit(node)
        self.scope = previous
        return name

    def visit_Assign(self, node):
        owner = self.graph.symbols.get(self.scope, {})
        if self.scope == self.module or owner.get("kind") == "class":
            try:
                ast.literal_eval(node.value)
                literal = True
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                literal = False
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                symbol = f"{self.scope}.{target.id}"
                existing = self.graph.symbols.get(symbol)
                if existing or (literal and symbol in self.assigned_names):
                    self.graph.issue("duplicate_definition", self.file, node.lineno, f"{self.module}.<module>")
                    self.graph.ambiguous_symbols.add(symbol)
                self.assigned_names.add(symbol)
                if literal:
                    self.graph.symbols[symbol] = {"file": self.file, "line": node.lineno,
                        "end_line": node.end_lineno, "column": node.col_offset,
                        "kind": "data", "module": self.module}
                    self.graph.data_symbols.add(symbol)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            assignment = ast.Assign(targets=[node.target], value=node.value)
            ast.copy_location(assignment, node)
            self.visit_Assign(assignment)

    def visit_FunctionDef(self, node):
        if self.scope == self.module and node.name in {"__getattr__", "__dir__"}:
            self.graph.issue("dynamic_module_attributes", self.file, node.lineno, f"{self.module}.<module>")
        self.define(node, "function")
        if node.name == "__enter__" and node.args.args:
            returns = [n for n in node.body if isinstance(n, ast.Return)]
            if len(node.body) == 1 and len(returns) == 1 and isinstance(returns[0].value, ast.Name) and returns[0].value.id == node.args.args[0].arg:
                self.graph.context_returns_self.add(self.scope)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        name = self.define(node, "class")
        self.graph.classes.add(name)
        if node.keywords:
            self.graph.custom_metaclasses.add(name)
        if node.bases or node.keywords:
            self.graph.issue("inheritance_or_metaclass", self.file, node.lineno, name)
        if any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and
               child.name.startswith("__") and child.name.endswith("__") and
               child.name not in {"__init__", "__enter__", "__exit__"} for child in node.body):
            self.graph.issue("implicit_object_protocol", self.file, node.lineno, name)


class _Bindings(ast.NodeVisitor):
    """Collect one lexical scope; do not leak aliases from sibling functions."""
    def __init__(self, module, scope, package):
        self.module, self.scope, self.package = module, scope, package
        self.names = {}

    def visit_Import(self, node):
        for alias in node.names:
            self.names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        module = node.module or ""
        if node.level:
            parts = self.package.split(".") if self.package else []
            if node.level > len(parts):
                module = "<invalid-relative-import>"
            else:
                module = ".".join(parts[:len(parts) - node.level + 1] + ([module] if module else []))
        for alias in node.names:
            if alias.name != "*":
                self.names[alias.asname or alias.name] = f"{module}.{alias.name}"

    def visit_FunctionDef(self, node):
        self.names[node.name] = f"{self.scope}.{node.name}"

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names[node.id] = None

    def visit_Lambda(self, node):
        pass


class _Calls(ast.NodeVisitor):
    def __init__(self, graph, module, tree, file, is_package):
        self.graph, self.module, self.file = graph, module, file
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        self.package = module if is_package else module.rpartition(".")[0]
        self.scope = module
        self.caller = f"{module}.<module>"
        self.class_name = None
        self.instances = set()
        collector = _Bindings(module, module, self.package)
        collector.visit(tree)
        self.env = collector.names
        for name, target in self.env.items():
            if target is None and f"{module}.{name}" in graph.data_symbols:
                self.env[name] = f"{module}.{name}"
        self.module_env = dict(self.env)
        for name, target in self.env.items():
            if target and target != f"{module}.{name}":
                graph.aliases[f"{module}.{name}"] = target

    def issue(self, reason, node):
        self.graph.issue(reason, self.file, node.lineno, self.caller)

    def resolve_expr(self, node):
        dotted = _dotted(node)
        if not dotted:
            if isinstance(node, ast.Call):
                from scripts.callback_analysis import returned_argument
                consumer = self.graph.resolve(self.resolve_expr(node.func))
                argument = returned_argument(self.graph, consumer, node)
                if argument is not None:
                    target = self.graph.resolve(self.resolve_expr(argument))
                    # Classes, descriptors and callable objects have different
                    # invocation semantics; retain unknown for those values.
                    if (self.graph.symbols.get(target, {}).get("kind") == "function"
                            and target not in self.graph.property_getters
                            and target not in self.graph.ambiguous_symbols):
                        return target
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.func.id not in self.env and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                base = self.resolve_expr(node.args[0])
                if base:
                    return f"{base}.{node.args[1].value}"
            # Immediate construction followed by a method call: Client().send().
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
                base = self.resolve_expr(node.value.func)
                return f"{base}.{node.attr}" if self.graph.resolve(base) in self.graph.classes else None
            return None
        first, *rest = dotted.split(".")
        base = self.env.get(first)
        return ".".join([base] + rest) if base else None

    def _read_data(self, node):
        target = self.graph.resolve(self.resolve_expr(node))
        if target in self.graph.data_symbols:
            self.graph.calls.append({"caller": self.caller, "target": target,
                "file": self.file, "line": node.lineno, "edge_kind": "data_reference"})

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._read_data(node)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Load):
            self._read_data(node)
            receiver = self.graph.resolve(self.resolve_expr(node.value))
            instance = isinstance(node.value, ast.Name) and node.value.id in self.instances
            if isinstance(node.value, ast.Call):
                receiver = self.graph.resolve(self.resolve_expr(node.value.func))
                instance = receiver in self.graph.classes
            if instance and receiver in self.graph.classes:
                self.graph.attribute_reads.append({"caller": self.caller,
                    "target": f"{receiver}.{node.attr}", "receiver": receiver,
                    "file": self.file, "line": node.lineno})
        self.generic_visit(node)

    def visit_Call(self, node):
        target = self.resolve_expr(node.func)
        if (isinstance(node.func, ast.Name) and node.func.id in self.instances
                and self.graph.resolve(target) in self.graph.classes):
            target = f"{target}.__call__"
        if target:
            self.graph.calls.append({"caller": self.caller, "target": target,
                                     "file": self.file, "line": node.lineno, "column": node.col_offset})
        elif isinstance(node.func, ast.Name) and node.func.id in vars(builtins) and node.func.id not in self.env:
            if node.func.id in DYNAMIC:
                self.issue("dynamic_dispatch", node)
            # Builtins can call Python protocols or callbacks; acknowledge that.
            elif node.func.id not in {"object", "isinstance", "issubclass", "id"}:
                self.issue("implicit_or_callback_dispatch", node)
        else:
            self.issue("unresolved_call", node)
        parent = self.parents.get(node)
        result_usage = ("discarded" if isinstance(parent, ast.Expr) else
                        "immediately_invoked" if isinstance(parent, ast.Call) and parent.func is node else
                        "unresolved")
        arguments = [(argument, index, None) for index, argument in enumerate(node.args)]
        arguments += [(kw.value, None, kw.arg) for kw in node.keywords]
        for argument, position, keyword in arguments:
            value = self.resolve_expr(argument)
            resolved_argument = self.graph.resolve(value) if value else None
            if isinstance(argument, ast.Lambda) or self.graph.symbols.get(resolved_argument, {}).get("kind") in {"function", "class"}:
                if resolved_argument in self.graph.classes:
                    is_instance = isinstance(argument, ast.Name) and argument.id in self.instances
                    callback = self.graph.resolve(f"{resolved_argument}.__call__" if is_instance else f"{resolved_argument}.__init__")
                else:
                    callback = resolved_argument
                if callback in self.graph.symbols and self.graph.symbols[callback]["kind"] == "function":
                    self.graph.calls.append({"caller": self.caller, "target": callback,
                                             "file": self.file, "line": node.lineno, "column": node.col_offset,
                                             "edge_kind": "passed_callable_may_be_invoked",
                                             "callback_consumer": target, "result_usage": result_usage,
                                             "argument_position": position,
                                             "argument_keyword": keyword,
                                             "binding_uncertain": any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords),
                                             "positional_count": len(node.args),
                                             "keyword_names": [kw.arg for kw in node.keywords]})
                else:
                    self.issue("callback_argument", node)
        self.generic_visit(node)

    def visit_Import(self, node):
        self._import(node)

    def visit_ImportFrom(self, node):
        if any(alias.name == "*" for alias in node.names):
            self.issue("star_import", node)
        self._import(node)

    def _import(self, node):
        bindings = _Bindings(self.module, self.scope, self.package)
        bindings.visit(node)
        self.env.update(bindings.names)
        # Imported module bodies execute even if no function is explicitly called.
        for target in bindings.names.values():
            resolved = self.graph.resolve(target)
            if resolved in self.graph.data_symbols:
                self.graph.calls.append({"caller": self.caller, "target": resolved,
                    "file": self.file, "line": node.lineno, "edge_kind": "data_reference"})
            parts = target.split(".")
            for size in range(1, len(parts) + 1):
                name = ".".join(parts[:size])
                self.graph.calls.append({"caller": self.caller, "target": f"{name}.<module>",
                                         "file": self.file, "line": node.lineno, "import": True})

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.resolve_expr(node.value)
        if isinstance(node.value, ast.Call):
            candidate = self.resolve_expr(node.value.func)
            # Only known classes have a known result type; functions may return anything.
            resolved = self.graph.resolve(candidate)
            value = value or (candidate if resolved in self.graph.classes else self.graph.possible_return_types.get(resolved))
            if resolved in self.graph.possible_return_types:
                self.issue("possible_return_type_dispatch", node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = value
                if value and (isinstance(node.value, ast.Call) or isinstance(node.value, ast.Name) and node.value.id in self.instances):
                    self.instances.add(target.id)
                else:
                    self.instances.discard(target.id)
                if self.scope == self.module or self.scope in self.graph.classes:
                    qualified = f"{self.scope}.{target.id}"
                    if value is None and qualified in self.graph.data_symbols:
                        self.env[target.id] = qualified
                        if self.scope == self.module:
                            self.module_env[target.id] = qualified
                    if value:
                        self.graph.aliases[qualified] = value
                    else:
                        self.graph.aliases.pop(qualified, None)
                    if self.scope == self.module:
                        self.module_env[target.id] = self.env[target.id]
            else:
                self.issue("attribute_or_destructuring_assignment", node)

    def visit_AnnAssign(self, node):
        if node.value:
            fake = ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno)
            self.visit_Assign(fake)

    def visit_NamedExpr(self, node):
        self.visit_Assign(ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno))

    def visit_FunctionDef(self, node):
        builtin_property = (self.class_name == self.scope and len(node.decorator_list) == 1
                            and isinstance(node.decorator_list[0], ast.Name)
                            and node.decorator_list[0].id == "property" and "property" not in self.env)
        if builtin_property:
            self.graph.property_getters.add(f"{self.scope}.{node.name}")
        for decorator in node.decorator_list:
            if not builtin_property and not (isinstance(decorator, ast.Name) and decorator.id in {"staticmethod", "classmethod"}):
                self.issue("decorator_dispatch", node)
            self.visit(decorator)
        for default in [*node.args.defaults, *(v for v in node.args.kw_defaults if v is not None)]:
            self.visit(default)
        saved = self.scope, self.caller, self.env, self.class_name
        saved_instances = set(self.instances)
        self.scope = f"{self.scope}.{node.name}"
        self.caller = self.scope
        # Method lexical lookup skips the class namespace.
        base = self.module_env if self.class_name == saved[0] else self.env
        self.env = dict(base)
        collector = _Bindings(self.module, self.scope, self.package)
        for statement in node.body:
            collector.visit(statement)
        self.env.update(collector.names)
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg:
            args.append(node.args.vararg)
        if node.args.kwarg:
            args.append(node.args.kwarg)
        for arg in args:
            self.env[arg.arg] = None
            self.instances.discard(arg.arg)
        static = any(isinstance(decorator, ast.Name) and decorator.id == "staticmethod" for decorator in node.decorator_list)
        if self.class_name and args and args[0].arg in {"self", "cls"} and not static:
            self.env[args[0].arg] = self.class_name
            if args[0].arg == "self":
                self.instances.add("self")
        for statement in node.body:
            self.visit(statement)
        self.scope, self.caller, self.env, self.class_name = saved
        self.instances = saved_instances

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        bases = [self.graph.resolve(self.resolve_expr(base)) for base in node.bases]
        self.graph.bases[f"{self.scope}.{node.name}"] = [base for base in bases if base in self.graph.classes]
        saved = self.scope, self.caller, self.env, self.class_name
        saved_instances = set(self.instances)
        self.scope = f"{self.scope}.{node.name}"
        self.class_name = self.scope
        self.env = dict(self.env)
        for decorator in node.decorator_list:
            self.issue("decorator_dispatch", node)
            self.visit(decorator)
        for statement in node.body:
            self.visit(statement)
        self.scope, self.caller, self.env, self.class_name = saved
        self.instances = saved_instances

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            cls = self.graph.resolve(self.resolve_expr(item.context_expr.func)) if isinstance(item.context_expr, ast.Call) else None
            for method in ("__enter__", "__exit__"):
                if cls in self.graph.classes:
                    self.graph.calls.append({"caller": self.caller, "target": f"{cls}.{method}", "file": self.file, "line": node.lineno})
            if isinstance(item.optional_vars, ast.Name):
                if cls in self.graph.context_returns_self:
                    self.env[item.optional_vars.id] = cls
                else:
                    self.env[item.optional_vars.id] = None
                    self.issue("unknown_context_manager_result", node)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node):
        self.issue("async_context_manager", node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self.issue("augmented_assignment_dispatch", node)
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.env[node.target.id] = None

    def visit_Delete(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = None
        self.issue("deleted_binding", node)

    def visit_Match(self, node):
        self.issue("pattern_matching_dispatch", node)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        self.issue("comprehension_dispatch", node)
        saved = self.env
        self.env = dict(saved)
        for generator in node.generators:
            self.visit(generator.iter)
            for target in ast.walk(generator.target):
                if isinstance(target, ast.Name):
                    self.env[target.id] = None
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.env = saved

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_For(self, node):
        self.issue("iteration_protocol", node)
        # Loop variables must shadow imported aliases.
        for target in ast.walk(node.target):
            if isinstance(target, ast.Name):
                self.env[target.id] = None
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.issue("loop_control_flow", node)
        self.generic_visit(node)

    def visit_Try(self, node):
        self.issue("exception_control_flow", node)
        before = dict(self.env)
        outcomes = []
        for body in [node.body + node.orelse, *(handler.body for handler in node.handlers)]:
            self.env = dict(before)
            for statement in body:
                self.visit(statement)
            outcomes.append(dict(self.env))
        for key in set().union(*(set(outcome) for outcome in outcomes)):
            values = {outcome.get(key) for outcome in outcomes}
            self.env[key] = values.pop() if len(values) == 1 else None
        for statement in node.finalbody:
            self.visit(statement)

    def visit_Lambda(self, node):
        self.issue("lambda_dispatch", node)

    def visit_Global(self, node):
        self.issue("global_mutation", node)

    def visit_Nonlocal(self, node):
        self.issue("nonlocal_binding", node)

    def visit_If(self, node):
        self.visit(node.test)
        before = dict(self.env)
        for statement in node.body:
            self.visit(statement)
        body = dict(self.env)
        self.env = dict(before)
        for statement in node.orelse:
            self.visit(statement)
        for key in set(body) | set(self.env):
            if body.get(key) != self.env.get(key):
                self.env[key] = None
                self.issue("conditional_binding", node)


def build_python_graph(directory, *, dependency_sources=(), include_tests=False, source_snapshots=None):
    graph = PythonGraph()
    inputs = [(Path(directory).resolve(), True), *((Path(p).resolve(), False) for p in dependency_sources)]
    if source_snapshots is None:
        source_snapshots = tuple(capture_sources(root, include_tests if first_party else False)
                                 for root, first_party in inputs)
    if len(source_snapshots) != len(inputs) or any(
            snapshot.root != root or snapshot.include_tests != (include_tests if first_party else False)
            for snapshot, (root, first_party) in zip(source_snapshots, inputs)):
        raise ValueError("Source snapshots do not match graph inputs")
    parsed = []
    for (root, first_party), snapshot in zip(inputs, source_snapshots):
        for path, raw in snapshot.files:
            # Packaging entrypoints are not installed import modules. Including
            # setup.py from every sdist creates an artificial global collision.
            if not first_party and path.relative_to(root).as_posix() == "setup.py":
                continue
            module = _module_name(path, root, snapshot.root_is_package)
            if not module:
                graph.issue("unresolved_module", str(path))
                continue
            if module in graph.modules:
                graph.issue("duplicate_module", str(path), caller=f"{module}.<module>")
                graph.ambiguous_symbols.update(name for name, meta in graph.symbols.items() if meta["module"] == module)
                continue
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                with io.TextIOWrapper(io.BytesIO(raw), encoding=encoding) as stream:
                    source = stream.read()
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as exc:
                graph.issue("parse_error", str(path), getattr(exc, "lineno", 0), None if first_party else f"{module}.<module>")
                continue
            graph.modules[module] = {"file": str(path), "source": source, "root": str(root), "first_party": first_party}
            graph.symbols[f"{module}.<module>"] = {"file": str(path), "line": 1, "kind": "module", "module": module}
            _Definitions(graph, module, str(path)).visit(tree)
            parsed.append((module, tree, str(path), path.name == "__init__.py"))
    if not graph.modules:
        graph.issue("no_python_sources")
    # Definitions from every dependency exist before resolving instance assignments.
    visitors = [(tree, _Calls(graph, module, tree, file, is_package)) for module, tree, file, is_package in parsed]
    from scripts.return_types import infer_return_types
    graph.possible_return_types, graph.dispatch_models = infer_return_types(graph, visitors)
    from scripts.callback_analysis import infer_parameter_returns
    graph.parameter_returns = infer_parameter_returns(graph, parsed)
    for tree, visitor in visitors:
        visitor.visit(tree)
    # Drop import candidates which are attributes, but flag truly missing modules.
    graph.calls = [c for c in graph.calls if not c.get("import") or
                   c["target"] in graph.symbols or
                   c["target"].split(".")[0] not in {m.split(".")[0] for m in graph.modules}]
    for name, info in graph.symbols.items():
        if info["kind"] != "class" and graph.modules[info["module"]]["first_party"]:
            if name not in graph.ambiguous_symbols:
                graph.roots.add(name)
    # All class bases and decorators are now known, including dependencies
    # visited after the application that reads an inherited descriptor.
    for read in graph.attribute_reads:
        target = graph.resolve(read["target"])
        if target not in graph.property_getters:
            continue
        hierarchy = graph.mro(read["receiver"])
        if any(cls in graph.custom_metaclasses or f"{cls}.__getattribute__" in graph.symbols
               or f"{cls}.__new__" in graph.symbols for cls in hierarchy):
            graph.issue("custom_descriptor_dispatch", read["file"], read["line"], read["caller"])
            continue
        graph.calls.append({**read, "target": target, "edge_kind": "property_getter_access"})
        # Reading the getter is modeled; the returned value's type/callability
        # is not automatically the getter function itself.
        graph.issue("property_result_type_unknown", read["file"], read["line"], read["caller"])
    from scripts.callback_analysis import resolve_callbacks
    resolve_callbacks(graph, parsed)
    # An ordinary call is stronger evidence than a speculative callback edge
    # for the same pair. Preserve it regardless of traversal order.
    graph.calls.sort(key=lambda call: call.get("edge_kind") == "passed_callable_may_be_invoked")
    graph.link()
    from scripts.callback_analysis import scope_parameter_calls
    scope_parameter_calls(graph, parsed)
    graph.finalized = True
    return graph
