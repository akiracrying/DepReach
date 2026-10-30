"""Resolve lexical identity of direct CommonJS require candidates.

This establishes a wrapper binding, not module execution, exported values or a
call path. Hoisting is collected before references are answered. The same tree
and captured bytes as the syntax audit are used; target code is never executed.
"""
from dataclasses import dataclass, field

from scripts.javascript_syntax import FUNCTIONS, MAX_NODES, _identifier_text, _span, _text

WRAPPER_NAMES = {"require", "module", "exports", "__dirname", "__filename"}
BLOCKS = {"statement_block", "switch_body", "for_statement", "for_in_statement", "catch_clause"}


def _pattern_names(node):
    """Binding/assignment positions only; keys and default expressions aren't names."""
    stack = [node] if node is not None else []
    while stack:
        value = stack.pop()
        if value.type in {"identifier", "shorthand_property_identifier_pattern", "shorthand_property_identifier", "type_identifier"}:
            yield value
        elif value.type in {"pair_pattern", "pair"}:
            child = value.child_by_field_name("value")
            if child is not None: stack.append(child)
        elif value.type in {"assignment_pattern", "object_assignment_pattern"}:
            child = value.child_by_field_name("left")
            if child is not None: stack.append(child)
        elif value.type in {"required_parameter", "optional_parameter"}:
            child = value.child_by_field_name("pattern") or value.child_by_field_name("name")
            if child is not None: stack.append(child)
        elif value.type in {"object_pattern", "array_pattern", "formal_parameters", "rest_pattern"}:
            stack.extend(reversed(value.named_children))


@dataclass
class Scope:
    parent: object
    kind: str
    start: int
    bindings: dict = field(default_factory=dict)
    dynamic: bool = False
    arrow: bool = False


class JavaScriptBindings:
    def __init__(self, syntax, facts=None):
        self.syntax = syntax
        self.facts = facts if facts is not None else syntax.facts()
        self.root = Scope(None, "module", 0)
        self.node_scopes = {}
        self.nodes = {}
        self.writes = []
        self.wrapper_writes = set()
        self.dynamic_reasons = set()
        self.annex_b_names = set()
        self.esm_syntax = False
        self.ambiguous_for_await = False
        self.root_lexical_wrapper_names = set()
        self.complete = self.facts["parse_complete"]
        if not self.complete or syntax.tree is None: return
        self._collect()
        if self.complete: self._collect_writes()

    def _name(self, node):
        return _identifier_text(node, self.syntax.raw) or _text(node, self.syntax.raw)

    def _declare(self, scope, node, kind, initialized=False):
        if node is None: return
        for name in _pattern_names(node):
            text = self._name(name)
            scope.bindings.setdefault(text, []).append({"name": text, "kind": kind,
                "initialized": initialized, **_span(name)})
            if scope is self.root and text in WRAPPER_NAMES and kind in {"lexical", "class", "import"}:
                self.root_lexical_wrapper_names.add(text)

    @staticmethod
    def _var_scope(scope):
        while scope.parent is not None and scope.kind not in {"function_body", "parameters", "static_block"}:
            scope = scope.parent
        return scope

    @staticmethod
    def _lookup(scope, name):
        while scope is not None:
            if name in scope.bindings: return scope, scope.bindings[name]
            scope = scope.parent
        return None, []

    @staticmethod
    def _in_function(scope):
        while scope is not None:
            if scope.kind == "parameters": return True
            scope = scope.parent
        return False

    @staticmethod
    def _wrapper_arguments(scope):
        while scope is not None:
            if scope.kind == "parameters" and not scope.arrow: return False
            if "arguments" in scope.bindings:
                if scope.parent is not None or any(d["kind"] != "var" for d in scope.bindings["arguments"]):
                    return False
            scope = scope.parent
        return True

    def _collect(self):
        stack = [(self.syntax.tree.root_node, self.root)]
        count = 0
        while stack:
            node, scope = stack.pop()
            count += 1
            if count > MAX_NODES:
                self.complete = False
                return
            self.nodes[node.start_byte, node.end_byte, node.type] = node
            parent = node.parent
            is_function = node.type in FUNCTIONS
            if is_function:
                name = node.child_by_field_name("name")
                if node.type in {"function_declaration", "generator_function_declaration"}:
                    self._declare(scope, name, "function", True)
                    if scope.kind not in {"module", "function_body"} and name is not None:
                        # Annex B may additionally create a binding outside this block.
                        # Do not assume branch execution or a particular strictness mode.
                        self.annex_b_names.add((id(self._var_scope(scope)), self._name(name)))
                parameter_scope = Scope(scope, "parameters", node.start_byte, arrow=node.type == "arrow_function")
                if node.type in {"function_expression", "generator_function"}:
                    self._declare(parameter_scope, name, "function_name", True)
                parameters = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
                self._declare(parameter_scope, parameters, "parameter", True)
                self.node_scopes[node.id] = parameter_scope
                body = node.child_by_field_name("body")
                for child in reversed(node.named_children):
                    if body is not None and child.id == body.id and body.type == "statement_block":
                        child_scope = Scope(parameter_scope, "function_body", body.start_byte)
                    else: child_scope = parameter_scope
                    stack.append((child, child_scope))
                continue
            if node.type == "class_static_block":
                scope = Scope(scope, "static_block", node.start_byte)
            elif node.type in BLOCKS and not (node.type == "statement_block" and scope.kind == "function_body" and scope.start == node.start_byte):
                scope = Scope(scope, node.type, node.start_byte)
            elif node.type in {"class", "class_declaration"}:
                name = node.child_by_field_name("name")
                if node.type == "class_declaration": self._declare(scope, name, "class", True)
                scope = Scope(scope, "class", node.start_byte)
                self._declare(scope, name, "class_name", True)
            self.node_scopes[node.id] = scope
            if node.type == "with_statement":
                # A with environment also affects functions closed over its body.
                # The object expression itself is conservatively included.
                scope = Scope(scope, "with", node.start_byte, dynamic=True)
                self.node_scopes[node.id] = scope
            if node.type == "catch_clause":
                self._declare(scope, node.child_by_field_name("parameter"), "catch", True)
            elif node.type == "variable_declarator":
                kind = "var" if parent.type == "variable_declaration" else "lexical"
                target = self._var_scope(scope) if kind == "var" else scope
                self._declare(target, node.child_by_field_name("name"), kind, node.child_by_field_name("value") is not None)
            elif node.type == "for_in_statement":
                kind = node.child_by_field_name("kind")
                left = node.child_by_field_name("left")
                if kind is not None:
                    declaration_kind = "var" if self._name(kind) == "var" else "lexical"
                    self._declare(self._var_scope(scope) if declaration_kind == "var" else scope, left, declaration_kind, True)
                else: self.writes.append((scope, left))
            elif node.type == "import_statement":
                for clause in node.named_children:
                    if clause.type != "import_clause": continue
                    for part in clause.named_children:
                        if part.type == "identifier": self._declare(scope, part, "import", True)
                        elif part.type == "namespace_import":
                            for name in part.named_children:
                                if name.type == "identifier": self._declare(scope, name, "import", True)
                        elif part.type == "named_imports":
                            for spec in part.named_children:
                                if spec.type == "import_specifier":
                                    self._declare(scope, spec.child_by_field_name("alias") or spec.child_by_field_name("name"), "import", True)
                self.esm_syntax = True
            elif node.type == "export_statement": self.esm_syntax = True
            elif node.type == "meta_property" and self._name(node) == "import.meta": self.esm_syntax = True
            elif node.type == "await_expression" and not self._in_function(scope): self.esm_syntax = True
            if node.type == "for_in_statement" and any(c.type == "await" for c in node.children) and not self._in_function(scope):
                self.esm_syntax = True
                self.ambiguous_for_await = True
            if node.type in {"assignment_expression", "augmented_assignment_expression"}:
                self.writes.append((scope, node.child_by_field_name("left")))
            elif node.type == "update_expression": self.writes.append((scope, node.child_by_field_name("argument")))
            if node.type == "call_expression":
                target = node.child_by_field_name("function")
                # Parentheses preserve direct eval. Anything else (e.g. comma)
                # is indirect eval and cannot replace the wrapper's locals.
                while target is not None and target.type == "parenthesized_expression" and len(target.named_children) == 1:
                    target = target.named_children[0]
                if target is not None and target.type == "identifier" and self._name(target) == "eval":
                    self.dynamic_reasons.add("direct_eval_may_change_bindings")
            stack.extend((child, scope) for child in reversed(node.named_children))
        # Delayed until every declaration has been seen, including hoisted ones.
        for node in self.nodes.values():
            if node.type == "identifier" and self._name(node) == "arguments" and self._wrapper_arguments(self.node_scopes[node.id]):
                self.dynamic_reasons.add("commonjs_wrapper_arguments_exposed")

    def _collect_writes(self):
        for scope, target in self.writes:
            for name in _pattern_names(target):
                text = self._name(name)
                owner, declarations = self._lookup(scope, text)
                if owner is None or owner is self.root:
                    self.wrapper_writes.add(text)

    def module_profile(self, module_format):
        if not self.complete: return "unsupported", "importer_syntax_or_binding_incomplete"
        if not self.facts["runtime_source"]: return "unsupported", "declaration_file_has_no_runtime_loader"
        if self.facts["language"] != "javascript" or self.syntax.file.endswith(".jsx"):
            return "unsupported", "compiler_or_typescript_runtime_profile_not_modeled"
        if module_format == "javascript_auto":
            if self.ambiguous_for_await:
                return "unsupported", "ambiguous_for_await_requires_runtime_check"
            return ("esm", "detected_esm_syntax") if self.esm_syntax or self.root_lexical_wrapper_names else ("commonjs", "default_commonjs_syntax")
        if module_format == "commonjs" and (self.esm_syntax or self.root_lexical_wrapper_names):
            return "unsupported", "syntax_conflicts_with_commonjs_wrapper"
        if module_format in {"commonjs", "esm"}: return module_format, "explicit_module_format"
        return "unsupported", "module_format_not_modeled"

    def commonjs_reference(self, reference, module_format):
        profile, profile_reason = self.module_profile(module_format)
        result = {"status": "unresolved_commonjs_binding", "binding_scope": "direct_require_identifier_only",
                  "module_profile": profile, "module_profile_reason": profile_reason, "resolution_is_invocation": False}
        node = self.nodes.get((reference["start_byte"], reference["end_byte"], "call_expression"))
        if profile == "unsupported" or node is None:
            return {**result, "reason": profile_reason if node is not None else "binding_node_unavailable"}
        scope = self.node_scopes[node.id]
        cursor = scope
        while cursor is not None:
            if cursor.dynamic: return {**result, "reason": "with_environment_may_shadow_require"}
            cursor = cursor.parent
        owner, declarations = self._lookup(scope, "require")
        wrapper_var = owner is self.root and all(d["kind"] == "var" and not d["initialized"] for d in declarations)
        if declarations and not (profile == "commonjs" and wrapper_var):
            return {**result, "status": "shadowed_commonjs_identifier", "reason": "lexical_require_declaration",
                    "declarations": declarations[:8], "omitted_declarations": max(0, len(declarations) - 8),
                    "scope_kind": owner.kind, "scope_start_byte": owner.start}
        if profile != "commonjs": return {**result, "reason": "require_not_a_node_esm_binding"}
        cursor = scope
        while cursor is not None:
            if cursor.dynamic: return {**result, "reason": "with_environment_may_shadow_require"}
            if (id(cursor), "require") in self.annex_b_names:
                return {**result, "reason": "annex_b_function_may_replace_require"}
            cursor = cursor.parent
        if self.dynamic_reasons: return {**result, "reason": sorted(self.dynamic_reasons)[0]}
        if "require" in self.wrapper_writes: return {**result, "reason": "commonjs_require_may_be_reassigned"}
        return {**result, "status": "verified_commonjs_wrapper", "reason": "unshadowed_unwritten_commonjs_require"}
