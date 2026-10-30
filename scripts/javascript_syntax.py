"""Capture JS/JSX/TS/TSX syntax without executing target code.

Syntax facts are not resolved call edges: require/exports may be shadowed,
imports may have conditions, and callbacks still require dataflow. Byte spans
refer to the exact captured bytes and can be reused for fix-diff mapping.
"""
import hashlib
import importlib.metadata
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
FUNCTIONS = {"function_declaration", "generator_function_declaration", "function_expression", "generator_function", "arrow_function", "method_definition"}
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_NODES = 500000
MAX_TEXT_EXCERPT = 512


@lru_cache(maxsize=8)
def _language(suffix):
    try:
        from packaging.version import Version
        version = Version(importlib.metadata.version("tree-sitter"))
        if not Version("0.25.2") <= version < Version("0.26"):
            raise RuntimeError('JS/TS parsing requires tree-sitter>=0.25.2,<0.26; 0.26.0 crashes in Windows regression tests')
        from tree_sitter import Language
        import tree_sitter_javascript as javascript
        import tree_sitter_typescript as typescript
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise RuntimeError('JS/TS parsing requires the node extra: pip install ".[node]"') from exc
    if suffix == ".tsx":
        grammar, language = typescript.language_tsx(), "tsx"
    elif suffix in {".ts", ".mts", ".cts"}:
        grammar, language = typescript.language_typescript(), "typescript"
    else:
        grammar, language = javascript.language(), "javascript"
    return Language(grammar), language


def _parser(suffix):
    grammar, language = _language(suffix)
    from tree_sitter import Parser
    return Parser(grammar), language


def _text(node, raw):
    return raw[node.start_byte:node.end_byte].decode("utf-8") if node is not None else None


def _display(node, raw, field):
    text = _text(node, raw)
    value = {field: text[:MAX_TEXT_EXCERPT] if text is not None else None}
    if text is not None and len(text) > MAX_TEXT_EXCERPT:
        value[field + "_truncated"] = True
    return value


def _span(node):
    return {"start_byte": node.start_byte, "end_byte": node.end_byte,
            "line": node.start_point.row + 1, "column": node.start_point.column,
            "end_line": node.end_point.row + 1, "end_column": node.end_point.column}


def _literal(node, raw):
    if node is None or node.type != "string":
        return None
    value = _text(node, raw)
    # Non-escaped literals are unambiguous in both quote forms. Escaped
    # specifiers require JS string decoding, not Python's string rules.
    return value[1:-1] if "\\" not in value else None


def _dotted(node, raw):
    if node is None:
        return None
    if node.type in {"identifier", "property_identifier"}:
        return _text(node, raw)
    if node.type == "member_expression":
        base = _dotted(node.child_by_field_name("object"), raw)
        prop = node.child_by_field_name("property")
        if base and prop is not None and prop.type == "property_identifier":
            return base + "." + _text(prop, raw)
    return None


def _function_name(node, raw):
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(name, raw)
    parent = node.parent
    if parent is not None:
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
        elif parent.type == "pair":
            name = parent.child_by_field_name("key")
        elif parent.type == "assignment_expression":
            name = parent.child_by_field_name("left")
        elif parent.type == "export_statement":
            return "<default>"
    return _text(name, raw) if name is not None else f"<anonymous@{node.start_point.row + 1}:{node.start_point.column}>"


@dataclass
class JavaScriptSyntax:
    file: str
    raw: bytes
    language: str
    tree: object
    issues: list
    parser: object = None

    def facts(self):
        functions, calls, imports, exports, bindings = [], [], [], [], []
        issues = list(self.issues)
        stack = [(self.tree.root_node, "<module>", "")] if self.tree is not None else []
        count = 0
        while stack:
            node, owner, prefix = stack.pop()
            count += 1
            if count > MAX_NODES:
                issues.append({"reason": "syntax_node_limit"})
                break
            if node.type == "ERROR" or node.is_missing:
                issues.append({"reason": "syntax_error", "node_type": node.type, **_span(node)})
            child_owner, child_prefix = owner, prefix
            if node.type in {"class_declaration", "class"}:
                name = node.child_by_field_name("name")
                child_prefix = prefix + (_text(name, self.raw) or f"<class@{node.start_byte}>") + "."
            if node.type in FUNCTIONS:
                name = prefix + _function_name(node, self.raw)
                symbol = f"{name}@{node.start_byte}"
                functions.append({"symbol": symbol, "qualified_name": name, "owner": owner,
                                  "kind": node.type, "source_sha256": hashlib.sha256(self.raw[node.start_byte:node.end_byte]).hexdigest(),
                                  **_display(node.child_by_field_name("parameters") or node.child_by_field_name("parameter"), self.raw, "parameters"),
                                  **_span(node)})
                child_owner, child_prefix = symbol, name + "."
            if node.type in {"call_expression", "new_expression"}:
                target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
                arguments = node.child_by_field_name("arguments")
                calls.append({"owner": owner, "kind": node.type, **_display(target, self.raw, "target_text"),
                              "target_name": _dotted(target, self.raw), "target_kind": target.type if target else None,
                              "target_span": _span(target) if target else None,
                              "arguments": [{"kind": arg.type, **_display(arg, self.raw, "text"), **_span(arg)}
                                            for arg in arguments.named_children] if arguments else [],
                              "resolution": "not_resolved", **_span(node)})
                if target is not None and (target.type == "import" or _dotted(target, self.raw) == "require"):
                    args = arguments.named_children if arguments else []
                    literal = _literal(args[0], self.raw) if len(args) == 1 else None
                    imports.append({"owner": owner, "kind": "dynamic_import" if target.type == "import" else "commonjs_candidate",
                                    "specifier": literal, "specifier_resolved": literal is not None,
                                    "requires_binding_resolution": target.type != "import", **_span(node)})
            if node.type == "import_statement":
                source = node.child_by_field_name("source")
                imports.append({"owner": owner, "kind": "esm", "specifier": _literal(source, self.raw),
                                **_display(node, self.raw, "statement"), "type_only": any(c.type == "type" for c in node.children), **_span(node)})
            if node.type == "export_statement":
                exports.append({"owner": owner, "kind": "esm", **_display(node, self.raw, "statement"),
                                "source": _literal(node.child_by_field_name("source"), self.raw),
                                "has_source": node.child_by_field_name("source") is not None,
                                "type_only": any(c.type == "type" for c in node.children), **_span(node)})
            if node.type in {"variable_declarator", "assignment_expression"}:
                left = node.child_by_field_name("name") if node.type == "variable_declarator" else node.child_by_field_name("left")
                right = node.child_by_field_name("value") if node.type == "variable_declarator" else node.child_by_field_name("right")
                bindings.append({"owner": owner, "kind": node.type, "name": _text(left, self.raw),
                                 "value_kind": right.type if right else None, "value_span": _span(right) if right else None, **_span(node)})
                dotted = _dotted(left, self.raw)
                if dotted and (dotted == "module.exports" or dotted.startswith(("module.exports.", "exports."))):
                    exports.append({"owner": owner, "kind": "commonjs_candidate", "target": dotted,
                                    "requires_binding_resolution": True, **_span(node)})
            stack.extend((child, child_owner, child_prefix) for child in reversed(node.children))
        # ERROR may wrap a large malformed subtree; never call a partially
        # recovered parse complete even if individual functions were recovered.
        if self.tree is not None and self.tree.root_node.has_error and not issues:
            issues.append({"reason": "syntax_error"})
        return {"file": self.file, "language": self.language, "source_sha256": hashlib.sha256(self.raw).hexdigest(),
                "source_bytes": len(self.raw), "nodes_visited": count, "parse_complete": not issues,
                "runtime_source": not self.file.endswith((".d.ts", ".d.mts", ".d.cts")),
                "functions": functions, "calls": calls, "imports": imports, "exports": exports,
                "bindings": bindings, "issues": issues, "call_resolution": "not_performed",
                "text_excerpt_limit": MAX_TEXT_EXCERPT}


def parse_javascript(file, raw=None):
    path = Path(file)
    if path.suffix.lower() not in EXTENSIONS:
        raise ValueError(f"Unsupported JavaScript/TypeScript extension: {path.suffix}")
    raw = path.read_bytes() if raw is None else raw
    parser, language = _parser(path.suffix.lower())
    if len(raw) > MAX_SOURCE_BYTES:
        return JavaScriptSyntax(str(path), raw, language, None, [{"reason": "source_size_limit"}])
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return JavaScriptSyntax(str(path), raw, language, None, [{"reason": "source_encoding_unsupported"}])
    return JavaScriptSyntax(str(path), raw, language, parser.parse(raw), [], parser)


def javascript_files(root, include_tests=False, *, exclude_roots=()):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"JavaScript source directory does not exist: {root}")
    def walk_error(error):
        raise error
    excluded = tuple(Path(path).resolve() for path in exclude_roots)
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(name for name in dirs if name not in {"node_modules", "venv", "__pycache__"}
                         and not name.startswith(".") and (include_tests or name not in {"test", "tests", "examples", "docs"})
                         and not Path(directory, name).is_symlink()
                         and not any(Path(directory, name).resolve() == p or p in Path(directory, name).resolve().parents for p in excluded))
        for name in sorted(files):
            path = Path(directory, name)
            if path.suffix.lower() in EXTENSIONS and not path.is_symlink():
                if not include_tests and any(mark in name for mark in (".test.", ".spec.")):
                    continue
                yield path


def audit_javascript_sources(project, source_context, output_dir, *, include_tests=False, exclude_roots=()):
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    roots = {str(Path(project).resolve()): ["<application>"]}
    for source in source_context["sources"]:
        roots.setdefault(source["source"], []).append(source["location"])
    modules, issues = [], []
    for root, instances in sorted(roots.items()):
        for path in javascript_files(root, include_tests, exclude_roots=exclude_roots if Path(root).resolve() == Path(project).resolve() else ()):
            facts = parse_javascript(path).facts()
            key = hashlib.sha256(str(path).encode()).hexdigest()
            (destination / (key + ".json")).write_text(json.dumps(facts, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            modules.append({"file": str(path), "root": root, "instances": sorted(instances),
                            "facts": str(destination / (key + ".json")), "source_sha256": facts["source_sha256"],
                            "parse_complete": facts["parse_complete"], "functions": len(facts["functions"]),
                            "calls": len(facts["calls"]), "imports": len(facts["imports"])})
            issues.extend({"file": str(path), **issue} for issue in facts["issues"])
    summary = {"schema_version": 1, "parser_versions": {name: importlib.metadata.version(name) for name in
               ("tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript")},
               "sources_complete": source_context["complete"], "modules": modules, "issues": issues,
               "syntax_complete": not issues and bool(modules), "call_graph_implemented": False,
               "scope": {"include_tests": include_tests, "dependency_node_modules": "separate_locked_instances",
                         "excluded_application_roots": [str(Path(p).resolve()) for p in exclude_roots]},
               "counts": {"modules": len(modules), "functions": sum(m["functions"] for m in modules),
                          "calls": sum(m["calls"] for m in modules), "imports": sum(m["imports"] for m in modules)}}
    (destination / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
