"""Map a fix's old-side context to the exact dependency source being analyzed.

Line numbers from a newer commit are not assumed to match an installed version.
Exact old-side context is preferred. Otherwise verified fix-parent source
recovers a fully qualified function identity, explicitly recording whether its
body differs in the installed release. These are candidates, not proven sinks.
"""
import re
from pathlib import PurePosixPath

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_hunks(diff):
    from scripts.patch_changes import parse_patch_files
    for file in parse_patch_files(diff):
        yield from file["hunks"]


def map_patch(diff, graph, library_root, *, reference="", evidence=None):
    mappings, reasons = [], set()
    evidence = evidence if evidence is not None else []
    from scripts.patch_changes import parse_patch_files, change_kind
    files = parse_patch_files(diff)
    for record in files:
        file = record["old_file"] if record["old_file"] != "/dev/null" else record["new_file"]
        kind = change_kind(file, binary=record["binary"])
        if record["hunks"] and not record["binary"]:
            continue
        ignored = kind == "non_runtime_documentation_or_test"
        detail = {"reference": reference, "file": file, "new_file": record["new_file"],
                  "old_start": 0, "old_context": "", "changes": [], "change_kind": kind,
                  "analysis_support": "ignored" if ignored else "unsupported",
                  "outcome": "non_runtime_change" if ignored else "binary_or_metadata_only_change",
                  "metadata": record["metadata"]}
        evidence.append(detail)
        if not ignored:
            reasons.add("unsupported_binary_or_metadata_patch")
    for hunk in parse_hunks(diff):
        file = hunk["file"] or hunk["new_file"] or ""
        if file == "/dev/null":
            file = hunk["new_file"]
        parts = PurePosixPath(file).parts
        kind = change_kind(file)
        if kind == "non_runtime_documentation_or_test":
            continue
        detail = {"reference": reference, "file": file, "new_file": hunk["new_file"],
                  "old_start": hunk["old_start"], "change_kind": kind,
                  "old_context": "\n".join(hunk["old"]), "analysis_support": "unknown",
                  "changes": [{"old_offset": n, "kind": k, "text": t} for n, k, t in hunk["changed"]]}
        evidence.append(detail)
        if not hunk["valid"]:
            detail["outcome"] = "malformed_or_truncated_hunk"
            reasons.add("malformed_or_truncated_hunk")
            continue
        if kind != "python_source":
            detail["outcome"] = "non_python_patch_change"
            detail["analysis_support"] = "unsupported"
            reasons.add("non_python_patch_change")
            continue
        candidates = []
        for module, info in graph.modules.items():
            if info["root"] != str(library_root):
                continue
            relative = PurePosixPath(info["file"].replace("\\", "/")).relative_to(PurePosixPath(info["root"].replace("\\", "/")))
            source_parts = relative.parts
            normalized_patch = parts[1:] if parts and parts[0] in {"src", "lib"} else parts
            normalized_source = source_parts[1:] if source_parts and source_parts[0] in {"src", "lib"} else source_parts
            normalized_new = PurePosixPath(hunk["new_file"]).parts
            if normalized_new and normalized_new[0] in {"src", "lib"}:
                normalized_new = normalized_new[1:]
            if normalized_source in (normalized_patch, normalized_new):
                candidates.append((module, info))
        if len(candidates) != 1:
            detail["outcome"] = "patch_file_not_uniquely_matched"
            reasons.add("patch_file_not_uniquely_matched")
            continue
        module, info = candidates[0]
        lines = info["source"].splitlines()
        old = hunk["old"]
        offsets = [i for i in range(len(lines) - len(old) + 1) if old and lines[i:i + len(old)] == old]
        if len(offsets) != 1:
            recovered, failures = _map_from_parent(hunk, module, info, graph, reference, detail)
            mappings.extend(item for item in recovered if item not in mappings)
            reasons.update(failures)
            if not recovered:
                reasons.add("patch_context_not_uniquely_matched")
            continue
        detail["outcome"] = "exact_old_context"
        detail["analysis_support"] = "supported"
        detail["target_kinds"] = []
        offset = offsets[0]
        hunk_mappings = []
        outer_addition = False
        for changed, kind, text in sorted(set(hunk["changed"])):
            if not text.strip() or text.lstrip().startswith("#"):
                continue
            line = offset + changed + 1
            containing = [(symbol, meta) for symbol, meta in graph.symbols.items()
                          if meta["module"] == module and meta["kind"] in {"function", "data"} and
                          meta["line"] <= line <= meta["end_line"]]
            if not containing:
                if any(graph.symbols.get(name, {}).get("module") == module for name in graph.ambiguous_symbols):
                    detail["analysis_support"] = "unknown"
                    reasons.add("patch_target_ambiguous")
                    continue
                detail["analysis_support"] = "partial" if hunk_mappings else "unsupported"
                detail["change_kind"] = "python_module_or_class_code"
                reasons.add("patch_changes_module_or_class_code")
                continue
            containing.sort(key=lambda pair: pair[1]["end_line"] - pair[1]["line"])
            symbol, meta = containing[0]
            if meta["kind"] == "data" and kind == "added":
                import ast
                try:
                    statement = ast.parse(text.strip()).body[0]
                    names = statement.targets if isinstance(statement, ast.Assign) else [statement.target] if isinstance(statement, ast.AnnAssign) else []
                    same_binding = any(isinstance(name, ast.Name) and name.id == symbol.rsplit(".", 1)[-1] for name in names)
                except (SyntaxError, IndexError):
                    same_binding = len(text) - len(text.lstrip()) > meta["column"]
                if not same_binding:
                    detail["analysis_support"] = "partial"
                    reasons.add("patch_adds_definition_or_outer_scope_code")
                    outer_addition = True
                    continue
            if meta["kind"] == "function" and kind == "added" and len(text) - len(text.lstrip()) <= meta["column"]:
                reasons.add("patch_adds_definition_or_outer_scope_code")
                outer_addition = True
                continue
            mapping = {"symbol": symbol, "file": info["file"], "line": line,
                       "patch_file": file, "method": "exact_old_context",
                       "meaning": "patch_associated_data" if meta["kind"] == "data" else "patch_associated_function",
                       "target_kind": meta["kind"]}
            if meta["kind"] not in detail["target_kinds"]:
                detail["target_kinds"].append(meta["kind"])
            if mapping not in hunk_mappings:
                hunk_mappings.append(mapping)
        if hunk_mappings and detail["analysis_support"] == "unsupported":
            detail["analysis_support"] = "partial"
        # Do not assign a newly inserted function's body to the function that
        # happened to precede the insertion in old-side context.
        if not outer_addition or any(kind == "removed" for _, kind, _ in hunk["changed"]):
            mappings.extend(item for item in hunk_mappings if item not in mappings)
    if not mappings:
        reasons.add("no_mapped_patch_functions")
    return mappings, sorted(reasons)


def _map_from_parent(hunk, module, info, graph, reference, detail):
    """Recover qualified function identity from verified pre-fix source.

    This is an identity mapping, explicitly not a claim of body equivalence
    across versions. An unrelated same-name method is never substituted.
    """
    from scripts.patch_evidence import get_parent_source, function_spans
    parent = get_parent_source(reference, hunk["file"])
    if not parent:
        detail["outcome"] = "fix_parent_source_unavailable"
        return [], {"fix_parent_source_unavailable"}
    start = hunk["old_start"] - 1
    if parent["source"].splitlines()[start:start + len(hunk["old"]) ] != hunk["old"]:
        detail["outcome"] = "fix_parent_context_mismatch"
        return [], {"fix_parent_context_mismatch"}
    detail.update({"parent_url": parent["url"], "parent_sha256": parent["sha256"]})
    spans = function_spans(parent["source"])
    installed = function_spans(info["source"])
    mappings, failures = [], set()
    outer_addition = False
    for changed, kind, text in hunk["changed"]:
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        line = hunk["old_start"] + changed
        owners = [x for x in spans if x["line"] <= line <= x["end_line"]]
        if not owners:
            failures.add("patch_changes_module_or_class_code")
            continue
        owner = min(owners, key=lambda x: x["end_line"] - x["line"])
        if kind == "added" and len(text) - len(text.lstrip()) <= owner["column"]:
            failures.add("patch_adds_definition_or_outer_scope_code")
            outer_addition = True
            continue
        symbol = module + "." + owner["name"]
        matches = [x for x in installed if x["name"] == owner["name"]]
        if len(matches) != 1 or symbol not in graph.symbols or symbol in graph.ambiguous_symbols:
            failures.add("fix_parent_symbol_missing_or_ambiguous")
            continue
        item = {"symbol": symbol, "file": info["file"], "line": matches[0]["line"],
                "patch_file": hunk["file"], "method": "qualified_symbol_from_fix_parent",
                "meaning": "patch_associated_function", "parent_url": parent["url"],
                "parent_sha256": parent["sha256"], "parent_line": line,
                "body_matches_fix_parent": matches[0]["ast"] == owner["ast"]}
        if item not in mappings:
            mappings.append(item)
    if outer_addition and not any(kind == "removed" for _, kind, _ in hunk["changed"]):
        mappings = []
    detail["outcome"] = "qualified_symbol_from_fix_parent" if mappings else "unmapped_fix_parent"
    detail["analysis_support"] = "partial" if mappings and failures else "supported" if mappings else "unknown"
    detail["target_kinds"] = ["function"] if mappings else []
    detail["symbols"] = sorted({x["symbol"] for x in mappings})
    return mappings, failures
