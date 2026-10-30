"""Opt-in, snapshot-verified Python excerpts for optional provider review.

Only explicitly allowed scan roots are read. Captured bytes supply both the
snapshot digest and the excerpts; no scanned code is executed or imported.
"""
import ast
import hashlib
import io
import re
import stat
from pathlib import Path
import tokenize

from scripts.python_graph import _module_name, python_files

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ROOT_BYTES = 64 * 1024 * 1024
MAX_ROOT_FILES = 5000
MAX_BATCH_BYTES = 128 * 1024 * 1024
MAX_SELECTED_ROOTS = 8
MAX_EXCERPTS = 8
MAX_EXCERPT_CHARS = 1800
MAX_EXCERPT_LINES = 40


class SourceEvidenceError(ValueError):
    pass


def _capture(root, include_tests):
    """Same digest contract as python_graph.capture_sources, with I/O bounds."""
    digest, contents, size = hashlib.sha256(), {}, 0
    for path in python_files(root, include_tests):
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise SourceEvidenceError("source_path_outside_allowed_root")
        if len(contents) >= MAX_ROOT_FILES:
            raise SourceEvidenceError("source_snapshot_file_limit")
        if not stat.S_ISREG(resolved.stat().st_mode):
            raise SourceEvidenceError("source_not_regular_file")
        with resolved.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        size += len(raw)
        if len(raw) > MAX_FILE_BYTES or size > MAX_ROOT_BYTES:
            raise SourceEvidenceError("source_snapshot_byte_limit")
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0" + raw + b"\0")
        contents[relative] = raw
    return {"sha256": digest.hexdigest(), "files": contents,
            "root_is_package": "__init__.py" in contents}


def _definition_spans(text):
    spans = []
    class Definitions(ast.NodeVisitor):
        def __init__(self): self.scope = []
        def definition(self, node, kind):
            self.scope.append(node.name)
            spans.append({"name": ".".join(self.scope), "kind": kind,
                "source_start_line": min([node.lineno, *(d.lineno for d in node.decorator_list)]),
                "end_line": node.end_lineno})
            self.generic_visit(node)
            self.scope.pop()
        def visit_ClassDef(self, node): self.definition(node, "python_class")
        def visit_FunctionDef(self, node): self.definition(node, "python_function")
        visit_AsyncFunctionDef = visit_FunctionDef
    Definitions().visit(ast.parse(text))
    return spans


def _excerpt(lines, start, end, focus):
    """Whole original lines only: ranges and hashes always describe sent text."""
    full = "".join(lines[start - 1:end])
    if end - start + 1 <= MAX_EXCERPT_LINES and len(full) <= MAX_EXCERPT_CHARS:
        return start, end, full, True
    # Prefer the call/change site in large functions, preserving contiguous lines.
    if len(lines[focus - 1]) > MAX_EXCERPT_CHARS:
        raise SourceEvidenceError("source_line_exceeds_excerpt_limit")
    left, right = focus, focus
    while right - left + 1 < MAX_EXCERPT_LINES:
        candidates = []
        if left > start: candidates.append((left - 1, right))
        if right < end: candidates.append((left, right + 1))
        if not candidates: break
        chosen = next(((a, b) for a, b in candidates if len("".join(lines[a - 1:b])) <= MAX_EXCERPT_CHARS), None)
        if chosen is None: break
        left, right = chosen
    return left, right, "".join(lines[left - 1:right]), False


class ReviewSources:
    def __init__(self, roots):
        self.roots = {Path(root).resolve(strict=True) for root in roots}
        if len(self.roots) > MAX_SELECTED_ROOTS:
            raise ValueError("at most eight source roots may be selected")
        if any(not root.is_dir() for root in self.roots):
            raise ValueError("source roots must be directories")
        self._captures = {}
        self._parsed = {}
        self._captured_bytes = 0

    def _snapshot(self, root, include_tests):
        key = (root, include_tests)
        if key not in self._captures:
            try:
                captured = _capture(root, include_tests)
                size = sum(len(raw) for raw in captured["files"].values())
                if self._captured_bytes + size > MAX_BATCH_BYTES:
                    raise SourceEvidenceError("source_batch_byte_limit")
                self._captured_bytes += size
                self._captures[key] = captured
            except SourceEvidenceError as exc:
                self._captures[key] = {"error": str(exc)}
            except (OSError, ValueError):
                # A failed capture remains failed within this review batch.
                self._captures[key] = {"error": "source_snapshot_capture_failed"}
        return self._captures[key]

    def _fragment(self, candidate, inputs):
        symbol, file = candidate.get("symbol"), candidate.get("file")
        line = candidate.get("call_line") or candidate.get("line")
        if not isinstance(symbol, str) or not isinstance(file, str) or type(line) is not int or line < 1:
            raise SourceEvidenceError("invalid_source_reference")
        file = Path(file)
        if not file.is_absolute():
            raise SourceEvidenceError("relative_source_reference_unsupported")
        # Match lexical report paths before resolving anything outside approved roots.
        roots = [root for root in self.roots if root in file.parents]
        if not roots:
            raise SourceEvidenceError("source_root_not_selected")
        root = max(roots, key=lambda p: len(p.parts))
        entries = []
        for entry in inputs:
            if isinstance(entry, dict) and isinstance(entry.get("root"), str) and Path(entry["root"]) == root:
                entries.append(entry)
        if not entries:
            raise SourceEvidenceError("scan_snapshot_missing_for_root")
        if len(entries) != 1:
            raise SourceEvidenceError("ambiguous_scan_snapshot")
        entry = entries[0]
        expected = entry.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise SourceEvidenceError("invalid_scan_snapshot_digest")
        include_tests = entry.get("include_tests")
        if type(include_tests) is not bool:
            raise SourceEvidenceError("invalid_scan_snapshot_scope")
        capture = self._snapshot(root, include_tests)
        if "error" in capture:
            raise SourceEvidenceError(capture["error"])
        if capture["sha256"] != expected:
            raise SourceEvidenceError("source_snapshot_changed_since_scan")
        relative = file.relative_to(root).as_posix()
        raw = capture["files"].get(relative)
        if raw is None:
            raise SourceEvidenceError("source_file_not_in_snapshot")
        key = (root, include_tests, relative)
        if key not in self._parsed:
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                text = raw.decode(encoding)
                spans = _definition_spans(text)
                # Python line numbers use CR/LF boundaries. str.splitlines also
                # splits Unicode separators/form feeds inside valid literals.
                lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", text)
                if lines and lines[-1] == "": lines.pop()
                self._parsed[key] = (encoding, lines, spans)
            except (SyntaxError, UnicodeError, LookupError, ValueError):
                raise SourceEvidenceError("source_parse_failed")
        encoding, lines, spans = self._parsed[key]
        if line > len(lines):
            raise SourceEvidenceError("source_line_out_of_range")
        module = _module_name(file, root, capture["root_is_package"])
        if symbol == module + ".<module>":
            # Module code can contain large class/function definitions. A module
            # call must not be attributed to an enclosing function body.
            if any(span["kind"] == "python_function" and span["source_start_line"] <= line <= span["end_line"] for span in spans):
                raise SourceEvidenceError("module_reference_inside_function")
            start, end, kind = max(1, line - 4), min(len(lines), line + 4), "module_line_context"
        else:
            matches = [span for span in spans if module + "." + span["name"] == symbol]
            # Duplicate definitions are ambiguous even when their ranges differ.
            if len(matches) != 1:
                raise SourceEvidenceError("source_symbol_not_unique")
            span = matches[0]
            start, end, kind = span["source_start_line"], span["end_line"], span["kind"]
            if not start <= line <= end:
                raise SourceEvidenceError("source_reference_outside_symbol")
        excerpt_start, excerpt_end, code, full = _excerpt(lines, start, end, line)
        # Absolute filesystem paths are deliberately absent from provider data.
        return {"symbol": symbol, "role": candidate["role"], "relative_path": relative,
                "kind": kind, "focus_line": line, "definition_start_line": start,
                "definition_end_line": end, "excerpt_start_line": excerpt_start,
                "excerpt_end_line": excerpt_end, "whole_definition": full and kind in {"python_function", "python_class"},
                "reference_lines": candidate["reference_lines"], "roles": candidate["roles"],
                "evidence_scope": "scan_wide_diagnostic" if candidate["roles"] == ["unresolved_caller"] else "finding_reference",
                "code": code, "encoding": encoding, "file_sha256": hashlib.sha256(raw).hexdigest(),
                "excerpt_utf8_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
                "scan_root_sha256": expected, "provenance": "matches_scan_snapshot"}

    def collect(self, finding):
        reach = finding.get("reachability") or {}
        snapshot = reach.get("source_snapshot") or {}
        inputs = snapshot.get("inputs", []) if isinstance(snapshot, dict) else []
        if not isinstance(inputs, list): inputs = []
        selection_issues = []
        def limited(values, limit, kind):
            if len(values) > limit:
                selection_issues.append({"reason": "source_reference_selection_limit", "kind": kind,
                                         "total": len(values), "selected": limit})
            return values[:limit]
        # Count distinct definitions, not the number of hunks touching each one.
        target_groups = {}
        for item in limited(reach.get("mappings", []), 64, "mapping_references"):
            if not isinstance(item, dict) or not isinstance(item.get("file"), str) or not isinstance(item.get("symbol"), str):
                selection_issues.append({"reason": "invalid_source_reference"})
                continue
            target_groups.setdefault((item["file"], item["symbol"]), []).append(item)
        if len(target_groups) > 4:
            selection_issues.append({"reason": "source_reference_selection_limit", "kind": "mapping_targets",
                                     "total": len(target_groups), "selected": 4})
        candidates = [{**item, "role": "patch_target"} for group in list(target_groups.values())[:4] for item in group]
        for path in limited(reach.get("paths", []), 2, "paths"):
            candidates.extend({**item, "role": "call_path"} for item in limited(path, 12, "path_steps"))
        for path in limited(reach.get("speculative_paths", []), 1, "speculative_paths"):
            candidates.extend({**item, "role": "speculative_path"} for item in limited(path, 6, "speculative_steps"))
        # For a finding with paths, keep diagnostics on its referenced symbols.
        # Without a path, bounded scan-wide diagnostics remain explicitly labeled.
        referenced = {item.get("symbol") for item in candidates}
        for diagnostic in reach.get("diagnostics", [])[:6]:
            if diagnostic.get("caller") and (not reach.get("paths") or diagnostic["caller"] in referenced):
                candidates.append({"symbol": diagnostic["caller"], "file": diagnostic.get("file"),
                                   "line": diagnostic.get("line"), "role": "unresolved_caller"})
        grouped = {}
        for candidate in candidates:
            key = (candidate.get("file"), candidate.get("symbol"))
            line = candidate.get("call_line") or candidate.get("line")
            if key not in grouped:
                grouped[key] = {**candidate, "reference_lines": [], "roles": []}
            entry = grouped[key]
            if type(line) is int and line not in entry["reference_lines"]:
                entry["reference_lines"].append(line)
            if candidate["role"] not in entry["roles"]:
                entry["roles"].append(candidate["role"])
        excerpts, issues = [], selection_issues
        for candidate in grouped.values():
            if len(excerpts) >= MAX_EXCERPTS:
                issues.append({"reason": "source_excerpt_count_limit"})
                break
            try:
                excerpts.append(self._fragment(candidate, inputs))
            except SourceEvidenceError as exc:
                issues.append({"symbol": candidate.get("symbol"), "reason": str(exc)})
        if not candidates:
            issues.append({"reason": "no_source_references_in_finding"})
        return {"excerpts": excerpts, "issues": issues, "consistency": "captured_bytes_verified_against_scan_snapshot",
                "atomic_filesystem_snapshot": False}
