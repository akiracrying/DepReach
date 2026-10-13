import logging
import os
import re
from scripts.source_store import download_purl_source

import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

LANG_FUNCTION_PATTERNS = {
    '.py': re.compile(r'(?:async\s+)?def\s+(\w+)\s*\('),
    '.js': re.compile(r'(?:(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>))'),
    '.ts': re.compile(r'(?:(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>))'),
    '.java': re.compile(r'(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)+[\w$<>\[\]]+\s+(\w+)\s*\('),
    '.go': re.compile(r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('),
    '.rb': re.compile(r'def\s+(?:self\.)?(\w+)'),
    '.rs': re.compile(r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]'),
    '.php': re.compile(r'(?:public|private|protected|static)?\s*function\s+(\w+)\s*\('),
}

HUNK_HEADER_RE = re.compile(r'^@@[^@]+@@\s*(.*)')


def extract_commit_links(references: list[str]) -> list[str]:
    # Collapse equivalent patch/diff/canonical references to the same fix.
    return sorted({re.sub(r"\.(?:patch|diff)$", "", ref.split("#", 1)[0].split("?", 1)[0])
                   for ref in references if "/commit/" in ref})


def extract_repo_name(url: str) -> str | None:
    parts = urlparse(url).path.strip('/').split('/')
    if len(parts) >= 2:
        return parts[1]
    return None


def get_diff(url: str) -> str | None:
    if url.endswith('.patch'):
        url = url[:-6]
    if not url.endswith('.diff'):
        url += '.diff'
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.warning("Failed to fetch diff from %s: %s", url, e)
        return None


def _match_func_name(pattern, text: str) -> str | None:
    m = pattern.search(text)
    if m:
        return next((g for g in m.groups() if g), None)
    return None


def extract_functions_from_diff(diff_text: str) -> set[str]:
    """Parse unified diff, extracting function names from changed lines and hunk headers."""
    changed_functions = set()
    current_ext = None

    for line in diff_text.splitlines():
        if line.startswith('diff --git'):
            m = re.search(r'b/(.+)$', line)
            if m:
                _, current_ext = os.path.splitext(m.group(1))
            continue

        if not current_ext:
            continue

        pattern = LANG_FUNCTION_PATTERNS.get(current_ext)
        if not pattern:
            continue

        # Hunk header: extract the enclosing function of the changed block
        if line.startswith('@@'):
            m = HUNK_HEADER_RE.match(line)
            if m:
                name = _match_func_name(pattern, m.group(1).strip())
                if name:
                    changed_functions.add(name)
            continue

        if line.startswith('+++') or line.startswith('---'):
            continue

        # Only process actually changed lines (+ added, - removed)
        if not (line.startswith('+') or line.startswith('-')):
            continue

        name = _match_func_name(pattern, line[1:])
        if name:
            changed_functions.add(name)

    return changed_functions

def check_reachability(vuln_references, component_usage=None, project_call_graph=None,
                       purl=None, imports_data="data", *, project_dir=None,
                       dependency_sources=(), library_source=None, include_tests=False,
                       use_cache=False, cve="", analysis_session=None, source_context=None):
    """Find possible calls to patch-associated functions in versioned source.

    A changed function is a candidate, not a confirmed exploit sink. Unknown
    source, mapping or dispatch is preserved in all output formats.
    """
    from pathlib import Path
    from scripts.python_graph import build_python_graph, capture_sources
    from scripts.patch_mapping import map_patch
    from scripts.reachability_result import result
    import hashlib
    import json
    from scripts.cache import make_context, get_cached_reachability, cache_reachability
    from packageurl import PackageURL

    try:
        package = PackageURL.from_string(purl)
    except (ValueError, TypeError):
        return result("unsupported", reasons=["versioned_python_package_required"])
    if package.type != "pypi" or not package.version:
        return result("unsupported", reasons=["versioned_python_package_required"])
    if project_dir is None:
        return result(reasons=["project_source_required"])
    from scripts.fix_references import resolve_fix_references
    links, reference_discovery = resolve_fix_references(vuln_references, session=analysis_session)
    if not links:
        return result(reasons=["no_fix_commit_reference", *(issue["reason"] for issue in reference_discovery["issues"])],
                      reference_discovery=reference_discovery)
    try:
        lib_dir = str(Path(library_source or download_purl_source(purl, imports_data)).resolve())
        sources = list(dict.fromkeys([*(str(Path(p).resolve()) for p in dependency_sources), lib_dir]))
        diffs = {link: get_diff(link) for link in links}
        patch_digests = {link: hashlib.sha256(diff.encode()).hexdigest() for link, diff in diffs.items() if diff}
        capture = analysis_session.source_snapshot if analysis_session else capture_sources
        snapshots = (capture(project_dir, include_tests), *(capture(path) for path in sources))
        project_digest = str(snapshots[0].root) + snapshots[0].digest
        dependency_digests = [str(snapshot.root) + snapshot.digest for snapshot in snapshots[1:]]
        source_snapshot_info = {
            "consistency": "hash_graph_and_mapping_use_same_captured_bytes",
            "reuse_scope": "scan" if analysis_session and analysis_session.freeze_sources else "check",
            "atomic_filesystem_snapshot": False,
            "inputs": [{"root": str(snapshot.root), "sha256": snapshot.digest,
                        "files": len(snapshot.files), "include_tests": snapshot.include_tests}
                       for snapshot in snapshots],
        }
        source_context = source_context or {}
        from scripts.vulnerability_models import load_catalog, annotate_mappings
        models, model_digest = load_catalog()
        context = make_context(project_digest,
                               [f"{link}:{patch_digests.get(link, 'unavailable')}" for link in links] + [source_context.get("fingerprint", ""), model_digest, hashlib.sha256(json.dumps(reference_discovery, sort_keys=True).encode()).hexdigest()],
                               dependency_digests=dependency_digests,
                               include_tests=include_tests)
        graph_key = make_context(project_digest, [], dependency_digests=dependency_digests, include_tests=include_tests)
        if use_cache:
            cached = get_cached_reachability(purl, cve, context)
            if cached:
                return {**cached, "cache_hit": True, "source_snapshot": source_snapshot_info}
        build = lambda: build_python_graph(project_dir, dependency_sources=sources, include_tests=include_tests, source_snapshots=snapshots)
        graph = analysis_session.graph(graph_key, build) if analysis_session else build()
    except (ValueError, OSError, requests.RequestException) as exc:
        return result(reasons=["dependency_source_unavailable"], error=str(exc))

    reference_gaps = {issue["reason"] for issue in reference_discovery["issues"]}
    reports, paths, mappings, reasons, digests = {}, [], [], set(reference_gaps), {}
    speculative_paths = []
    from scripts.source_uncertainty import source_issue_scope
    blocking_source_issues, unrelated_source_issues = source_issue_scope(graph, source_context)
    inventory_gaps = {item["reason"] for item in blocking_source_issues}
    reasons.update(inventory_gaps)
    patch_evidence = []
    reviewed_targets = []
    for link in links:
        diff = diffs[link]
        if not diff:
            reports[link] = result(reasons=["fix_diff_unavailable"])
            reasons.add("fix_diff_unavailable")
            continue
        digests[link] = hashlib.sha256(diff.encode()).hexdigest()
        evidence_start = len(patch_evidence)
        mapped, mapping_gaps = map_patch(diff, graph, lib_dir, reference=link, evidence=patch_evidence)
        mapped, reviews = annotate_mappings(mapped, graph, lib_dir, purl, cve, [*vuln_references, link], models)
        reviewed_targets.extend(reviews)
        mappings.extend({**item, "reference": link} for item in mapped)
        reasons.update(mapping_gaps)
        target_gaps = graph.gaps([item["symbol"] for item in mapped]) if mapped else graph.gaps()
        reasons.update(target_gaps)
        chain = graph.path((item["symbol"] for item in mapped), include_speculative=False)
        possible_chain = graph.path(item["symbol"] for item in mapped) if not chain else []
        if possible_chain:
            speculative_paths.append(graph.evidence(possible_chain))
            reasons.add("speculative_callback_path")
        evidence = graph.evidence(chain) if chain else []
        if evidence:
            paths.append(evidence)
        status = "reachable" if evidence else "unknown" if target_gaps or mapping_gaps or inventory_gaps or reference_gaps else "no_path_found"
        relevant_changes = [item for item in patch_evidence[evidence_start:] if item.get("analysis_support") != "ignored"]
        if not mapped and relevant_changes and all(item.get("analysis_support") == "unsupported" for item in relevant_changes):
            status = "unsupported"
        reports[link] = result(status, reasons=[*target_gaps, *mapping_gaps, *inventory_gaps, *reference_gaps], paths=[evidence] if evidence else [], mappings=mapped)
    status = "reachable" if paths else "unsupported" if reports and all(item["status"] == "unsupported" for item in reports.values()) else "unknown" if reasons else "no_path_found"
    from collections import Counter
    function_results = []
    for symbol in sorted({item["symbol"] for item in mappings}):
        chain = graph.path([symbol], include_speculative=False)
        function_results.append({"symbol": symbol,
            "target_kind": graph.symbols.get(symbol, {}).get("kind", "function"),
            "call_path_status": "found" if chain else "not_found",
            "status": "reachable" if chain else "unknown" if graph.gaps([symbol]) or inventory_gaps else "no_path_found",
            "paths": [graph.evidence(chain)] if chain else [],
            "blocking_reasons": sorted(set(graph.gaps([symbol])) | inventory_gaps),
            "vulnerability_evidence": sorted({m.get("vulnerability_evidence", "patch_candidate") for m in mappings if m["symbol"] == symbol}),
            "mapping_evidence": sorted({m.get("mapping_evidence", "unknown") for m in mappings if m["symbol"] == symbol}),
            "mapping_methods": sorted({m["method"] for m in mappings if m["symbol"] == symbol})})
    # Keep bounded representative diagnostics, with exact counts and truncation
    # metadata. Thousands of repeated AST warnings obscured the actual evidence.
    counts = Counter(d["reason"] for d in graph.diagnostics)
    sample_counts, samples = Counter(), []
    for diagnostic in graph.diagnostics:
        if sample_counts[diagnostic["reason"]] < 5:
            samples.append(diagnostic)
            sample_counts[diagnostic["reason"]] += 1
    def bounded_models(models, category, relevant):
        totals, seen, examples = Counter(item[category] for item in models), Counter(), []
        for item in models:
            if relevant(item) or seen[item[category]] < 5:
                examples.append(item)
                seen[item[category]] += 1
        return examples, dict(totals), len(models) - len(examples)
    path_symbols = {step["symbol"] for path in paths for step in path}
    callback_samples, callback_counts, callback_omitted = bounded_models(
        graph.callback_models, "disposition", lambda item: item["callback"] in path_symbols and item["caller"] in path_symbols)
    dispatch_samples, dispatch_counts, dispatch_omitted = bounded_models(
        graph.dispatch_models, "basis", lambda item: item["method"] in path_symbols)
    report = result(status, reasons=reasons, paths=paths, mappings=mappings,
                  call_path_status="found" if paths else "not_found" if mappings else "not_evaluated",
                  function_results=function_results, patch_evidence=patch_evidence,
                  reviewed_targets=reviewed_targets, model_catalog_sha256=model_digest,
                  dispatch_models=dispatch_samples, dispatch_model_counts=dispatch_counts,
                  dispatch_models_omitted=dispatch_omitted,
                  callback_models=callback_samples, callback_model_counts=callback_counts,
                  callback_models_omitted=callback_omitted,
                  analysis_gaps=graph.gaps(),
                  speculative_paths=speculative_paths,
                  blocking_source_issues=blocking_source_issues,
                  nonblocking_source_issues=unrelated_source_issues,
                  source_context={k: source_context[k] for k in ("fingerprint", "complete", "issues", "manifest_path") if k in source_context},
                  analysis_metrics=analysis_session.metrics() if analysis_session else {"graph_builds": 1, "graph_hits": 0},
                  diagnostic_counts=dict(counts), diagnostics_total=len(graph.diagnostics),
                  diagnostics_omitted=len(graph.diagnostics) - len(samples),
                  references=reports, reference_discovery=reference_discovery,
                  patch_sha256=digests, diagnostics=samples,
                  scope="all_first_party_functions_and_module_code",
                  target_kind="patch_associated_code_or_data" if any(m.get("target_kind") == "data" for m in mappings) else "patch_associated_function",
                  unsupported_changes=[{"file": item["file"], "change_kind": item.get("change_kind"),
                                        "outcome": item.get("outcome")} for item in patch_evidence
                                       if item.get("analysis_support") in {"unsupported", "partial"}],
                  vulnerability_mapping="candidate_from_fix_reference",
                  exploitability="not_assessed",
                  library_source=lib_dir,
                  source_provenance="user_supplied_version" if library_source else "pypi_versioned_sdist",
                  limitations=["Static possible call paths; not proof of execution or exploitability.",
                               "No path found is scoped to the modeled calls, not a safety verdict."],
                  analyzed_modules=len(graph.modules), analyzed_functions=len(graph.symbols),
                  input_fingerprint=context, source_snapshot=source_snapshot_info, cache_hit=False)
    from scripts.reachability_result import explain_result
    report["explanation"] = explain_result(report)
    if use_cache:
        cache_reachability(purl, cve, report, context)
    return report


def extract_library_function_calls(directory):
    """Compatibility helper returning fully qualified targets grouped by module root."""
    graph = build_call_graph(directory)
    result = {}
    for call in graph.calls:
        target = call.get("resolved")
        if target and not call.get("import"):
            result.setdefault(target.split(".")[0], set()).add(target)
    return result


def build_call_graph(directory, *, dependency_sources=(), include_tests=False):
    from scripts.python_graph import build_python_graph
    return build_python_graph(directory, dependency_sources=dependency_sources, include_tests=include_tests)


def is_func_reachable(start_funcs: set[str], target_func: str, call_graph: dict[str, set[str]]) -> bool:
    """Whether target_func is reachable from any of start_funcs in call_graph."""
    visited = set()
    stack = list(start_funcs)

    while stack:
        current = stack.pop()
        if current == target_func:
            return True
        if current not in visited:
            visited.add(current)
            stack.extend(call_graph.get(current, []))

    return False
