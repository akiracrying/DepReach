"""Shared, conservative reachability semantics for every output format."""

ANALYZER_VERSION = "python-static-v4.10"
STATUSES = {"reachable", "no_path_found", "unknown", "unsupported"}


def result(status="unknown", *, reasons=(), paths=(), **details):
    if status not in STATUSES:
        raise ValueError(f"Invalid reachability status: {status}")
    return {
        "status": status,
        # False means no path in this model, never proof of non-exploitability.
        "is_reachable": True if status == "reachable" else False if status == "no_path_found" else None,
        "reasons": sorted(set(reasons)),
        "paths": list(paths),
        "analyzer_version": ANALYZER_VERSION,
        **details,
    }


def reachability_status(report):
    """Accept current and legacy reports, without turning missing data into False."""
    if not isinstance(report, dict) or not report:
        return "unknown"
    if report.get("status") in STATUSES:
        return report["status"]
    if "is_reachable" in report:
        value = report["is_reachable"]
        return "reachable" if value is True else "no_path_found" if value is False else "unknown"
    statuses = [reachability_status(item) for item in report.values()]
    if "reachable" in statuses:
        return "reachable"
    if statuses and all(s == "no_path_found" for s in statuses):
        return "no_path_found"
    if statuses and all(s == "unsupported" for s in statuses):
        return "unsupported"
    return "unknown"


def reachability_value(report):
    status = reachability_status(report)
    return True if status == "reachable" else False if status == "no_path_found" else None


def explain_result(report):
    state = reachability_status(report)
    reasons = set(report.get("reasons", []))
    count = len({m["symbol"] for m in report.get("mappings", [])})
    if state == "reachable":
        return "Reference path found to patch-associated code/data" if report.get("target_kind") == "patch_associated_code_or_data" else "Call path found to a patch-associated function"
    if state == "unsupported" and report.get("unsupported_changes"):
        kinds = sorted({item["change_kind"] for item in report["unsupported_changes"] if item.get("change_kind")})
        return "Patch changes require an unsupported analysis model: " + ", ".join(kinds)
    if "speculative_callback_path" in reasons:
        return "Only a speculative callback path found; callback invocation is unresolved"
    if "no_fix_commit_reference" in reasons:
        return "No fix commit in advisory references"
    if "dependency_source_unavailable" in reasons:
        return "Dependency source unavailable: " + report.get("error", "unknown error")
    if not count and "no_mapped_patch_functions" in reasons:
        return "No function mapped; inspect patch_evidence for each changed file"
    if state == "no_path_found":
        return f"No path to {count} mapped target(s); modeled analysis has no blocking gaps"
    if count:
        return f"No path found to {count} mapped target(s); unresolved calls prevent a negative conclusion"
    return "Analysis incomplete: " + ", ".join(sorted(reasons)[:3])


def suggested_next_action(report):
    """A triage action, not another reachability verdict."""
    state = reachability_status(report)
    reasons = set(report.get("reasons", [])) if isinstance(report, dict) else set()
    if state == "reachable":
        return "Inspect the call path and check the advisory's runtime exploit conditions."
    if "javascript_reachability_not_implemented" in reasons:
        return "Prioritize the affected package update; JS/TS call-path analysis is not available yet."
    if "no_fix_commit_reference" in reasons:
        return "Find the advisory's immutable fix commit before mapping affected code."
    if reasons & {"dependency_source_unavailable", "transitive_version_unresolved", "transitive_version_conflict", "dependency_metadata_incomplete"}:
        return "Provide a resolved dependency inventory and the missing exact-version source or metadata."
    if reasons & {"patch_context_not_uniquely_matched", "patch_file_not_uniquely_matched", "no_mapped_patch_functions", "fix_parent_symbol_missing_or_ambiguous", "patch_target_ambiguous"}:
        return "Compare the fix against the installed version and inspect the unmatched patch evidence."
    if reasons & {"non_python_patch_change", "patch_changes_module_or_class_code"}:
        return "Inspect changed native/data/module code and the unsupported model boundaries."
    if reasons & {"speculative_callback_path", "callback_escapes", "callback_argument"}:
        return "Check where the callback is registered and whether its consumer actually invokes it."
    if state == "no_path_found":
        return "Review the modeled scope and remaining advisory conditions before changing alert policy."
    return "Inspect unresolved-call evidence and the caller that blocks this finding's conclusion."
