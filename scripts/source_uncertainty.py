"""Limit dependency metadata gaps to components participating in the call graph.

Only a component with indexed exact source and no reachable module/symbol is
excluded. Missing source identities remain blocking. Dynamic or missing calls
are still handled by graph.gaps; this function does not claim they are resolved.
"""
from pathlib import Path


def source_issue_scope(graph, context):
    indexed = {str(Path(info["root"]).resolve()) for info in graph.modules.values()}
    active = set()
    for symbol in graph.root_parents():
        meta = graph.symbols.get(symbol, {})
        module = graph.modules.get(meta.get("module"), {})
        if module.get("root"):
            active.add(str(Path(module["root"]).resolve()))
    source_roots = {record["purl"]: str(Path(record["source"]).resolve())
                    for record in context.get("sources", []) if record.get("source") and record.get("purl")}
    blocking, unrelated = [], []
    for issue in context.get("issues", []):
        root = source_roots.get(issue.get("purl"))
        if root in indexed and root not in active:
            unrelated.append({**issue, "scope_basis": "component_source_indexed_but_no_reachable_symbols"})
        else:
            blocking.append(issue)
    return blocking, unrelated
