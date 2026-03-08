"""
Export vulnerability report to SARIF 2.1. Keeps reachability in result.properties
so ASPM/Code Scanning can display it.
"""
import json
import os


def _is_reachable(v):
    r = v.get("reachability") or {}
    if not isinstance(r, dict):
        return False
    for info in r.values():
        if isinstance(info, dict) and info.get("is_reachable"):
            return True
    return False


def vulns_to_sarif(vulns: list, project_uri: str = None) -> dict:
    """Build SARIF 2.1 object from vulns list. Reachability in result.properties."""
    rules = []
    rule_id_to_index = {}
    for v in vulns:
        rid = v.get("cve") or f"vuln-{v.get('purl', 'unknown')}"
        if rid not in rule_id_to_index:
            rule_id_to_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "shortDescription": {"text": v.get("cve") or "Vulnerability"},
                "properties": {"security-severity": str(v.get("score") or "0")},
            })

    results = []
    for v in vulns:
        rid = v.get("cve") or f"vuln-{v.get('purl', 'unknown')}"
        sev = (v.get("severity") or "UNKNOWN").upper()
        level = "error" if sev in ("CRITICAL", "HIGH") else "warning"
        desc = (v.get("description") or "")[:500] or v.get("cve", "")
        reachable = _is_reachable(v)
        loc_uri = project_uri or v.get("purl") or f"pkg:{v.get('package', 'unknown')}@{v.get('installed_version', '')}"
        if not loc_uri.startswith("file://") and not loc_uri.startswith("pkg:"):
            loc_uri = "file:///" + os.path.abspath(loc_uri).replace("\\", "/")

        results.append({
            "ruleId": rid,
            "ruleIndex": rule_id_to_index.get(rid, 0),
            "level": level,
            "message": {"text": desc},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc_uri},
                }
            }],
            "properties": {
                "isReachable": reachable,
                "package": v.get("package"),
                "installed_version": v.get("installed_version"),
                "severity": sev,
                "score": v.get("score"),
                "purl": v.get("purl"),
                "cve": v.get("cve"),
                "affected_version": v.get("affected_version"),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DepReach",
                    "informationUri": "https://github.com/DepReach/DepReach",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }


def write_sarif(vulns: list, output_path: str, project_uri: str = None) -> None:
    """Write vulns to a SARIF file. Reachability preserved in result.properties."""
    sarif = vulns_to_sarif(vulns, project_uri=project_uri)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
