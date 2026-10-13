"""
Export vulnerability report to SARIF 2.1. Keeps reachability in result.properties
so ASPM/Code Scanning can display it.
"""
import json
import os
from pathlib import Path


from scripts.reachability_result import reachability_status, reachability_value


def _is_reachable(v):
    return reachability_value(v.get("reachability"))


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
            loc_uri = Path(loc_uri).resolve().as_uri()

        entry = {
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
                "reachabilityStatus": reachability_status(v.get("reachability")),
                "reachability": v.get("reachability"),
                "package": v.get("package"),
                "installed_version": v.get("installed_version"),
                "severity": sev,
                "score": v.get("score"),
                "purl": v.get("purl"),
                "component_refs": v.get("component_refs", []),
                "cve": v.get("cve"),
                "affected_version": v.get("affected_version"),
            },
        }
        report = v.get("reachability") or {}
        paths = report.get("paths", []) if isinstance(report, dict) else []
        if paths:
            flows = []
            for path in paths:
                locations = []
                for step in path:
                    if step.get("file") and step.get("line"):
                        locations.append({"location": {
                            "message": {"text": step["symbol"] + (" [possible callback invocation]" if step.get("edge_kind") == "passed_callable_may_be_invoked" else "")},
                            "physicalLocation": {
                                "artifactLocation": {"uri": Path(step["file"]).resolve().as_uri()},
                                "region": {"startLine": step.get("call_line") or step["line"]},
                            },
                        }})
                if locations:
                    flows.append({"threadFlows": [{"locations": locations}]})
            if flows:
                entry["codeFlows"] = flows
                entry["locations"] = [flows[0]["threadFlows"][0]["locations"][0]["location"]]
        results.append(entry)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DepReach",
                    "informationUri": "https://github.com/akiracrying/DepReach",
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
