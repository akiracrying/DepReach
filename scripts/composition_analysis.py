import json
import os
import warnings
import logging

from custom_json_diff.lib.utils import json_load
from packageurl import PackageURL
from typing import List, Dict
from pydantic import BaseModel
from itertools import chain

warnings.filterwarnings("ignore", category=UserWarning)
logger = logging.getLogger(__name__)
MAX_SCAN_WORKERS = 8

def serialize_source_data(source_data):
    try:
        if hasattr(source_data, "root") and isinstance(source_data.root, BaseModel):
            return source_data.root.model_dump()
        return source_data
    except Exception as e:
        print(f"Failed to serialize source_data: {e}")
        return {}

def extract_version_from_purl(purl: str) -> str | None:
    try:
        return PackageURL.from_string(purl).version
    except (TypeError, ValueError):
        return None


def search_by_any(*args, **kwargs):
    from vdb.lib.search import search_by_any as search
    return search(*args, **kwargs)


def search_by_purl_like(*args, **kwargs):
    from vdb.lib.search import search_by_purl_like as search
    return search(*args, **kwargs)


def ensure_vdb_available():
    from vdb.lib import config
    import sqlite3
    for path, table in [(config.VDB_BIN_FILE, "cve_data"), (config.VDB_BIN_INDEX, "cve_index")]:
        if not os.path.isfile(path):
            raise RuntimeError("Vulnerability database is missing; update VDB before scanning")
        try:
            from pathlib import Path
            with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
                populated = db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
            if not populated:
                raise RuntimeError("Vulnerability database is empty; update VDB before scanning")
        except sqlite3.Error as exc:
            raise RuntimeError("Vulnerability database is unreadable") from exc

def extract_metrics(cve_object):
    metrics = find_by_path(cve_object, ["containers", "cna", "metrics", "0"])
    if not metrics:
        return None, None

    cvss_data = {}
    for entry in metrics:
        for key, value in entry.items():
            if key.startswith("cvssV") and isinstance(value, dict):
                try:
                    version_number = int(key[-3:].replace("_", ""))
                    cvss_data[version_number] = value
                except ValueError:
                    continue

    if not cvss_data:
        return None, None

    best_version = max(cvss_data.keys())
    best_metrics = cvss_data[best_version]

    base_score = best_metrics.get("baseScore")
    if isinstance(base_score, dict):
        base_score = base_score.get("value") or base_score.get("name")
    elif hasattr(base_score, "value"):
        base_score = getattr(base_score, "value", None)

    base_severity = best_metrics.get("baseSeverity")
    if isinstance(base_severity, dict):
        base_severity = base_severity.get("value") or base_severity.get("name")
    elif hasattr(base_severity, "value"):
        base_severity = getattr(base_severity, "value", None)

    return base_score, base_severity

def find_by_path(obj, path):
    def search(obj, path, current=[]):
        results = []
        if not path:
            return results

        key = path[0]
        rest = path[1:]

        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    if not rest:
                        results.append(v)
                    else:
                        results += search(v, rest, current + [k])
                else:
                    results += search(v, path, current + [k])

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if str(i) == key:
                    if not rest:
                        results.append(item)
                    else:
                        results += search(item, rest, current + [i])
                else:
                    results += search(item, path, current + [i])
        return results

    return search(obj, path)

def find_affected_version(cve_object: dict) -> str | None:
    versions = find_by_path(cve_object, ["containers", "cna", "affected", "0", "versions", "0"])
    if not versions:
        return None

    for version_entry in versions:
        if version := version_entry.get("lessThan"):
            return "<" + version
        if version := version_entry.get("lessThanOrEqual"):
            return "<=" + version

    return None

def _process_one_component(comp: Dict) -> List[Dict]:
    purl = comp.get("purl")
    if not purl:
        return []
    if extract_version_from_purl(purl) is None:
        logger.debug("Skipping component without version (unpinned): %s", purl)
        return []

    # For PURLs, VDB's search_by_any already delegates to search_by_purl_like.
    # An empty result must not trigger an identical second database query.
    results = search_by_any(purl, with_data=True)

    out = []
    for vuln in results:
        cve_object = serialize_source_data(vuln.get("source_data"))
        base_score, base_severity = extract_metrics(cve_object)
        refs_raw = find_by_path(cve_object, ["containers", "cna", "references"])
        flat_refs = list(chain.from_iterable(r for r in refs_raw if isinstance(r, list)))
        urls = [str(r.get("url")) for r in flat_refs if isinstance(r, dict) and "url" in r]

        desc_values = find_by_path(cve_object, ["containers", "cna", "descriptions", "0", "value"])
        cwe_values = find_by_path(cve_object, ["containers", "cna", "problemTypes", "0", "descriptions", "0", "cweId"])
        if not cwe_values:
            cwe_values = find_by_path(cve_object, ["containers", "0", "descriptions", "cweId"])

        v = {
            "package": comp.get("name"),
            "installed_version": extract_version_from_purl(purl),
            "purl": purl,
            "cve": vuln.get("cve_id"),
            "severity": base_severity,
            "score": base_score,
            "description": (desc_values[0] if desc_values else "") or "",
            "affected_version": find_affected_version(cve_object),
            "CWE": (cwe_values[0] if cwe_values else None),
            "references": urls
        }
        out.append(v)
    return out


def count_sbom_components(bom_file: str) -> int:
    """Quick count of components with purl for progress/estimate."""
    if not os.path.exists(bom_file):
        return 0
    try:
        data = json_load(bom_file)
        return sum(1 for c in data.get("components", []) if c.get("purl"))
    except Exception:
        return 0


def check_vulnerabilities_from_sbom(src_dir: str, bom_file: str) -> List[Dict]:
    if not os.path.exists(bom_file):
        raise FileNotFoundError(f"No BOM found at {bom_file}")

    sbom_data = json_load(bom_file)
    if not isinstance(sbom_data, dict) or sbom_data.get("bomFormat") != "CycloneDX":
        raise ValueError("Expected a CycloneDX JSON SBOM")
    missing_identity = [c for c in sbom_data.get("components", []) if c.get("type", "library") == "library" and not c.get("purl")]
    if missing_identity:
        raise ValueError(f"SBOM contains {len(missing_identity)} libraries without package identity")
    components = [c for c in sbom_data.get("components", []) if c.get("purl")]
    unresolved = [c for c in components if not extract_version_from_purl(c["purl"])]
    if unresolved:
        raise ValueError(f"SBOM contains {len(unresolved)} unversioned dependencies; resolve exact installed versions first")
    ensure_vdb_available()
    logger.info("Starting SBOM scan: %d components with purl", len(components))

    # Query a package version once, retaining every SBOM instance that uses it.
    # npm can install the same PURL at multiple distinct resolution locations.
    by_purl, instance_refs = {}, {}
    for comp in components:
        by_purl.setdefault(comp["purl"], comp)
        if comp.get("bom-ref"):
            instance_refs.setdefault(comp["purl"], set()).add(comp["bom-ref"])
    # vdb/APSW: no multiprocessing or threading (database locked)
    all_vulns = []
    for purl, comp in by_purl.items():
        for finding in _process_one_component(comp):
            finding["component_refs"] = sorted(instance_refs.get(purl, ()))
            all_vulns.append(finding)

    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v["purl"], v["cve"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    return unique_vulns
