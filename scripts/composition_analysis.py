import json
import os
import warnings

from custom_json_diff.lib.utils import json_load
from vdb.lib.search import search_by_any, search_by_purl_like
from scripts.detect_type import detect_project_type
from typing import List, Dict
from pydantic import BaseModel, AnyUrl
from itertools import chain

warnings.filterwarnings("ignore", category=UserWarning)

def serialize_source_data(source_data):
    try:
        if hasattr(source_data, "root") and isinstance(source_data.root, BaseModel):
            return source_data.root.model_dump()
        return source_data
    except Exception as e:
        print(f"Failed to serialize source_data: {e}")
        return {}

def extract_severity(vuln):
    # Пытаемся достать severity из source_data
    if hasattr(vuln.get("source_data", {}), "containers"):
        for container in vuln["source_data"].containers or []:
            for rating in getattr(container, "ratings", []):
                if severity := getattr(rating, "severity", None):
                    return severity
    return vuln.get("severity", "UNKNOWN")

def extract_version_from_purl(purl: str) -> str | None:
    if "@" in purl:
        return purl.split("@")[-1]
    return None

def extract_metrics(cve_object):
    """
    Извлекает метрики (baseScore и baseSeverity) из наиболее высокой CVSS версии в metrics.
    """
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

    # baseScore может быть float или объектом с value
    base_score = best_metrics.get("baseScore")
    if isinstance(base_score, dict):
        base_score = base_score.get("value") or base_score.get("name")
    elif hasattr(base_score, "value"):
        base_score = getattr(base_score, "value", None)

    # baseSeverity аналогично
    base_severity = best_metrics.get("baseSeverity")
    if isinstance(base_severity, dict):
        base_severity = base_severity.get("value") or base_severity.get("name")
    elif hasattr(base_severity, "value"):
        base_severity = getattr(base_severity, "value", None)

    return base_score, base_severity

def find_by_path(obj, path):
    """
    Рекурсивно ищет значения по частичному пути, поддерживая индексы и ключи.
    Если path = ["problemTypes", "0", "descriptions", "0", "cweId"], то найдёт даже если путь не полный.
    """
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
    """
    Использует find_by_path, чтобы достать lessThan или lessThanOrEqual из cve_object
    """
    # Получаем список всех версий
    versions = find_by_path(cve_object, ["containers", "cna", "affected", "0", "versions", "0"])
    if not versions:
        return None

    for version_entry in versions:
        # Сначала пытаемся взять lessThan, если нет — lessThanOrEqual
        if version := version_entry.get("lessThan"):
            return "<" + version
        if version := version_entry.get("lessThanOrEqual"):
            return "<=" + version

    return None

def extract_description(vuln):
    # Пытаемся достать описание из source_data
    desc = vuln.get("description")
    if desc:
        return desc
    try:
        data = vuln.get("source_data", None)
        if data:
            return data.cveMetadata.description or ""
    except Exception:
        pass
    return ""

def extract_fixed_version(vuln):
    affects = getattr(vuln.get("source_data", {}), "containers", [])
    for container in affects or []:
        for aff in getattr(container, "affected", []):
            for ver in getattr(aff, "versions", []):
                if getattr(ver, "status", "").lower() == "fixed":
                    return getattr(ver, "version", "")
    return vuln.get("fixed_location")

def check_vulnerabilities_from_sbom(src_dir: str, bom_file: str) -> List[Dict]:
    print("Scanning")
    if not os.path.exists(bom_file):
        raise FileNotFoundError(f"No BOM found at {bom_file}")

    sbom_data = json_load(bom_file)
    components = sbom_data.get("components", [])
    all_vulns = []

    # Определяем тип проекта


    for comp in components:
        purl = comp.get("purl")
        if not purl:
            continue

        results = search_by_any(purl, with_data=True)
        if not results:
            results = search_by_purl_like(purl, with_data=True)

        for vuln in results:
            # debug_file = "vuln_raw_dump.json"
            # with open(debug_file, "w", encoding="utf-8") as f:
            #     json.dump(vuln, f, indent=2, default=str)
            # return []
            cve_object = serialize_source_data(vuln.get("source_data"))

            final_data ={

            }
            base_score, base_severity = extract_metrics(cve_object)
            refs_raw = find_by_path(cve_object, ["containers", "cna", "references"])
            flat_refs = list(chain.from_iterable(r for r in refs_raw if isinstance(r, list)))
            urls = [str(r.get("url")) for r in flat_refs if isinstance(r, dict) and "url" in r]

            v = {
                "package": comp.get("name"),
                "installed_version": extract_version_from_purl(purl),
                "purl": purl,
                "cve": vuln.get("cve_id"),
                "severity": base_severity,
                "score": base_score,
                "description": find_by_path(cve_object, ["containers", "cna", "descriptions", "0", "value"])[0],
                "affected_version": find_affected_version(cve_object),
                "CWE": find_by_path(cve_object, ["containers", "0", "descriptions", "cweId"])[0],
                "references": urls
            }
            all_vulns.append(v)

    seen = set()
    unique_vulns = []

    for v in all_vulns:
        key = (v["package"], v["cve"], v["affected_version"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    return unique_vulns
