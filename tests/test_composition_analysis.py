import pytest
from scripts.composition_analysis import (
    extract_version_from_purl,
    find_by_path,
    find_affected_version,
    extract_metrics,
)


def test_extract_version_from_purl():
    assert extract_version_from_purl("pkg:pypi/foo@1.2.3") == "1.2.3"
    assert extract_version_from_purl("pkg:pypi/bar@0.0.1") == "0.0.1"
    assert extract_version_from_purl("pkg:pypi/baz") is None
    assert extract_version_from_purl("") is None


def test_find_by_path_dict():
    obj = {"a": 1, "b": {"c": 2}}
    assert find_by_path(obj, ["a"]) == [1]
    assert find_by_path(obj, ["b", "c"]) == [2]
    assert find_by_path(obj, ["b"]) == [{"c": 2}]
    assert find_by_path(obj, ["x"]) == []


def test_find_by_path_list():
    obj = {"items": [10, 20]}
    assert find_by_path(obj, ["items", "0"]) == [10]
    assert find_by_path(obj, ["items", "1"]) == [20]


def test_find_by_path_nested():
    obj = {"containers": [{"cna": {"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]}}]}
    metrics = find_by_path(obj, ["containers", "cna", "metrics", "0"])
    assert len(metrics) == 1
    assert metrics[0]["cvssV3_1"]["baseScore"] == 7.5


def test_find_affected_version():
    cve = {
        "containers": [{
            "cna": {
                "affected": [{
                    "versions": [{"lessThan": "2.0.0"}]
                }]
            }
        }]
    }
    assert find_affected_version(cve) == "<2.0.0"

    cve2 = {
        "containers": [{
            "cna": {
                "affected": [{"versions": [{"lessThanOrEqual": "1.9"}]}]
            }
        }]
    }
    assert find_affected_version(cve2) == "<=1.9"


def test_find_affected_version_empty():
    assert find_affected_version({}) is None
    assert find_affected_version({"containers": []}) is None


def test_extract_metrics():
    cve = {
        "containers": [{
            "cna": {
                "metrics": [{
                    "cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH"}
                }]
            }
        }]
    }
    score, severity = extract_metrics(cve)
    assert score == 8.1
    assert severity == "HIGH"


def test_extract_metrics_empty():
    assert extract_metrics({}) == (None, None)
    assert extract_metrics({"containers": []}) == (None, None)


def test_purl_version_ignores_qualifiers_and_subpath():
    assert extract_version_from_purl("pkg:pypi/demo@1.2?repository_url=https://example.org#src") == "1.2"


def test_multiple_installed_versions_are_not_deduplicated(tmp_path, monkeypatch):
    import json
    from scripts import composition_analysis as analysis
    components = [{"name": "demo", "purl": f"pkg:pypi/demo@{version}"} for version in ("1", "2")]
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}), encoding="utf-8")
    monkeypatch.setattr(analysis, "ensure_vdb_available", lambda: None)
    monkeypatch.setattr(analysis, "_process_one_component", lambda comp: [{"purl": comp["purl"], "package": "demo", "cve": "CVE-X", "affected_version": "<3"}])
    assert len(analysis.check_vulnerabilities_from_sbom(str(tmp_path), str(path))) == 2


def test_unversioned_sbom_cannot_produce_clean_scan(tmp_path):
    import json
    from scripts.composition_analysis import check_vulnerabilities_from_sbom
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"purl": "pkg:pypi/demo"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unversioned"):
        check_vulnerabilities_from_sbom(str(tmp_path), str(path))


@pytest.mark.parametrize("state", ["missing", "empty", "corrupt", "populated"])
def test_vdb_preflight(tmp_path, monkeypatch, state):
    import sqlite3
    import sys
    from types import SimpleNamespace
    from scripts.composition_analysis import ensure_vdb_available
    data, index = tmp_path / "data.db", tmp_path / "index.db"
    fake = SimpleNamespace(config=SimpleNamespace(VDB_BIN_FILE=str(data), VDB_BIN_INDEX=str(index)))
    monkeypatch.setitem(sys.modules, "vdb.lib", fake)
    for path, table in [(data, "cve_data"), (index, "cve_index")]:
        if state == "corrupt":
            path.write_text("not a database", encoding="utf-8")
        elif state != "missing":
            with sqlite3.connect(path) as db:
                db.execute(f"CREATE TABLE {table} (cve_id TEXT)")
                if state == "populated":
                    db.execute(f"INSERT INTO {table} VALUES ('CVE-X')")
    if state == "populated":
        ensure_vdb_available()
    else:
        with pytest.raises(RuntimeError, match="database"):
            ensure_vdb_available()



def test_same_version_instances_keep_their_identity_with_one_database_query(tmp_path, monkeypatch):
    import json
    from scripts import composition_analysis as analysis
    from scripts.sarif_report import vulns_to_sarif
    components = [{"name": "demo", "purl": "pkg:npm/demo@1.0.0", "bom-ref": location}
                  for location in ("npm:node_modules/demo", "npm:node_modules/parent/node_modules/demo")]
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}), encoding="utf-8")
    calls = []
    def query(component):
        calls.append(component)
        return [{"purl": component["purl"], "package": "demo", "cve": "CVE-X"}]
    monkeypatch.setattr(analysis, "ensure_vdb_available", lambda: None)
    monkeypatch.setattr(analysis, "_process_one_component", query)
    findings = analysis.check_vulnerabilities_from_sbom(str(tmp_path), str(path))
    assert len(calls) == len(findings) == 1
    assert findings[0]["component_refs"] == sorted(c["bom-ref"] for c in components)
    assert vulns_to_sarif(findings)["runs"][0]["results"][0]["properties"]["component_refs"] == findings[0]["component_refs"]



def test_empty_vdb_result_does_not_repeat_the_same_purl_lookup(monkeypatch):
    from scripts import composition_analysis as analysis
    calls = []
    monkeypatch.setattr(analysis, "search_by_any", lambda *args, **kwargs: calls.append(args[0]) or [])
    monkeypatch.setattr(analysis, "search_by_purl_like", lambda *args, **kwargs: pytest.fail("identical fallback query"))
    assert analysis._process_one_component({"name": "demo", "purl": "pkg:npm/demo@1.0.0"}) == []
    assert calls == ["pkg:npm/demo@1.0.0"]
