import json
import sqlite3

import pytest

from scripts import cache
from scripts.html_report import generate_html_report, _js_json
from scripts.reachability_result import result, reachability_status
from scripts.sarif_report import vulns_to_sarif


@pytest.mark.parametrize("report, expected", [
    ({}, "unknown"),
    ({"is_reachable": "Unknown"}, "unknown"),
    ({"commit": {"is_reachable": False}, "other": "Unknown"}, "unknown"),
    ({"commit": {"is_reachable": True}, "other": "Unknown"}, "reachable"),
    ({"commit": {"is_reachable": False}}, "no_path_found"),
])
def test_legacy_aggregation_preserves_unknown(report, expected):
    assert reachability_status(report) == expected


@pytest.mark.parametrize("status, value", [("reachable", True), ("no_path_found", False), ("unknown", None), ("unsupported", None)])
def test_all_reports_preserve_status(tmp_path, status, value):
    vulnerability = {"cve": "TEST-1", "package": "example", "purl": "pkg:pypi/example@1", "reachability": result(status, reasons=["test_reason"])}
    sarif = vulns_to_sarif([vulnerability])
    properties = sarif["runs"][0]["results"][0]["properties"]
    assert properties["isReachable"] is value
    assert properties["reachabilityStatus"] == status
    (tmp_path / "sbom.json").write_text(json.dumps({"components": []}), encoding="utf-8")
    (tmp_path / "report.json").write_text(json.dumps([vulnerability]), encoding="utf-8")
    generate_html_report("sample", tmp_path / "sbom.json", tmp_path / "report.json", tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert f'>{status.replace("_", " ")}</span>' in html
    assert "test_reason" in html
    assert ">not reachable</span>" not in html


def test_sarif_preserves_call_evidence(tmp_path):
    steps = [{"symbol": "app.route", "file": str(tmp_path / "app.py"), "line": 2, "call_line": 4},
             {"symbol": "lib.danger", "file": str(tmp_path / "lib.py"), "line": 10}]
    sarif = vulns_to_sarif([{"cve": "TEST", "reachability": result("reachable", paths=[steps])}])
    locations = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 4


def test_cached_results_require_all_input_identity(tmp_path):
    cache.init_cache(tmp_path / "cache.db")
    context = cache.make_context("project-v1", ["diff-hash-v1"], dependency_digests=["library-v1"])
    cache.cache_reachability("pkg:pypi/lib@1", "CVE-1", result("reachable"), context)
    assert cache.get_cached_reachability("pkg:pypi/lib@1", "CVE-1", context)["status"] == "reachable"
    for other in [None, cache.make_context("project-v2", ["diff-hash-v1"], dependency_digests=["library-v1"]),
                  cache.make_context("project-v1", ["diff-hash-v2"], dependency_digests=["library-v1"]),
                  cache.make_context("project-v1", ["diff-hash-v1"], dependency_digests=["library-v2"]),
                  cache.make_context("project-v1", ["diff-hash-v1"], dependency_digests=["library-v1"], include_tests=True)]:
        assert cache.get_cached_reachability("pkg:pypi/lib@1", "CVE-1", other) is None


def test_expired_and_legacy_cache_rows_cannot_hide_changes(tmp_path, monkeypatch):
    path = tmp_path / "cache.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE cached_vulnerabilities (purl, cve, reachability)")
        db.execute("INSERT INTO cached_vulnerabilities VALUES ('p', 'c', '{}')")
    cache.init_cache(path)
    assert cache.get_cached_reachability("p", "c", "ctx") is None
    cache.cache_reachability("p", "c", result("no_path_found"), "ctx")
    now = cache.time.time()
    monkeypatch.setattr(cache.time, "time", lambda: now + cache.CACHE_TTL_SECONDS + 1)
    assert cache.get_cached_reachability("p", "c", "ctx") is None


def test_unknown_results_are_retried(tmp_path):
    cache.init_cache(tmp_path / "cache.db")
    cache.cache_reachability("p", "c", result(), "ctx")
    assert cache.get_cached_reachability("p", "c", "ctx") is None


def test_script_data_escapes_case_insensitive_html_end_tags():
    value = {"description": "</ScRiPt><script>bad()</script>"}
    encoded = _js_json(value)
    assert "<" not in encoded
    assert json.loads(encoded) == value
