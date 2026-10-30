import json
import re

from scripts.html_report import generate_html_report


def test_overview_defaults_and_instance_counts(tmp_path):
    components = [{"name": "demo", "version": "1", "purl": "pkg:npm/demo@1"}] * 2
    findings = [{"package": "demo", "installed_version": "1", "cve": "CVE-DEMO", "purl": "pkg:npm/demo@1", "severity": "HIGH", "reachability": {"status": "unsupported", "is_reachable": None}}]
    sbom, report, output = (tmp_path / name for name in ("sbom.json", "report.json", "report.html"))
    sbom.write_text(json.dumps({"components": components}), encoding="utf-8")
    report.write_text(json.dumps(findings), encoding="utf-8")
    generate_html_report("demo", sbom, report, output)
    html = output.read_text(encoding="utf-8")
    assert '<details class="card" id="dependency-map">' in html
    assert 'id="hide-clean-nodes" checked' in html
    assert 'id="finding-search"' in html and 'id="status-filter"' in html
    assert 'data-status="unsupported"' in html
    data = json.loads(re.search(r'const graphData = (.*);', html)[1])
    assert len(data["nodes"]) == 2
    assert data["nodes"][1]["instanceCount"] == 2
    assert len(data["links"]) == 1
    assert 'Lines connect packages to the project' in html
