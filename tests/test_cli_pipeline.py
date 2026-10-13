import json

import pytest

import depreach
from scripts.reachability_result import result


@pytest.mark.parametrize("state, exit_code", [(None, 0), ("no_path_found", 1), ("reachable", 2), ("unknown", 3), ("unsupported", 3)])
def test_pipeline_reports_and_exit_code(tmp_path, monkeypatch, state, exit_code):
    monkeypatch.chdir(tmp_path)
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text("def run(): pass\n", encoding="utf-8")
    (app / "requirements.txt").write_text("demo==1\n", encoding="utf-8")

    def bom(_, output):
        with open(output, "w", encoding="utf-8") as stream:
            json.dump({"bomFormat": "CycloneDX", "components": [{"name": "demo", "purl": "pkg:pypi/demo@1"}]}, stream)
        return True

    monkeypatch.setattr(depreach, "generate_sbom_python", bom)
    monkeypatch.setattr(depreach, "_run_with_timed_status", lambda _, fn, **kwargs: fn())
    monkeypatch.setattr(depreach, "show_logo", lambda: True)
    monkeypatch.setattr(depreach, "print_vulns", lambda _: None)
    monkeypatch.setattr(depreach, "prepare_source_context", lambda *a, **kw: {"sources": [], "issues": [], "complete": True, "fingerprint": "fixture"})
    findings = [{"cve": "CVE-X", "package": "demo", "purl": "pkg:pypi/demo@1", "references": []}] if state else []
    monkeypatch.setattr(depreach, "check_vulnerabilities_from_sbom", lambda *args: findings)

    def analyze(*args, **kwargs):
        assert kwargs["project_dir"] == str(app)
        assert kwargs["library_source"] == str(app)
        return result(state)

    monkeypatch.setattr(depreach, "check_reachability", analyze)
    _, actual = depreach.run(str(app), skip_update=True, sarif_path="result.sarif", package_sources={"pkg:pypi/demo@1": str(app)})
    assert actual == exit_code
    assert (tmp_path / "reports/app/report.html").is_file()
    stored = json.loads((tmp_path / "reports/app/report.json").read_text(encoding="utf-8"))
    sarif = json.loads((tmp_path / "result.sarif").read_text(encoding="utf-8"))
    if state:
        assert stored[0]["reachability"]["status"] == state
        assert sarif["runs"][0]["results"][0]["properties"]["reachabilityStatus"] == state


def test_invalid_directory_or_jobs_fails_before_scan(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        depreach.run(str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="at least 1"):
        depreach.run(str(tmp_path), jobs=0)
