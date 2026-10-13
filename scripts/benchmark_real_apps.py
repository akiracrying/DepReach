"""Analyze selected real CVEs in unchanged, pinned application repositories.

This is a focused reachability experiment, not a full vulnerability scan or an
accuracy score. Advisory identities/fix references are supplied explicitly, so
this experiment does not need VDB. Full CLI instructions: docs/REAL_APPS.md.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

from scripts.bom import generate_sbom_python
from scripts.html_report import generate_html_report
from scripts.reachability import check_reachability
from scripts.sarif_report import write_sarif
from scripts.source_store import download_purl_source

APPLICATIONS = {
    "whoogle-search": {
        "repository": "https://github.com/benbusby/whoogle-search.git",
        "tag": "v0.8.2",
        "revision": "5ae9160d380f7188a281b70b5665e51937e5f467",
    },
    "linkding": {
        "repository": "https://github.com/sissbruecker/linkding.git",
        "tag": "v1.20.0",
        "revision": "f071423f1e29f2781b9dc31c2ce8cfce9b8a5a50",
    },
}
CASES = [
    {
        "application": "whoogle-search", "purl": "pkg:pypi/requests@2.28.2",
        "cve": "CVE-2023-32681",
        "fix": "https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5",
        "advisory": "https://github.com/advisories/GHSA-j8r2-6x86-q33q",
        "intermediates": [],
    },
    {
        "application": "whoogle-search", "purl": "pkg:pypi/werkzeug@2.2.3",
        "cve": "CVE-2024-49766",
        "fix": "https://github.com/pallets/werkzeug/commit/2767bcb10a7dd1c297d812cc5e6d11a474c1f092",
        "advisory": "https://github.com/advisories/GHSA-f9vj-2wh5-fj8j",
        "intermediates": ["pkg:pypi/flask@2.2.3"],
    },
    {
        "application": "linkding", "purl": "pkg:pypi/requests@2.31.0",
        "cve": "CVE-2024-35195",
        "fix": "https://github.com/psf/requests/commit/a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac",
        "advisory": "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
        "intermediates": [],
    },
]


def git(directory, *args):
    # Scoped to this explicit checkout; do not change global safe.directory.
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={directory.as_posix()}", "-C", str(directory), *args],
        text=True, timeout=120,
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone", action="store_true", help="Clone missing repositories")
    parser.add_argument("--prepare-only", action="store_true", help="Verify revisions and inventories only")
    parser.add_argument("--workspace", default="tests_local/real_apps")
    parser.add_argument("--output", default="reports/real-apps-focused")
    args = parser.parse_args()
    workspace, output = Path(args.workspace).resolve(), Path(args.output).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    inventories = {}
    for name, info in APPLICATIONS.items():
        directory = workspace / name
        if not directory.exists() and args.clone:
            subprocess.run(["git", "clone", "--depth", "1", "--branch", info["tag"],
                            "--single-branch", info["repository"], str(directory)], check=True, timeout=180)
        if git(directory, "rev-parse", "HEAD") != info["revision"]:
            raise RuntimeError(f"Unexpected revision: {directory}")
        if git(directory, "status", "--porcelain"):
            raise RuntimeError(f"Modified application checkout: {directory}")
        report_dir = output / name
        report_dir.mkdir(exist_ok=True)
        sbom = report_dir / "sbom.json"
        if not generate_sbom_python(directory, sbom):
            raise RuntimeError(f"Inventory generation failed: {name}")
        components = json.loads(sbom.read_text(encoding="utf-8"))["components"]
        if any(not c.get("purl") or not c.get("version") for c in components):
            raise RuntimeError(f"Unresolved inventory: {name}")
        inventories[name] = {c["purl"] for c in components}
        print(f"{name} {info['tag']}: {len(components)} inventory entries", flush=True)
    if args.prepare_only:
        return 0
    summary = []
    findings = {name: [] for name in APPLICATIONS}
    for case in CASES:
        name = case["application"]
        for purl in [case["purl"], *case["intermediates"]]:
            if purl not in inventories[name]:
                raise RuntimeError(f"Selected package is absent from inventory: {name}, {purl}")
        start = time.perf_counter()
        intermediate_sources = [download_purl_source(p, "data") for p in case["intermediates"]]
        result = check_reachability(
            [case["fix"]], purl=case["purl"], cve=case["cve"],
            project_dir=workspace / name, dependency_sources=intermediate_sources,
        )
        seconds = round(time.perf_counter() - start, 3)
        package, version = case["purl"].removeprefix("pkg:pypi/").split("@")
        findings[name].append({
            "package": package, "installed_version": version, "purl": case["purl"],
            "cve": case["cve"], "references": [case["advisory"], case["fix"]],
            "reachability": result,
            "experiment": "Selected advisory; no full VDB search; exploitability not assessed",
        })
        summary.append({
            **case, **APPLICATIONS[name], "status": result["status"], "seconds": seconds,
            "paths": [[step["symbol"] for step in path] for path in result["paths"]],
            "reasons": result["reasons"],
        })
        report_dir = output / name
        (report_dir / "report.json").write_text(json.dumps(findings[name], indent=2), encoding="utf-8")
        generate_html_report(f"{name} - selected advisories only", report_dir / "sbom.json",
                             report_dir / "report.json", report_dir / "report.html")
        write_sarif(findings[name], str(report_dir / "report.sarif"))
        print(f"{name} {case['cve']}: {result['status']} ({seconds}s)", flush=True)
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Success means the experiment completed, not that applications are safe.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
