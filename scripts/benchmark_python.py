"""Reproducible reachability probes against pinned, real Python libraries.

Run: python -m scripts.benchmark_python --clone
Downloads source and fix diffs only. It never imports or runs the target code.
This is a small regression corpus, not an ecosystem accuracy benchmark.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

from scripts.reachability import check_reachability
from scripts.html_report import generate_html_report
from scripts.sarif_report import write_sarif

LIBRARIES = {
    "requests": {
        "repo": "https://github.com/psf/requests.git", "tag": "v2.30.0",
        "revision": "2ad18e0e10e7d7ecd5384c378f25ec8821a10a29",
        "purl": "pkg:pypi/requests@2.30.0", "cve": "CVE-2023-32681",
        "fix": "https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5",
        "advisory": "https://github.com/advisories/GHSA-j8r2-6x86-q33q",
    },
    "werkzeug": {
        "repo": "https://github.com/pallets/werkzeug.git", "tag": "2.3.7",
        "revision": "3c2ba3da894c0767dd6dde7b2707cac65bad5422",
        "purl": "pkg:pypi/werkzeug@2.3.7", "cve": "CVE-2024-49766",
        "fix": "https://github.com/pallets/werkzeug/commit/2767bcb10a7dd1c297d812cc5e6d11a474c1f092",
        "advisory": "https://github.com/advisories/GHSA-f9vj-2wh5-fj8j",
    },
}
CASES = [
    ("requests_top_level", "requests", "import requests\nrequests.get('https://example.invalid')\n", "reachable"),
    ("requests_redirects_disabled", "requests", "import requests\nrequests.get('https://example.invalid', allow_redirects=False)\n", "reachable"),
    ("requests_dynamic", "requests", "import requests\ndef run(method):\n    getattr(requests, method)('https://example.invalid')\n", "unknown"),
    ("requests_unused", "requests", "def run():\n    return 1\n", "no_path_found"),
    ("werkzeug_alias", "werkzeug", "from werkzeug.security import safe_join as join\ndef run(path):\n    return join('public', path)\n", "reachable"),
    ("werkzeug_wrapper", "werkzeug", "from werkzeug.utils import send_from_directory\ndef run(path):\n    return send_from_directory('public', path, {})\n", "reachable"),
    ("werkzeug_same_name", "werkzeug", "def safe_join(directory, path):\n    return directory\ndef run(path):\n    return safe_join('public', path)\n", "no_path_found"),
    ("werkzeug_dynamic", "werkzeug", "import werkzeug.security\ndef run(name, path):\n    return getattr(werkzeug.security, name)('public', path)\n", "unknown"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone", action="store_true")
    parser.add_argument("--workspace", default="tests_local")
    parser.add_argument("--output", default="reports/python-benchmark")
    args = parser.parse_args()
    workspace, output = Path(args.workspace).resolve(), Path(args.output).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    for name, info in LIBRARIES.items():
        directory = workspace / name
        if not directory.exists() and args.clone:
            subprocess.run(["git", "clone", "--depth", "1", "--branch", info["tag"], info["repo"], str(directory)], check=True)
        revision = subprocess.check_output(["git", "-c", f"safe.directory={directory.as_posix()}", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
        if revision != info["revision"]:
            raise RuntimeError(f"Unexpected revision for {name}: {revision}")
        if subprocess.check_output(["git", "-c", f"safe.directory={directory.as_posix()}", "-C", str(directory), "status", "--porcelain"], text=True).strip():
            raise RuntimeError(f"Benchmark source is modified: {directory}")
    summaries = []
    for name, library, source, expected in CASES:
        app = workspace / "benchmark_apps" / name
        app.mkdir(parents=True, exist_ok=True)
        (app / "app.py").write_text(source, encoding="utf-8")
        info = LIBRARIES[library]
        start = time.perf_counter()
        report = check_reachability([info["fix"]], purl=info["purl"], project_dir=app, library_source=workspace / library)
        elapsed = round(time.perf_counter() - start, 3)
        findings = [{"package": library, "purl": info["purl"], "installed_version": info["purl"].split("@")[1],
                     "cve": info["cve"], "references": [info["fix"], info["advisory"]], "reachability": report}]
        case_dir = output / name
        case_dir.mkdir(exist_ok=True)
        (case_dir / "report.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
        (case_dir / "sbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"type": "library", "name": library, "version": findings[0]["installed_version"], "purl": info["purl"]}]}), encoding="utf-8")
        generate_html_report(name, case_dir / "sbom.json", case_dir / "report.json", case_dir / "report.html")
        write_sarif(findings, str(case_dir / "report.sarif"))
        summary = {"case": name, "expected": expected, "actual": report["status"], "seconds": elapsed,
                   "passed": report["status"] == expected, "revision": info["revision"],
                   "paths": [[step["symbol"] for step in path] for path in report["paths"]],
                   "reasons": report["reasons"], "patch_sha256": report.get("patch_sha256", {})}
        summaries.append(summary)
        print(f"{name}: {summary['actual']} (expected {expected}) {elapsed:.3f}s", flush=True)
    (output / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    return 0 if all(item["passed"] for item in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
