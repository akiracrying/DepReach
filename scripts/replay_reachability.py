"""Reanalyze an existing SCA finding set; no VDB update or inventory changes."""
import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scripts.reachability import check_reachability
from scripts.html_report import generate_html_report
from scripts.sarif_report import write_sarif


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", required=True, help="New directory, to preserve the original report")
    parser.add_argument("--dependency-source", action="append", default=[])
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    source, output = Path(args.report).resolve(), Path(args.output).resolve()
    if output.exists():
        parser.error("Output already exists; choose a new directory")
    data = json.loads(source.read_text(encoding="utf-8"))
    before = [item.get("reachability", {}) for item in data]
    def analyze(index):
        item = data[index]
        return index, check_reachability(item.get("references", []), purl=item["purl"],
            cve=item["cve"], project_dir=args.project, dependency_sources=args.dependency_source)
    output.mkdir(parents=True)
    changes = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(analyze, i) for i in range(len(data))]
        for future in as_completed(futures):
            index, report = future.result()
            item = data[index]
            changes.append({"purl": item["purl"], "cve": item["cve"],
                "before": before[index].get("status"), "after": report["status"],
                "mapped_before": len({m["symbol"] for m in before[index].get("mappings", [])}),
                "mapped_after": len({m["symbol"] for m in report.get("mappings", [])})})
            item["reachability"] = report
            print(f"{len(changes)}/{len(data)} {item['package']} {item['cve']}: {report['status']}", flush=True)
    (output / "report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    summary = {"baseline": str(source), "before": dict(Counter(x.get("status") for x in before)),
               "after": dict(Counter(x["reachability"]["status"] for x in data)),
               "mapped_findings_before": sum(bool(x.get("mappings")) for x in before),
               "mapped_findings_after": sum(bool(x["reachability"].get("mappings")) for x in data),
               "changes": sorted(changes, key=lambda x: (x["purl"], x["cve"]))}
    (output / "comparison.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Prefer the original full SBOM; retain a finding-only inventory if unavailable.
    candidates = list(source.parent.glob("*_sbom.json"))
    sbom = json.loads(candidates[0].read_text(encoding="utf-8")) if len(candidates) == 1 else {
        "components": [{"name": x["package"], "version": x.get("installed_version"), "purl": x["purl"]} for x in data]}
    (output / "sbom.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    generate_html_report(Path(args.project).name, output / "sbom.json", output / "report.json", output / "report.html")
    write_sarif(data, str(output / "report.sarif"))
    print(json.dumps({k: v for k, v in summary.items() if k != "changes"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
