"""Run independently labeled structural reachability cases without executing them.

Fixture cases are offline. Real library/application cases verify pinned clean
checkouts and fetch exact dependency sources and public fix diffs. Labels remain
in the input manifest; scanner results never modify the expected classifications.
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from scripts.analysis_session import AnalysisSession
from scripts.benchmark_real_apps import git
from scripts.reachability import check_reachability
from scripts.source_store import download_purl_source


def classification(truth, status):
    if truth not in {"present", "absent", "undetermined"}:
        raise ValueError("Invalid independent label")
    if status not in {"reachable", "no_path_found", "unknown", "unsupported"}:
        raise ValueError("Invalid analysis status")
    if status in {"unknown", "unsupported"}:
        return "expected_indeterminate" if truth == "undetermined" else "abstention"
    if truth == "undetermined":
        return "unsupported_conclusion"
    return {("present", "reachable"): "true_positive", ("present", "no_path_found"): "false_negative",
            ("absent", "reachable"): "false_positive", ("absent", "no_path_found"): "true_negative"}[(truth, status)]


def metrics(results):
    counts = Counter(item["classification"] for item in results)
    determinate = sum(item["truth"] != "undetermined" for item in results)
    decisions = sum(counts[key] for key in ("true_positive", "false_positive", "true_negative", "false_negative"))
    positive_calls = counts["true_positive"] + counts["false_positive"]
    negative_calls = counts["true_negative"] + counts["false_negative"]
    positives = sum(item["truth"] == "present" for item in results)
    negatives = sum(item["truth"] == "absent" for item in results)
    return {"cases": len(results), "classifications": dict(counts),
            "decision_coverage": decisions / determinate if determinate else None,
            "positive_precision": counts["true_positive"] / positive_calls if positive_calls else None,
            "negative_precision": counts["true_negative"] / negative_calls if negative_calls else None,
            "present_target_coverage": counts["true_positive"] / positives if positives else None,
            "absent_target_coverage": counts["true_negative"] / negatives if negatives else None,
            "incorrect_conclusions": sum(counts[key] for key in ("false_positive", "false_negative", "unsupported_conclusion"))}


def load_cases(path):
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    if data.get("schema_version") != 1 or not data.get("label_scope") or not data.get("label_method"):
        raise ValueError("Missing label schema, scope or provenance")
    seen = set()
    for case in data["cases"]:
        if not re.fullmatch(r"[a-z0-9_]+", case["id"]) or case["id"] in seen:
            raise ValueError("Invalid or duplicate case identity")
        seen.add(case["id"])
        if not case.get("label_reason") or not case.get("target") or not case.get("purl"):
            raise ValueError("Case lacks independent target/rationale")
        if case["truth"] not in {"present", "absent", "undetermined"}:
            raise ValueError("Invalid independent truth label")
        if case["kind"] not in {"fixture", "library", "application"}:
            raise ValueError("Invalid case kind")
        if case["kind"] != "fixture" and (not case.get("source_evidence") or not re.fullmatch(r"[a-f0-9]{40}", case.get("revision", ""))):
            raise ValueError("Real cases require source evidence and pinned revision")
    return data, hashlib.sha256(raw).hexdigest()


def _contained(base, relative):
    path = (base / relative).resolve()
    if base.resolve() not in path.parents:
        raise ValueError("Case path escapes its source root")
    return path


def _check_checkout(directory, revision):
    if git(directory, "rev-parse", "HEAD") != revision:
        raise ValueError(f"Unexpected checkout revision: {directory}")
    if git(directory, "status", "--porcelain"):
        raise ValueError(f"Modified checkout: {directory}")


def run_case(case, output, root):
    directory = output / case["id"]
    directory.mkdir()
    if case["kind"] == "application":
        app = _contained(root, case["project_path"])
        _check_checkout(app, case["revision"])
    else:
        app = directory / "app"
        app.mkdir()
        (app / "app.py").write_text(case["app_source"], encoding="utf-8")
    if case["kind"] == "fixture":
        lib = directory / "lib"
        lib.mkdir()
        for relative, text in case["library_files"].items():
            file = _contained(lib, relative)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text, encoding="utf-8")
        refs = ["https://github.com/corpus/fixture/commit/a"]
        with patch("scripts.reachability.get_diff", return_value=case["diff"]):
            report = check_reachability(refs, purl=case["purl"], cve=case.get("cve", ""),
                                        project_dir=app, library_source=lib)
    else:
        if case["kind"] == "library":
            lib = _contained(root, case["library_path"])
            _check_checkout(lib, case["revision"])
        else:
            lib = Path(download_purl_source(case["purl"], root / "data"))
        for item in case["source_evidence"]:
            owner = lib if case["kind"] == "library" else app
            if not _contained(owner, item["path"]).is_file():
                raise ValueError("Labeled source evidence is missing")
        report = check_reachability(case["references"], purl=case["purl"], cve=case.get("cve", ""),
                                    project_dir=app, library_source=lib, analysis_session=AnalysisSession())
    candidates = [item for item in report.get("function_results", []) if item["symbol"] == case["target"]]
    status = candidates[0]["status"] if len(candidates) == 1 else "unknown"
    (directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"id": case["id"], "kind": case["kind"], "target": case["target"],
            "truth": case["truth"], "target_status": status, "finding_status": report["status"],
            "classification": classification(case["truth"], status),
            "label_reason": case["label_reason"], "report": str(directory / "report.json"),
            "patch_sha256": report.get("patch_sha256", {}),
            "input_fingerprint": report.get("input_fingerprint")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="tests/corpus/cases.json")
    parser.add_argument("--output", required=True, help="New report directory")
    parser.add_argument("--offline", action="store_true", help="Run generated fixtures only")
    parser.add_argument("--min-coverage", type=float, default=0.0)
    args = parser.parse_args()
    if not 0 <= args.min_coverage <= 1:
        parser.error("--min-coverage must be between 0 and 1")
    root = Path.cwd().resolve()
    data, digest = load_cases(args.corpus)
    output = Path(args.output).resolve()
    if output.exists():
        parser.error("Choose a new output directory")
    output.mkdir(parents=True)
    results = []
    selected = [case for case in data["cases"] if not args.offline or case["kind"] == "fixture"]
    for case in selected:
        row = run_case(case, output, root)
        results.append(row)
        print(f"{row['id']}: label={row['truth']}, actual={row['target_status']}, {row['classification']}", flush=True)
    summary = {"corpus_sha256": digest, "label_scope": data["label_scope"], "label_method": data["label_method"],
               "excluded_cases": len(data["cases"]) - len(selected), "metrics": metrics(results),
               "by_kind": {kind: metrics([row for row in results if row["kind"] == kind]) for kind in sorted({row["kind"] for row in results})},
               "results": results, "limitations": "A source-reviewed regression corpus; not an ecosystem accuracy estimate."}
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary["metrics"], indent=2))
    coverage = summary["metrics"]["decision_coverage"]
    return 1 if summary["metrics"]["incorrect_conclusions"] or (coverage or 0) < args.min_coverage else 0


if __name__ == "__main__":
    raise SystemExit(main())
