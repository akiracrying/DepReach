
import re
import sys
import argparse
import os
import time
import threading
import warnings
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from scripts.bom import generate_sbom_python
from scripts.detect_type import detect_project_type
from scripts.reachability import check_reachability, extract_library_function_calls, build_call_graph
from scripts.update_db import update_vdb
from scripts.composition_analysis import check_vulnerabilities_from_sbom, count_sbom_components
from scripts.cache import init_cache, get_cached_reachability, cache_reachability
from scripts.html_report import generate_html_report
from scripts.sarif_report import write_sarif

from rich.console import Console
from rich.table import Table
from rich import box
from rich.markup import escape

warnings.filterwarnings("ignore", category=DeprecationWarning)

logging.basicConfig(
    filename="depreach.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()
MAX_REACHABILITY_WORKERS = 6


def _run_with_timed_status(msg_template: str, task_fn, spinner: str = "dots", done_msg: str = None):
    """Runs task_fn in a thread and shows status with elapsed seconds on the right.
    If done_msg is set, prints a permanent line when the task completes."""
    result = [None]
    exc = [None]

    def run():
        try:
            result[0] = task_fn()
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=run)
    t.start()
    start = time.time()
    with console.status("", spinner=spinner, spinner_style="dim") as status:
        while t.is_alive():
            elapsed = int(time.time() - start)
            status.update(f"{msg_template} [dim]({elapsed}s)[/dim]")
            time.sleep(0.5)
        t.join()
    elapsed = int(time.time() - start)
    if done_msg:
        console.print(f"[dim]{done_msg} in {elapsed}s[/dim]")
    if exc[0]:
        raise exc[0]
    return result[0]


def show_logo():
    logo_dep = r"""
______ ___________              
|  _  \  ___| ___ \             
| | | | |__ | |_/ /             
| | | |  __||  __/              
| |/ /| |___| |                 
|___/ \____/\_|  
  """.rstrip()
    logo_reach = r"""
______ _____  ___  _____  _   _ 
| ___ \  ___|/ _ \/  __ \| | | |
| |_/ / |__ / /_\ \ /  \/| |_| |
|    /|  __||  _  | |    |  _  |
| |\ \| |___| | | | \__/\| | | |
\_| \_\____/\_| |_/\____/\_| |_/
    """.rstrip()

    console.print(logo_dep + "  " + logo_reach)
    return True


def format_description(desc: str) -> str:
    if not desc:
        return ""
    try:
        desc = desc.encode().decode(r"unicode_escape")
    except Exception:
        pass
    clean = re.sub(r'`+', '', desc)
    clean = re.sub(r'\*+', '', clean)
    clean = re.sub(r'#+\s*', '', clean)
    clean = re.sub(r'\[.*?\]\(.*?\)', '', clean)
    clean = re.sub(r'\n{2,}', '\n', clean)
    first_line = clean.split('\n')[0].strip()
    return escape(first_line)

def print_vulns(vulns: list[dict]):
    console = Console(width=300)

    table = Table(title="Vulnerabilities Report", box=box.SQUARE, padding=(0, 1), show_lines=True)

    if not vulns:
        console.print("[bold yellow]No vulnerabilities found.[/bold yellow]")
        return

    columns = [
        ("package", "Package", None, True),
        ("installed_version", "Installed version", None, True),
        ("purl", "PURL", None, True),
        ("cve", "CVE", None, True),
        ("severity", "Severity", None, True),
        ("score", "CVSS Score", None, True),
        ("description", "Description", 60, False),
        ("affected_version", "Affected version", None, True),
        ("CWE", "CWE", None, True),
        ("references", "References", None, False),
        ("reachable", "Reachable?", 10, True),
    ]

    for key, header, width, nowrap in columns:
        table.add_column(
            header,
            style="bold",
            width=width,
            no_wrap=nowrap,
            overflow="ellipsis" if nowrap else "fold",
        )

    MAX_REFS_TO_SHOW = 3

    for vuln in vulns:
        row = []
        for key, *_ in columns:
            if key == "description":
                val = format_description(vuln.get(key, ""))

            elif key == "references":
                refs = vuln.get(key, [])
                shown = refs[:MAX_REFS_TO_SHOW]
                rest = len(refs) - MAX_REFS_TO_SHOW
                val = "\n".join(f"[link={url}]{url}[/link]" for url in shown)
                if rest > 0:
                    val += f"\n...and {rest} more"

            elif key == "reachable":
                reach = vuln.get("reachability", {})
                if not reach:
                    val = "[dim]—[/dim]"
                else:
                    lines = []
                    for i, (url, info) in enumerate(reach.items(), 1):
                        if info != "Unknown":
                            try:
                                mark = "[green]✅[/green]" if info.get("is_reachable") else "[red]❌[/red]"
                            except Exception:
                                status = reach.get("is_reachable")
                                if status is True:
                                    mark = "[green]✅[/green]"
                                elif status is False:
                                    mark = "[red]❌[/red]"
                                else:
                                    mark = "Unknown"
                        else:
                            mark = "Unknown"
                        lines.append(f"{i}. {mark}")
                    val = "\n".join(lines)

            else:
                val = str(vuln.get(key, ""))
            row.append(val)
        table.add_row(*row)

    console.print(table)

def dep_reach(args):

    src_dir = args.input
    output_file = args.output
    skip_update = args.skip_update

    logger.info(
        "DepReach run started: src_dir=%s, output=%s, skip_update=%s, cache=%s, jobs=%s",
        src_dir,
        output_file,
        skip_update,
        args.cache,
        args.jobs,
    )

    project_types = detect_project_type(src_dir)
    if not project_types:
        project_types = ["universal"]
    if "python" not in project_types:
        console.print(
            "[red]Docker/cdxgen is temporarily disabled.[/red] Only Python projects are supported for testing.\n"
            "  → Use a directory with requirements.txt, pyproject.toml, poetry.lock, or Pipfile."
        )
        raise SystemExit(1)

    project_name = os.path.basename(os.path.abspath(os.path.normpath(src_dir)))
    output_dir = os.path.join("reports", project_name)
    report_filename = os.path.basename(output_file) or "report.json"
    output_file = os.path.join(output_dir, report_filename)
    sbom_file = os.path.join(output_dir, f"{project_name}_sbom.json")
    os.makedirs(output_dir, exist_ok=True)

    if show_logo():
        console.print()
        if not skip_update:
            _run_with_timed_status(
                "[bold]Updating Vulnerabilities Database[/bold]",
                lambda: update_vdb(silent=True),
                done_msg="VDB updated",
            )
        logger.info("Generating SBOM (Python) for %s -> %s", src_dir, sbom_file)
        _run_with_timed_status(
            "[bold]Generating SBOM…[/bold]",
            lambda: generate_sbom_python(src_dir, sbom_file),
            done_msg="SBOM generated",
        )
        logger.info("SBOM generation finished, checking file %s", sbom_file)
        if not os.path.exists(sbom_file):
            console.print(
                "[red]SBOM was not generated.[/red] Check that the project has requirements.txt, poetry.lock, or Pipfile."
            )
            raise SystemExit(1)
        logger.info("Starting vulnerability scan from SBOM %s", sbom_file)
        n_comp = count_sbom_components(sbom_file)
        est_lo = max(1, n_comp // 150)
        est_hi = max(2, n_comp // 60)
        est_str = f"~{est_lo}-{est_hi} min" if n_comp > 100 else ""
        scan_msg = f"[bold green]Scanning {n_comp:,} components…[/bold green]" + (f" [dim](est. {est_str})[/dim]" if est_str else "")
        vulns = _run_with_timed_status(
            scan_msg,
            lambda: check_vulnerabilities_from_sbom(src_dir, sbom_file),
            spinner="line",
            done_msg="Scanning completed",
        )

        ignore_packages = {s.strip().lower() for s in (getattr(args, "ignore", "") or "").split(",") if s.strip()}
        if ignore_packages:
            before = len(vulns)
            vulns = [v for v in vulns if (v.get("package") or "").lower() not in ignore_packages]
            if before != len(vulns):
                logger.info("Ignored %d vulns for packages: %s", before - len(vulns), ignore_packages)

        use_cache = args.cache

        if use_cache:
            init_cache()

        if vulns:
            def _build_graph():
                return extract_library_function_calls(src_dir), build_call_graph(src_dir)
            project_functions, call_graph = _run_with_timed_status(
                "[bold]Building call graph…[/bold]",
                _build_graph,
                spinner="line",
                done_msg="Call graph ready",
            )
            logger.info(
                "Vulnerabilities found: %d, project functions: %d, call graph nodes: %d",
                len(vulns),
                len(project_functions),
                len(call_graph),
            )

            to_analyze = []
            cached_count = 0
            for idx, vuln in enumerate(vulns):
                if use_cache:
                    cached = get_cached_reachability(vuln["purl"], vuln["cve"])
                    if cached:
                        vuln["reachability"] = cached
                        cached_count += 1
                        print(f"[cache] Using cached result for {vuln['purl']} (CVE: {vuln['cve']})")
                        continue
                to_analyze.append((idx, vuln))

            logger.info(
                "Reachability phase: total=%d, cached=%d, to_analyze=%d",
                len(vulns),
                cached_count,
                len(to_analyze),
            )

            if to_analyze:
                def analyze_one(idx_vuln):
                    idx, vuln = idx_vuln
                    report = check_reachability(
                        vuln["references"], project_functions, call_graph,
                        purl=vuln["purl"],
                    )
                    return idx, report

                reach_start = time.time()
                with console.status("", spinner="line") as status:
                    done = 0
                    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
                        futures = {executor.submit(analyze_one, item): item for item in to_analyze}
                        for future in as_completed(futures):
                            idx, report = future.result()
                            vulns[idx]["reachability"] = report
                            if use_cache:
                                cache_reachability(vulns[idx]["purl"], vulns[idx]["cve"], report)
                            done += 1
                            elapsed = int(time.time() - reach_start)
                            status.update(f"[bold green]Analyzing reachability ({done}/{len(to_analyze)})…[/bold green] [dim]({elapsed}s)[/dim]")
                reach_elapsed = int(time.time() - reach_start)
                console.print(f"[dim]Reachability analysis completed in {reach_elapsed}s[/dim]")

        print_vulns(vulns)

        with open(output_file, "w", encoding="utf-8") as f:
            import json
            json.dump(vulns, f, indent=2, ensure_ascii=False)

        # HTML report next to JSON report
        html_report_file = os.path.join(output_dir, "report.html")
        try:
            generate_html_report(project_name, sbom_file, output_file, html_report_file)
            console.print(f"[dim]HTML report saved to {html_report_file}[/dim]")
        except Exception as e:
            logger.exception("Failed to generate HTML report: %s", e)

        sarif_path = getattr(args, "sarif", None)
        if sarif_path:
            try:
                write_sarif(vulns, sarif_path, project_uri=os.path.abspath(src_dir))
                console.print(f"[dim]SARIF report saved to {sarif_path}[/dim]")
            except Exception as e:
                logger.exception("Failed to write SARIF: %s", e)

        def _is_reachable(v):
            r = v.get("reachability") or {}
            if not isinstance(r, dict):
                return False
            for info in r.values():
                if isinstance(info, dict) and info.get("is_reachable"):
                    return True
            return False

        has_reachable = any(_is_reachable(v) for v in vulns) if vulns else False
        if not vulns:
            return (vulns, 0)
        return (vulns, 2 if has_reachable else 1)
    return ([], 0)


def run(
    input_dir: str,
    output_file: str = "report.json",
    *,
    skip_update: bool = False,
    cache: bool = False,
    jobs: int = None,
    ignore: str = "",
    sarif_path: str = None,
):
    """Run DepReach scan programmatically. Returns (vulns_list, exit_code).
    exit_code: 0 = no vulns, 1 = vulns but none reachable, 2 = at least one reachable."""
    if jobs is None:
        jobs = MAX_REACHABILITY_WORKERS
    ns = argparse.Namespace(
        input=input_dir,
        output=output_file,
        skip_update=skip_update,
        cache=cache,
        jobs=jobs,
        ignore=ignore or "",
        sarif=sarif_path or "",
    )
    return dep_reach(ns)


def main():
    """CLI entry point (for pip-installed depreach and programmatic use)."""
    if sys.stdin.isatty():
        fd = os.open(os.devnull, os.O_RDONLY)
        os.dup2(fd, 0)
        os.close(fd)

    parser = argparse.ArgumentParser(description="DepReach — Next Gen SCA analyzer")
    parser.add_argument("--input", "-i", required=True, help="Path to source code directory")
    parser.add_argument("--output", "-o", required=True, help="Path to output result file (JSON)")
    parser.add_argument("--skip-update", action="store_true", help="Skip updating the vulnerability database")
    parser.add_argument("--cache", action="store_true", help="Cache reachability results in local SQLite")
    parser.add_argument("--jobs", "-j", type=int, default=MAX_REACHABILITY_WORKERS, help="Parallel jobs for reachability analysis (default: %(default)s)")
    parser.add_argument("--ignore", type=str, default="", help="Comma-separated package names to ignore (e.g. flask,requests)")
    parser.add_argument("--sarif", type=str, default="", help="Write SARIF 2.1 file (reachability in result.properties) for ASPM/Code Scanning")

    args = parser.parse_args()
    start_time = time.time()
    vulns, exit_code = dep_reach(args)
    elapsed = time.time() - start_time
    console.print(f"[bold]Finished in {elapsed:.1f}s[/bold]")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())