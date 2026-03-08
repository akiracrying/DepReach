# DepReach

**DepReach** is a [Software Composition Analysis](https://owasp.org/www-project-software-composition-analysis/) (SCA) tool that goes beyond listing CVEs: it tells you whether vulnerable code is **reachable** from your project. It builds call graphs, maps fixes from GitHub diffs to affected functions, and marks issues as reachable or not — so you can prioritize what actually matters.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://pypi.org/project/depreach/)

## Features

- **SBOM** — CycloneDX via cyclonedx-py (Python) or cdxgen (Docker)
- **Vulnerability lookup** — Local VDB (e.g. appthreat-vulnerability-db)
- **Reachability** — Call graph + AST + GitHub diff → which vuln code is reachable
- **Caching** — SQLite cache for reachability results
- **HTML report** — Interactive dependency graph, filter by package, zoom, “hide clean”
- **SARIF** — Output for ASPM / Code Scanning with reachability in `result.properties`

## Installation

DepReach is available on [PyPI](https://pypi.org/project/depreach/). Requires **Python 3.10+**:

```bash
pip install depreach
```
Or install from source:

```bash
git clone https://github.com/akiracrying/DepReach.git && cd DepReach
pip install .
```
## Quick start

```bash
depreach -i /path/to/your/project -o report.json
```

Reports are written to `reports/<project_name>/` (JSON, SBOM, HTML). Use `--sarif <file>` to also emit SARIF 2.1.

## Usage

```bash
depreach -i <input_dir> -o report.json [options]
```

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Source code directory (required) |
| `-o`, `--output` | Report filename; output dir is `reports/<project_name>/` |
| `--skip-update` | Skip updating the vulnerability database |
| `--cache` | Cache reachability results in SQLite |
| `-j`, `--jobs` | Parallel jobs for reachability (default: 6) |
| `--ignore` | Comma-separated package names to ignore (e.g. `flask,requests`) |
| `--sarif` | Write SARIF 2.1 file for ASPM/Code Scanning |

**Exit codes:** `0` = no vulns, `1` = vulns but none reachable, `2` = at least one reachable.

**Example**

```bash
depreach -i ./my-app -o report.json --cache --ignore "flask" --sarif report.sarif
```

## Output

| Artifact | Path | Description |
|----------|------|-------------|
| JSON report | `reports/<name>/report.json` | Vulns with CVE, severity, description, references, reachability |
| SBOM | `reports/<name>/<name>_sbom.json` | CycloneDX SBOM |
| HTML report | `reports/<name>/report.html` | Interactive graph, filter by package, zoom |
| SARIF | path from `--sarif` | SARIF 2.1 with `isReachable` in result properties (for ASPM) |

## Use as a library

```python
from depreach import run

vulns, exit_code = run(
    input_dir="./my-app",
    output_file="report.json",
    skip_update=False,
    cache=True,
    jobs=6,
    ignore="flask,requests",
    sarif_path="report.sarif",
)
# exit_code: 0 = ok, 1 = vulns, 2 = reachable vulns
```

## License

MIT. See [LICENSE](LICENSE).
