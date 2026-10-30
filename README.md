# DepReach

**DepReach** is a Python Software Composition Analysis (SCA) tool. It identifies vulnerable package versions, maps fix patches to functions and supported literal data in the versioned dependency source, and reports possible static call paths from your application.

A reachable **patch-associated function** is evidence for triage, not proof of exploitability. Missing source, unmatched patches, and unsupported dynamic behavior remain **unknown**, rather than being labeled safe. See [analysis contract and limitations](docs/PYTHON_REACHABILITY.md).

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://pypi.org/project/depreach/)

## Features

- **SBOM** — CycloneDX via cyclonedx-py for Python; an additional npm lockfile command preserves installation instances
- **npm SCA preview** — `python -m scripts.npm_inventory --input APP --output NEW_REPORT_DIR --scan`; [scope and commands](docs/NPM.md). `--sources` verifies package bytes; `--syntax` extracts JS/TS AST facts (node extra). `--resolve-imports` audits Node module paths and implies source/syntax stages. JS/TS reachability is not implemented yet
- **Vulnerability lookup** — Local VDB (e.g. appthreat-vulnerability-db)
- **Reachability** — Qualified Python symbols, scoped imports and re-exports, simple instances and inheritance, exact old-side patch context, and call-chain evidence
- **Caching** — SQLite cache keyed by project and dependency source contents, patch contents, analysis options and analyzer version
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

Reports are written to `reports/<project_name>/` (JSON, SBOM, HTML). Use `--sarif <file>` to also emit SARIF 2.1 with call paths.

For inventory generation, provide a resolved virtualenv, `poetry.lock`, `Pipfile`/`Pipfile.lock`, or pinned `requirements.txt`. A bare `pyproject.toml` or `uv.lock` is not supported yet. A requirements-only inventory may omit transitive dependencies; use the resolved environment when complete inventory matters. The scanner rejects missing package identities and unversioned inventory entries. VDB must contain both a populated index and vulnerability data; an incomplete database is a scan error.

The vulnerable package's exact PyPI source distribution is downloaded and checked against its registry SHA256. Sources for declared intermediate dependencies are prepared automatically; missing transitive versions remain explicit blockers. Additional source roots can also be supplied explicitly. No source package build/install hook runs during reachability analysis. Inventorying an existing virtualenv can invoke that environment's interpreter through cyclonedx-py; use environments you trust.

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
| `--sarif` | Write SARIF 2.1 with status, limitations and call flows |
| `--dependency-source` | Additional dependency source root; repeat for intermediary libraries |
| `--package-source` | `pkg:pypi/name@version=path`: use explicitly supplied source for a package version |
| `--include-tests` | Include first-party tests in analysis roots (excluded by default) |
| `--target-environment` | JSON marker environment overrides for pinned requirements; defaults to scanner environment |
| `--requirements` | Explicit requirements file, relative to the input directory or absolute |
| `--all-environments` | Retain marker alternatives; conflicting versions cannot form one resolved runtime |

**Scan exit codes:** `0` = no known vulnerabilities in the supplied inventory; `1` = vulnerabilities, with no modeled path found for every finding; `2` = at least one reachable patch-associated function; `3` = inconclusive analysis with no reachable finding; `4` = scan/export failure. Argument syntax errors use argparse's standard exit code 2.

`1` is not a safety verdict. JSON uses `status` and a nullable `is_reachable`; `unknown` and `unsupported` are never exported as `false`. CLI, HTML and SARIF share the same semantics. This changes the previous JSON reachability shape; old cache records are ignored.

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
# exit_code: 0 = no CVEs, 1 = no modeled path, 2 = reachable, 3 = inconclusive
```

Reviewed vulnerability models remain separate from patch candidates. JSON includes
mapping evidence levels, unsupported change kinds and explicit source blockers.
See [the labeled evaluation corpus](docs/EVALUATION.md) for measured coverage
and known abstentions; these measurements do not establish ecosystem accuracy.

Remaining work and acceptance criteria: [next implementation steps](docs/NEXT_STEPS.md).

## Optional AI second opinion

The current checkout can review existing JSON evidence through OpenAI, DeepSeek
or Claude. Preview the request with `python -m scripts.ai_review --dry-run`;
provider/model and input/output arguments are required. Opinions stay separate
from static verdicts. See [configuration and examples](docs/AI_REVIEW.md).

Saved reports can be refreshed with `python -m scripts.html_report` without
rescanning. The updated view adds status counts, search and combined filters,
compact evidence disclosures, and a collapsed package map with fewer labels.

## Verification

```bash
pip install -e ".[dev,node]"
python -m pytest tests -q
python -m scripts.benchmark_python --clone
```

Unit and regression tests run without external network access or a populated VDB. The optional benchmark downloads pinned Requests/Werkzeug sources and real fix diffs, analyzes eight small caller programs, and writes evidence to `reports/python-benchmark/`. It never executes the target programs. These probes are a regression corpus, not a measurement of accuracy across the Python ecosystem.

See [the Python roadmap and observed limits](docs/PYTHON_REACHABILITY.md) before using results in CI policy.

## License

MIT. See [LICENSE](LICENSE).
