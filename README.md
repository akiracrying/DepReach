# DepReach: Software Composition Analysis with Reachability

**DepReach** is a Software Composition Analysis (SCA) tool that extends vulnerability scanning with **reachability analysis** — determining whether vulnerable code is actually reachable from your project via call graphs.

## Features

- **SBOM generation** — CycloneDX format via cdxgen (Docker)
- **Vulnerability lookup** — Local vulnerability database (VDB)
- **Reachability analysis** for Python packages:
  - Call graph construction
  - AST-based analysis
  - GitHub diff integration to map fixes to affected functions
- **Caching** — SQLite cache for reachability results
- **Optional GraphQL API** — Query vulnerability data via FastAPI + Strawberry

## Requirements

- Python 3.10+
- **Docker** — Required for SBOM generation (cdxgen)
- Git — For reachability analysis (GitHub diffs)

## Installation

```bash
git clone https://github.com/your-org/DepReach.git
cd DepReach
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

## Usage

```bash
python depreach.py -i path/to/project -o report.json
```

### Options

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Path to source code directory (required) |
| `-o`, `--output` | Report filename (e.g. `report.json`). Saved under `reports/{project_name}/` |
| `--skip-update` | Skip updating the vulnerability database |
| `--cache` | Cache reachability results in local SQLite |
| `-j`, `--jobs` | Parallel jobs for reachability analysis (default: 6) |

### Example

```bash
python depreach.py -i ./my-project -o report.json --cache
```

## Output

- **JSON report** — `reports/{project_name}/report.json` — vulnerability list with CVE, severity, description, references, and reachability
- **SBOM** — `reports/{project_name}/{project_name}_sbom.json`
- **Console table** — Rich-formatted summary with reachability status (✅/❌)
- **Log** — `depreach.log` for debugging

## Architecture

| Component | Purpose |
|-----------|---------|
| `depreach.py` | Main entry point, CLI, workflow orchestration |
| `scripts/bom.py` | SBOM generation via cdxgen Docker image |
| `scripts/composition_analysis.py` | Vulnerability scanning against VDB |
| `scripts/reachability.py` | Call graph, AST, GitHub diff analysis |
| `scripts/update_db.py` | VDB update |
| `scripts/cache.py` | Reachability result caching |
| `graphql_db/` | Optional FastAPI + Strawberry GraphQL API |

## Optional: GraphQL API

To query vulnerability data via GraphQL, start the server from the `graphql_db` directory:

```bash
cd graphql_db
uvicorn server:app --reload --port 5555
```

Example query:

```graphql
query {
  getVulnsByPurl(purl: "pkg:pypi/requests@2.25.1") {
    cve
    description
    severity
    reachability {
      isReachable
      changedFuncs
      reachableFuncs
    }
  }
}
```

Note: The main `depreach.py` flow writes to a JSON file. The GraphQL server reads from `vulns.db` — integration between the two is optional and can be wired separately.
