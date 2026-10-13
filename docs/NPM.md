# npm inventory and SCA checkpoint

The npm command reads package-lock.json or npm-shrinkwrap.json (versions 2 and
3), exports the locked installation tree as CycloneDX 1.5, and can query the
configured local VDB. It does not install dependencies or execute application
code, npm lifecycle scripts or build tools. It requires package.json to agree
with the root dependency declarations in the selected lockfile.

The main `depreach.py` pipeline still requires Python. The npm command now also
verifies source artifacts and extracts JS/JSX/TS/TSX syntax facts with `--syntax`.
Resolved JavaScript/TypeScript call graphs and patch-to-symbol reachability are
not implemented yet. npm findings remain explicitly `unsupported`, with
`is_reachable: null`; syntax facts alone do not establish a call path. Do not
interpret lock-tree completeness as installed-tree or source completeness.

## Run on the checked-out real application

Run from C:/Projects/DepReach. Choose a new output directory for each run.
The VDB paths below reference the already downloaded database used for Whoogle.

```powershell
Set-Location C:\Projects\DepReach
$env:VDB_HOME = 'C:\Projects\DepReach\data\vdb-real-apps'
$env:VDB_CACHE = 'C:\Projects\DepReach\data\vdb-real-apps-cache'
& .\venv\Scripts\python.exe -m scripts.npm_inventory `
  --input .\tests_local\real_apps\NodeGoat `
  --output .\reports\nodegoat-my-run `
  --omit-dev --target-os linux --target-cpu x64 --syntax --scan
```

The `node` extra supplies the parsers (`pip install ".[node]"` in the selected
Python environment). The project venv already contains the tested versions.
Tree-sitter is constrained to >=0.25.2,<0.26 because 0.26.0 reproducibly crashed
on Windows regression cases; 0.25.2 passed them. VDB requires >=6.6.1,<7.

Omit `--syntax` and `--sources` for inventory/SBOM only; omit `--scan` to skip VDB. `--omit-optional` excludes optional-only
packages as declared in the lockfile. `devOptional` packages remain if either
dev or optional dependencies are included. Target OS/CPU constraints are explicit;
if a constrained package has no selected target dimension, that uncertainty is
recorded. Excluding a package also excludes all installations nested under it;
a similarly named sibling or a shared top-level copy is retained. Version ranges, Node engine requirements and libc conditions are not
yet validated. Lockfile version 1, Yarn and pnpm inventories are not supported.

The command writes `inventory.json`, `sbom.json`, and, with `--scan`,
`vulnerabilities.json`, `vulnerabilities.sarif` and `report.html`. `--sources`
adds `dependency-sources.json` and freshly extracted source roots. `--syntax`
implies `--sources` and adds per-module AST facts plus `syntax/summary.json`.
Functions have qualified names, exact byte/line spans and content SHA256;
imports, exports, bindings and call expressions retain their lexical owner.
CommonJS candidates explicitly require binding resolution (require/exports can
be shadowed). Parse errors, unsupported encodings and resource limits are visible.
Long expression excerpts are bounded; source hashes and ranges are not truncated. Exit 3 indicates
inventory uncertainty or findings whose JS reachability is unsupported; it does
not indicate a successful reachability verdict. Missing/unusable VDB is an error.

## Identity and resolution

Each installation location is a separate SBOM component with its own bom-ref.
Nested versions, aliases and scoped packages retain their actual package identity.
Dependencies resolve to the nearest captured ancestor node_modules entry.
Workspace links use their recorded real source location; alternate Node symlink
flags and custom loaders are not modeled. Missing required instances are explicit
issues. VDB is queried once per PURL; each finding retains all component_refs in
JSON, SARIF and HTML evidence, including repeated instances of the same version.

Reference contracts: [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
and [Node module resolution](https://nodejs.org/api/modules.html#loading-from-node_modules-folders).

## Historical inventory/SCA checkpoint (superseded counts)

The counts below predate the September 22 omission fix: 66 nested dependencies
of macOS-only fsevents were incorrectly retained for Linux. The current Linux
counts are 396 instances and 47 package/advisory findings, as recorded below.

## Initial real-source checkpoint

Repository: [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), unchanged commit
`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`. Selection: Linux/x64, omit dev,
include optional. Evidence: `reports/nodegoat-sca-v1/validation.json`.

- 462 package instances, 379 distinct PURLs, 693 dependency edges.
- 1,017 omitted package instances; zero unresolved tree issues under this selection.
- CycloneDX 1.5 strict schema validation passed.
- 68 package-version/advisory findings, 60 distinct advisories, 33 affected PURLs.
- 12 findings affect multiple instances of the same package version.
- All 68 reachability results are unsupported; this checkpoint measures npm SCA,
  not JavaScript reachability.

Next integration work must preserve instance identity while adding resolved
ESM/CommonJS imports and exports, package entry/condition resolution, call paths,
immutable fix mapping and independently reviewed positive/negative/unknown JS
application cases. The original ten-part goal
remains open.


## Verified source and syntax checkpoint, 2026-09-22

`reports/nodegoat-syntax-v1/validation.json` records the same unchanged NodeGoat
commit, Linux/x64 without dev dependencies:

- 396/396 package instances have verified source, sharing 345 downloaded artifacts.
- 1,680 source modules, 19,156 function definitions, 65,949 call expressions and
  5,452 import expressions/statements were parsed, with zero parse issues.
- SCA reports 47 package/advisory rows, 42 advisories and 30 affected PURLs.
  All 47 JS reachability results remain unsupported.
- Strict CycloneDX 1.5 validation passed. After replacing VDB 6.6.0, the SCA-only
  phase took 0.578s with 6.6.1 on the existing local database. The older query's
  plan scanned the entire index; the updated query uses indexed prefix lookup.
  The original slow SCA process was explicitly stopped, and the completed source
  and syntax artifacts were reused. This is a measured phase, not whole-scan time.

An additional source-only macOS/x64 check (`reports/nodegoat-darwin-sources-v1/`)
resolved 463/463 instances, including 66 bundled packages, with zero source
issues. It inspected macOS-targeted bytes without executing them.

Source retrieval supports public HTTPS npm registry tarballs with lockfile SRI
checks (the strongest supplied supported algorithm), then verifies package.json
name/version. Legacy SHA1 is explicitly labeled. Bundled dependencies inherit
verification from the containing artifact and have their own identity checked.
Workspace sources have separate local provenance. Cached archives are rechecked;
each scan extracts fresh source, so edits to an older report are not reused as
registry-verified code. No package lifecycle scripts or target code are run.

327 tests passed in the project venv, including JS/TS parser tests; CI installs
the node extra, but no remote CI execution is claimed. This checkpoint does not
complete the original ten-part goal or establish JS reachability accuracy.


The compact AST artifact check (`reports/nodegoat-syntax-v1/syntax-compact-validation.json`)
preserved all source hashes and the same function/call/import counts while
reducing intermediate JSON files from 115,159,003 to 69,768,676 bytes. The
summary remains formatted for review; per-module machine-readable facts use
compact JSON and explicit markers only for actually truncated text excerpts.
The final full test run is `reports/pytest-node-final-02` (327 passed).
