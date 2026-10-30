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


## Candidate module lookup checkpoint, 2026-10-30

The current checkout adds Node module path analysis; this feature is not in the
published 0.2.0 package. Direct CommonJS require identity is now checked against
lexical scopes, but exported values and function calls are not yet resolved.
A resolved file path does not change an npm finding's unsupported reachability.

Run the full pipeline from C:/Projects/DepReach with a fresh output directory:

```powershell
$env:VDB_HOME = 'C:\Projects\DepReach\data\vdb-real-apps'
$env:VDB_CACHE = 'C:\Projects\DepReach\data\vdb-real-apps-cache'
.\venv\Scripts\python.exe -m scripts.npm_inventory `
  --input tests_local/real_apps/NodeGoat --output reports/nodegoat-my-module-run `
  --omit-dev --target-os linux --target-cpu x64 --resolve-imports --scan
```

`--resolve-imports` implies source verification and syntax extraction. It adds
`module-resolution/imports.jsonl` and `module-resolution/summary.json`. Each
record preserves importer instance, lexical owner, source hash, byte/line span,
lookup mode, target instance/PURL/file hash or an explicit blocker. Re-exports,
type-only imports, nonliteral candidates and unverified CommonJS calls remain
distinct. Global module lookup counts are separate from vulnerability statuses.
JSON/SARIF findings retain the module-resolution manifest; fresh scans also
include a scan-wide module lookup summary in the HTML report.

To audit sources already captured by an earlier scan, without downloads, SCA
queries, package installation or application execution:

```powershell
.\venv\Scripts\python.exe -m scripts.node_imports `
  --inventory reports/nodegoat-syntax-v1/inventory.json `
  --sources reports/nodegoat-syntax-v1/dependency-sources.json `
  --output reports/nodegoat-my-lookup
```

A completed candidate lookup with no unresolved CommonJS binding returns 0.
Explicit unknown/unsupported lookup or binding, syntax/source gaps and output
omissions return 3. This exit code concerns audit coverage, not whether the
application is vulnerable. The full --scan pipeline
continues to return 3 for npm vulnerabilities with unsupported JS reachability.

### Modeled profile and boundaries

- Modern Node 22/24 default conditions: node, node-addons, module-sync, plus
  require/import as appropriate. Additional conditions can be passed with
  repeatable --condition values; npm CLI requires --resolve-imports for them.
- Node-style CommonJS extension/main/index lookup, ESM exact relative/subpath
  targets, package exports/imports, ordered conditions, wildcard specificity,
  arrays and null blocking. Missing files after a valid exports target do not
  trigger a guessed fallback to another target.
- Versioned installation locations remain separate even when identical archive
  sources share one syntax parse. Default workspace real paths are used only
  when the corresponding source context is present; missing real paths remain
  unsupported. Conflicting instance/source identities are rejected.
- Package.json follows Node's last-value semantics for duplicate properties,
  retaining nonblocking warnings. In the real bcrypt-nodejs package, a repeated
  author field previously prevented a valid main lookup. Lockfile and root
  inventory JSON retain their stricter duplicate-key input validation.
- Captured bytes supply parsing, source hashes and module metadata. Exact source
  identity and recorded package.json hashes are checked. Supported source bytes,
  virtual file existence, engine-source digest, parser versions and profile
  enter the audit fingerprint. No source package code or loader executes.
- Output directories created inside the application are excluded from its source
  scope; dependency roots are still analyzed separately. Excluded roots are
  recorded. Other pre-existing directories remain in the requested input scope.
- Bounds: 16 MB per supported source file, 128 MB per root, 256 MB of captured
  source bytes, 20,000 files per root, 20,000 module instances and 50,000 emitted
  reference records. Count/resource omissions are explicit, not negative results.

Custom loaders, NODE_PATH/global folders, preserve-symlinks overrides, browser
bundler rules and TypeScript compiler path/extension mapping are not modeled.
Encoded/URL-like specifiers and targets remain unsupported. File paths match
captured names; general case/Unicode normalization is not modeled. Windows and
POSIX trailing-separator behavior is distinguished, with an explicit loader-
format boundary where appropriate. Native/JSON/TypeScript targets retain their
format boundaries. File lookup alone does not validate loadability or exports.
Only recognized syntax candidates are audited; loader aliases and computed
external mechanisms still require binding/dataflow models.

### Real application evidence

The unchanged NodeGoat input and earlier inventory selection yielded:

- 396/396 verified source instances, zero source issues.
- 1,680 physical JS/TS modules parsed; 1,763 module contexts preserve repeated
  installation instances. No parse issues or count/output omissions.
- 5,525 lookup candidates: 4,807 file targets, 520 built-ins, three type-only,
  195 unresolved (32 nonliteral, 81 absent package instances, 82 absent relative
  files). Of 5,494 direct CommonJS candidates, 5,382 have a verified wrapper
  binding, 78 refer to local declarations and 34 remain unresolved due to eval.
  Local declarations may still receive a loader value; that dataflow is pending.
- 47 package/advisory findings remain unsupported for JS reachability.

Artifacts: reports/nodegoat-resolution-scan-v1 and the standalone audits under
reports/nodegoat-module-resolution-v3. These counts measure path lookup over the
captured scope, not vulnerability precision or actual executed application paths.
Unresolved references in unused library helpers must not later become global
blockers for every CVE; contextual call-graph work remains necessary.

Independent tests compare results against createRequire().resolve and
import.meta.resolve plus an explicit filesystem check. Target modules never
load; importer real paths match Node's default symlink behavior. Tests also cover
version nesting, aliases, imports/exports edge cases and source mutations.
Dedicated CI jobs use Node 22 and 24 and retain oracle comparisons as artifacts.
Windows may skip the symlink oracle when the host lacks creation privileges;
Linux CI covers it. Visual viewport checks and live AI calls remain separate.

Reference contracts: [Node CommonJS lookup](https://nodejs.org/docs/latest-v22.x/api/modules.html#all-together),
[package entry points and conditions](https://nodejs.org/api/packages.html),
[ESM resolution](https://nodejs.org/api/esm.html#resolution-and-loading-algorithm).


## Direct CommonJS loader binding, 2026-10-30

The module audit now uses lexical scopes from the same captured tree to
classify a direct require identifier. This is a precursor to symbol/call
analysis, not a vulnerability verdict or a complete binding/dataflow engine.

- verified_commonjs_wrapper: a runtime CommonJS profile, no shadowing declaration
  and no observed write or dynamic environment that could replace require.
- shadowed_commonjs_identifier: a parameter, local declaration or imported value
  with that name. It may itself receive a loader value; forwarding and value
  flow remain unmodeled. Keep the raw path candidate separate from this identity.
- unresolved_commonjs_binding: module/compile boundaries, direct eval, with,
  wrapper arguments exposure, possible wrapper reassignment or incomplete
  syntax/binding analysis. The reason is preserved per reference.

Scopes distinguish function parameters from body declarations, including
closures created by default arguments. Hoisting, block/loop/catch scope,
var/let/const, named functions/classes and destructured bindings are modeled.
ESM imports are local declarations, never an implicit CommonJS wrapper.
Ambiguous .js uses the declared default Node syntax profile; import/export,
import.meta, top-level await and top-level lexical wrapper redeclarations
prevent a guessed CommonJS binding. Ambiguous top-level for-await retains a
runtime-check boundary after Node 22 rejected an authored syntax-detection
fixture. Explicit CommonJS syntax conflicts are unsupported. JSX/TS/declaration files retain compiler boundaries. Dynamic eval
and writes are conservatively scoped to the source module; no control-flow
proof that a write/eval is irrelevant is claimed yet.

Records add binding_evidence with profile, reason, declaration spans and explicit
limits. Summary commonjs_bindings counts all candidates, including records
omitted by the output cap. Binding source enters the audit fingerprint. Trees
and lexical tables are released after each physical parse; reused package
artifacts retain compact results and their individual installation contexts.
The standalone/npm audit returns 3 if a CommonJS binding remains unresolved.
Full npm SCA still preserves unsupported reachability for every advisory.

Real evidence: reports/nodegoat-binding-audit-v3, using the existing verified
NodeGoat sources and inventory. The 5,525 path lookup counts are unchanged.
The 78 local bindings include browser-bundle loader parameters; treating them
as Node require would create the wrong dependency relationship. The application's
own 50 candidates have 48 verified wrapper bindings and two unresolved because
the containing module uses eval. No real application or dependency code ran.

Synthetic tests compare authored scope fixtures with Node's vm.compileFunction
using an injected sentinel require; only those test strings execute. The normal
resolution oracle continues to avoid loading any target module. Both independent
checks run in required Node 22/24 CI jobs. Separate retained artifacts contain
18 scope fixtures and 24 default-module-profile comparisons per runtime.

Next: resolve ESM named/default/namespace imports and re-exports; model CommonJS
module.exports/exports values and their aliasing/mutations/cycles; then connect
actual call expressions and immutable fix-to-symbol mappings. Require aliases,
module.require/createRequire, callbacks, receiver/object flow and custom loaders
remain explicit future work.


## Stable value/function target audit

The current checkout adds --resolve-symbols. The npm command implies
--resolve-imports, --sources and --syntax. The standalone module audit accepts
the same flag with previously verified source/inventory manifests. This is not
in the published 0.2.0 package. Install from the current source checkout.

```powershell
.\venv\Scripts\python.exe -m scripts.node_imports `
  --inventory reports/nodegoat-resolution-scan-v1/inventory.json `
  --sources reports/nodegoat-resolution-scan-v1/dependency-sources.json `
  --output reports/nodegoat-my-symbols --resolve-symbols

# Full pipeline with a fresh output directory and the existing configured VDB:
.\venv\Scripts\python.exe -m scripts.npm_inventory `
  --input tests_local/real_apps/NodeGoat --output reports/nodegoat-my-full-symbols `
  --omit-dev --target-os linux --target-cpu x64 --resolve-symbols --scan
```

The new symbols/calls.jsonl records call/new expressions, their lexical owner,
importer instance/source hash, a candidate function's exact source span/hash
and defining module/PURL, plus a bounded explanation of value/binding/export
steps. Only an actual call/new expression creates a record: passing or storing
a function alone does not establish invocation. Calls inside unused functions
still appear and have entrypoint_reachable and vulnerability_reachable null.
The summary and HTML keep these scan-wide candidates separate from CVE status.
The HTML candidate card is closed by default and shows up to eight application
examples with caller/definition locations.

Modeled cases include stable lexical function declarations and aliases; direct
CommonJS default/named values, object exports, simple export assignment chains
and forwarding; object destructuring and literal property selection; ESM named,
default and namespace imports, explicit re-exports and star export ambiguity.
ESM default imports from CJS are supported; named CJS import heuristics and
require-of-ESM namespace interop remain unmodeled. Installation contexts remain
distinct even when source artifacts share one parse.

CJS exports and module.exports start as aliases of one object; replacing one
reference does not update the other. A function's identity is distinct from its
mutable properties. Property modifications can make its properties unknown
while leaving its direct call target intact; replacing module.exports, escaping
the module object, eval or wrapper arguments exposure also blocks that identity.
Conditional/delayed writes, computed keys, destructured/member assignments,
for-in/of writes and delete do not borrow an earlier static target. Object
arguments/aliases and known cross-module object mutations retain shape taint.

This remains a partial model with explicit default-loader and stable-value
assumptions. In particular receiver/heap side effects, custom loaders/cache
modifications, returned values/instances, callback forwarding, framework
registration and full initialization order are not modeled. A function target
is not runtime execution or loadability proof. Inter-module initialization
cycles that affect a query are unresolved, not traversed as completed exports.
Generator calls are iterator creation, not evidence of executing their bodies;
nonconstructible/async functions are not treated as ordinary constructors.

The audit uses captured bytes for syntax and value lowering and releases the
full tree/scope tables after each physical parse. Engine sources, parser/profile
and the resolve-symbols selection enter its input fingerprint. Value depth and
step budgets, property/record limits and evidence-trace omissions are explicit.
The standalone/npm audit returns 3 for unresolved symbol coverage or omissions.
SCA findings continue to have unsupported JS reachability even when some function
targets resolve. No absence of a path or vulnerability verdict is inferred.

Independent Node fixture checks compare selected function identity using the
exact SHA256 of Function.prototype.toString output against captured definition
bytes. Only authored fixture module initializers load; selected function bodies
and captured real application/dependency modules are not executed. Node 22/24
jobs retain those comparisons alongside the previous scope/profile oracles.

Next: establish application entrypoints and contextual function-call paths,
propagate receiver/instance/return/callback flow and scope missing edges to the
relevant target; map immutable fixes to exact-version vulnerability targets
before producing JS vulnerability reachability verdicts.

Real NodeGoat checkpoint (reports/nodegoat-full-symbol-scan-v4): the complete
CLI used the local VDB and all 345 cached archives, verifying 396/396 source
instances without executing the application or dependencies. Across 1,680
physical files / 1,763 installation contexts, 68,486 call/new expressions yielded
12,236 modeled function targets, 6,432 built-in targets and 49,818 unresolved.
There are 559 modeled function targets in the application-owned files, including
constructor links from allocations/contributions modules to UserDAO. This scope
includes browser asset files under the requested root; it is not a server
entrypoint selection or ecosystem-wide precision estimate.

The standalone and freshly extracted full-pipeline sources produced identical
source captures, input fingerprints, counts and calls.jsonl bytes. Independently
checking every modeled function record against source bytes verified 12,236
records / 3,974 contextual function definitions in 942 physical files. This
checks provenance and spans, not runtime execution or vulnerability mapping.
Evidence: reports/nodegoat-symbols-v4/function-byte-validation.json and
reports/nodegoat-full-symbol-scan-v4/validation.json. All 47 package/advisory
findings remain unsupported for JS reachability; exit 3 is expected.

Identifier names now decode valid JavaScript Unicode escapes before lexical
lookup: r\u0065quire and require have the same binding identity. The spelling
in source bytes/spans is retained. Unsupported surrogate/out-of-range escapes
make syntax incomplete. This prevents an encoded parameter or root lexical
declaration from being mistaken for an unshadowed CommonJS loader. Node scope,
module-profile and exported-function identity fixtures exercise these cases.

Function-call output limits: 100,000 records, 16,384 metadata characters per
record, 64 KiB encoded per record and 128 MiB per JSONL file. Count/text/byte
omissions have separate counters, make symbol coverage incomplete and are shown
in HTML when present. Application examples are selected only from emitted
records and limit each display string to 512 characters with a truncation flag.
JSONL uses explicit UTF-8/LF so the byte budget equals the actual output size.

ESM export names preserve the distinction between a missing alias and an empty
string alias. String namespace export names are interpreted as names, not as
quoted source text. Unsupported escaped string aliases remain unresolved and
do not expose the original local name. Native Node function-identity fixtures
cover supported empty/string aliases; they complement Unicode identifier
decoding, which is separate from general JavaScript string-literal decoding.
