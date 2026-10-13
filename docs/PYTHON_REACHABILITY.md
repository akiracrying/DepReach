# Python reachability: contract, evidence and next steps

## What DepReach answers

Given an inventory of exact Python dependency versions and CVE fix references,
DepReach looks for **possible static calls from first-party code to functions
associated with those patches**. It does not execute the target application.

There are three separate questions:

1. Is a known affected package version present in the inventory?
2. Can the modeled application calls reach a function associated with its fix?
3. Are the vulnerability's conditions satisfied (arguments, platform,
   configuration, attacker-controlled data, runtime entrypoint)?

The current implementation addresses 1 and a bounded subset of 2. Question 3
is explicitly `exploitability: not_assessed`. A patch can also change helpers
which are not the vulnerable operation. Mappings are therefore labeled
`candidate_from_fix_reference`, even when the source context matches exactly.

## Result semantics

| Status | Meaning | `is_reachable` |
| --- | --- | --- |
| `reachable` | At least one modeled call path to a patch-associated function was found | `true` |
| `no_path_found` | No path found within the stated scope, with no recorded analysis gaps affecting the search | `false` |
| `unknown` | Source, patch mapping, or call resolution is insufficient | `null` |
| `unsupported` | The input is outside the supported ecosystem/version contract | `null` |

`no_path_found` is **not** proof that a vulnerability cannot be exploited.
Static call graphs overapproximate some behavior and omit other behavior.
Diagnostics describe detected limitations, not a mathematical completeness
certificate. Unknown results must not be automatically suppressed in CI.

Reports include qualified symbols, source locations, call-site lines, fix URLs,
patch hashes, mapping provenance, diagnostic reasons, source provenance and an
input fingerprint. SARIF exports the paths as `codeFlows`; HTML includes an
evidence/limitations section. Legacy reports with mixed negative and unknown
entries aggregate to unknown.

## Modeled Python subset

The analyzer handles scoped imports and aliases, relative imports, explicit
re-exports, direct and nested functions, module calls, straightforward function
aliases, known class instances, simple `self`/`cls` method calls, and statically
known class inheritance using C3 ordering. It recognizes context managers whose
`__enter__` consists of `return self`. Qualified names prevent unrelated
`parse`, `run`, etc. from being merged.

All first-party functions and module code are analysis roots. This deliberately
includes functions which a particular runtime may never invoke. It is usage
triage, not HTTP-entrypoint analysis. Tests are excluded unless `--include-tests`
is supplied. Dependency tests, documentation/examples, virtualenvs, generated
output and local benchmark directories are excluded. The exact directory
policy is `python_graph.EXCLUDED` / `TEST_DIRS`; it is not a full `.gitignore`
implementation or a package manager's build selection.

Dynamic dispatch, callbacks, decorators, unresolved external calls, complex
instance state, properties/descriptors, native extensions, monkeypatching,
reflection, implicit protocols, and runtime-dependent imports are not modeled
completely. Many are recorded as explicit gaps. Arbitrary return types and
subclass override dispatch are not inferred. Conditional paths are not tested
for feasibility. Missing intermediate dependency source prevents reliable
negative conclusions.

Exact, unique old-side patch context in the supplied dependency version is
preferred. When that context differs, the analyzer retrieves the immutable
first-parent source of a full GitHub fix SHA, verifies the hunk at its original
location, and recovers its fully qualified function identity. That identity
must exist unambiguously in the installed source. The mapping records
`qualified_symbol_from_fix_parent`, the parent source URL/hash, and
`body_matches_fix_parent`; identity is not a claim of body equivalence.
Commit line numbers are never applied blindly to another release. Ambiguous context, unsupported production-file changes, or
changes outside modeled functions remain unknown. Added helper functions are
not attributed to the preceding function. Known test/documentation changes
are excluded from target selection.

## Source and inventory handling

The target dependency source is obtained from a versioned PyPI sdist. Archives
are size-bounded, SHA256-checked, and extracted without filesystem links or
build hooks. Internal tar links to a regular member are materialized as copies;
external paths, link chains and special files are rejected.
Sources are published atomically under a PURL-specific cache directory.
Network operations have timeouts. Both zip and tar sdists are supported.

Intermediate sources can be supplied using repeated `--dependency-source`.
For a target version, use `--package-source pkg:pypi/name@version=path`.
Local source overrides are explicitly **user-supplied version assertions**;
the tool does not prove that a checkout corresponds to the specified release.
No automatic recursive download of every transitive dependency is implemented.

Inventory generation supports existing Python virtualenvs, Poetry, Pipenv,
and pinned requirements. A requirements-only SBOM may omit transitive packages.
Bare `uv.lock` and `pyproject.toml` are not supported inventory providers yet;
the CLI reports that explicitly. Inventorying a virtualenv may invoke its
interpreter through cyclonedx-py. A missing/empty/unreadable VDB or an unresolved
package identity/version fails the scan rather than producing a clean result.

## Caching

Result keys cover project path/content, dependency paths/content, downloaded
patch content, inclusion options and `ANALYZER_VERSION`. Downloading a diff
precedes the cache lookup, so changing a reference's content invalidates it.
Old unscoped cache rows are ignored. Unknown/unsupported reports are retried,
not cached. Successful results also have a 24-hour TTL. Analyzer changes that
alter semantics must bump `ANALYZER_VERSION`.

## Validation on 2026-09-19

The regression suite exercises aliasing, scopes, class-name collisions,
re-exports, wrappers, inheritance, context managers, source exclusion,
malformed code, transitive calls, diff mapping across shifted source lines,
ambiguous/new patch functions, cache invalidation, report semantics, archives,
SBOM failures, VDB preflight, multi-version inventories and CLI status codes.

`python -m scripts.benchmark_python --clone` runs eight small caller programs
against pinned Requests 2.30.0 and Werkzeug 2.3.7 repositories. The script
checks their revisions and clean worktrees before analyzing them. No target
program is executed. Results are stored in `reports/python-benchmark/`.

Observed paths include:

```text
app -> requests.api.get -> requests.api.request -> Session.request
    -> Session.send -> SessionRedirectMixin.resolve_redirects
    -> SessionRedirectMixin.rebuild_proxies

app.run -> werkzeug.utils.send_from_directory -> werkzeug.security.safe_join
```

The two CVEs are [CVE-2023-32681](https://github.com/advisories/GHSA-j8r2-6x86-q33q)
and [CVE-2024-49766](https://github.com/advisories/GHSA-f9vj-2wh5-fj8j).
Dynamic callers return unknown; unrelated same-name and unused-function
probes return no path found. Requests with `allow_redirects=False` still has
a modeled path: this intentionally demonstrates that function reachability
does not evaluate the advisory's preconditions. Similarly, the Werkzeug
advisory has Windows/Python-version conditions which are not evaluated here.

An additional local CLI integration used a separate one-advisory VDB fixture
based on the official CVE record, enriched with the PyPI identity and version
range. Requirements -> CycloneDX -> real VDB search -> downloaded source/fix ->
reachability -> JSON/HTML/SARIF completed successfully. Requests 2.30.0 matched;
2.31.0 did not. This verifies the pipeline, not coverage of the full VDB.
The user's pre-existing VDB directory contained the index but lacked the data
file; no multi-gigabyte database replacement was performed.

This corpus is too small to claim ecosystem precision, recall, or safe alert
suppression. The next expansion must include realistic applications, not just
library caller probes, and independently labeled positive/negative cases.

## Recommended direction

1. **Python correctness and measurable coverage first.** Expand the corpus
   with Flask/Django/FastAPI applications, callbacks, decorators, inheritance,
   native boundaries and missing sources. Record coverage, unknown rate,
   wrong positives/negatives and runtime separately.
2. **Improve package identity and source resolution.** Resolve complete
   environments and lockfiles, link intermediate dependencies automatically,
   support explicit source roots and namespace packages, and avoid rebuilding
   identical graphs for every CVE in a scan.
3. **Separate curated vulnerability models from patch candidates.** Store
   reviewed affected symbols and version ranges, with provenance. Add precise
   argument/platform preconditions only when backed by regression examples.
4. **Expose trustworthy evidence in existing workflows.** Preserve this
   result contract when importing findings from another SCA, comparing PRs,
   or defining CI policy. Do not turn an inconclusive scan into an ignore rule.

AI is not required for these steps. If introduced later, its best initial use
is proposing patch/symbol mappings which the corpus and reviewers validate.
The near-term product is an explainable Python dependency triage tool with
visible uncertainty, not an automated claim that a CVE is harmless.


## v3: evidence and additional possible calls

The call graph includes possible invocation of explicitly passed functions or
callable instances. Such edges have `edge_kind: passed_callable_may_be_invoked`;
the receiving function is not proven to invoke the callback. Constructor
returns and values retrieved from instance registries provide possible receiver
types. `dispatch_models` records their source locations and assumptions. These
models add positive candidates; they never establish complete dispatch.

Class attributes initialized with known classes/instances and literal
`getattr(module, "name")` can resolve additional calls. Arbitrary string-based
reflection still remains unresolved. Dependency setup.py files are excluded.
Parse errors in unimported dependency modules no longer contaminate the whole graph; an
imported broken module still blocks a negative conclusion.

Every mapped function has a `function_results` entry. `call_path_status` is
`found` / `not_found` / `not_evaluated` at finding level, separate from the final
conservative `status`. A not-found path with unresolved behavior remains
`unknown`; it is not relabeled safe. `patch_evidence` preserves each relevant
hunk's old context, additions/deletions, mapping outcome and fix reference.
HTML exposes these details, and CLI prints a compact explanation per finding.
Diagnostics contain at most five examples per reason plus exact counts and
`diagnostics_omitted`, instead of repeating thousands of warnings per CVE.

`python -m scripts.replay_reachability --report OLD_JSON --project APP_DIR
--output NEW_DIR` reruns a frozen finding set for a controlled before/after
comparison without updating VDB or changing the inventory. It does not discover
new CVEs; NEW_DIR must not exist. It accepts repeated `--dependency-source`.


## v4.2: environment, source closure and callback evidence

Requirements inputs are filtered for the scanner's marker environment by
default. `--target-environment path.json` provides explicit marker overrides;
`--requirements requirements/prod.txt` selects an input relative to the scanned
project; `--all-environments` retains alternatives and reports conflicts rather
than combining their code into one runtime. These options currently apply to
pinned requirements, not arbitrary lockfile providers. Development/runtime
scope is preserved as declared; it is not inferred from package names.

Exact declared dependency sources are prepared automatically. Missing transitive
 versions remain unresolved rather than being guessed. The source manifest is
`reports/<project>/dependency-sources.json`. For null PyPI release dependency
 metadata, a compatible wheel's core metadata can be used after validating the
 SHA256 advertised by the [PyPA Simple API](https://packaging.python.org/en/latest/specifications/simple-repository-api/),
 identity and required headers. No wheel is installed or executed. Foreign
 target descriptions currently allow only compatible generic pure-Python wheels
 for this fallback; platform-specific ABI compatibility is not guessed.

A merely passed callback no longer establishes a positive result. JSON preserves
 such paths in `speculative_paths`; HTML labels them as unverified, and SARIF
 does not promote them to positive code flows. A known direct consumer calling
 the bound parameter adds `callback_invocation` evidence with its source file,
 line and parameter. Unused parameters add no callback edge; storing/returning
 a callback is reported as an escape rather than an invocation. These are static
 possible calls, not proof that execution occurs or exploit preconditions hold.

`function_results[].blocking_reasons` is target-specific where an uncertainty
 has a finite candidate set. An escaped callback unrelated to a target can be
 excluded only after checking its modeled call closure for hidden uncertainty.
 Unbounded dynamic behavior remains blocking. `analysis_gaps` preserves the
 broader graph diagnostics even when they do not block a particular target.

Callback and return-model examples have exact counts and explicit omitted
 counts. Positive paths preserve their invocation evidence. One completed graph
 is shared by findings with identical source contents during a scan.

The verified Whoogle run and remaining gaps are recorded in
 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). A zero no_path_found count
 in that real application is still an open coverage issue, not silently fixed
 by changing labels. v3 reports remain historical evidence with older callback
 semantics.


## v4.3: fix reference discovery

When no direct commit is supplied, supported GitHub advisory and PR references
are resolved through the public API. A merged PR provides its merge SHA; open
PRs, withdrawn advisories, mismatched identities and API failures do not provide
fix evidence. `reference_discovery` records provenance, response hashes and
issues. Requests are bounded and successful responses reused within a scan.
A partial discovery failure prevents a negative finding even if another commit
was mapped. Direct commits retain the existing fast path.

This discovers candidate patches, not confirmed vulnerable functions. It does
not infer a sink from prose or automatically crawl arbitrary issue links.
See the [GitHub advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories)
and [pull request API](https://docs.github.com/en/rest/pulls/pulls).


## v4.4-v4.7: reviewed evidence, data and descriptors

`mapping_evidence` distinguishes exact patch context, full function AST equality
with the fix parent, and qualified identity only. `vulnerability_evidence` stays
`patch_candidate` unless a catalog entry matches the advisory, exact inspected
version, source root and full function-source fingerprint. `reviewed_targets`
records checks, source references, reviewer kind and unevaluated conditions.
The initial source-reviewed entries cover Requests rebuild_proxies and Werkzeug
safe_join. They do not assert exploitability or silently replace candidate
findings. Catalog contents are part of cache identity and included in wheels.

Patch evidence now records `change_kind` and `analysis_support`. Native code,
certificate data, configuration and binary/metadata-only changes remain explicit
unsupported boundaries; mixed patches remain inconclusive when unsupported
parts could matter. Truncated hunks do not produce mappings. Old-side context
can also match a uniquely identified renamed file.

Literal module/class assignments have data symbols. Reads add `data_reference`
edges and mappings identify `patch_associated_data`. Importing a module alone
is not a read of each constant. Rebindings and shadowed names are checked.
Arbitrary computed data and external resource-flow analysis are not covered.

An instance property read can add `property_getter_access`; accessing the same
attribute on a class yields the descriptor object and does not call its getter.
Custom descriptor dispatch and unknown getter return values remain gaps. Calling
a known callable instance resolves __call__, while class instantiation resolves
constructor methods.

`blocking_source_issues` and `nonblocking_source_issues` explain whether a source
manifest gap belongs to a component participating in the graph. An unused exact
source component can be excluded as a metadata blocker, but unresolved dynamic
calls still prevent negatives. See [evaluation evidence](EVALUATION.md).
