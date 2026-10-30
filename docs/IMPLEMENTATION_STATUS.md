# Implementation and verification ledger

Scope: implement and verify all ten requested improvements. Work only in
C:/Projects/DepReach. A checked test or a smaller unknown count alone does not
establish completion. Historical Whoogle v3: 65 findings, 8 possible paths,
57 unknown; mapped functions for 35 findings. Preserve historical reports.

| # | Requirement | Acceptance evidence | State |
|---|---|---|---|
| 1 | Target-specific uncertainty and negative conclusions | Per-function blocking boundaries; labeled negative controls and hidden-call counterexamples; real-app before/after audit | In progress |
| 2 | Complete, version-consistent dependency sources | Inventory-to-source manifest, intermediate library paths without manual source flags, explicit missing/conflicting source handling | In progress |
| 3 | Independently labeled evaluation corpus | Reviewed expected labels and source evidence for positive/negative/unknown real-library/application cases; separate precision/coverage metrics | In progress |
| 4 | Fix/reference/function discovery | Advisory/PR/commit provenance, renames/version branches, failure fixtures and live public-source checks | In progress |
| 5 | Distinguish patch candidates from verified affected functions | Explicit mapping evidence levels and reviewed-model provenance; no inference presented as confirmed vulnerability sink | In progress |
| 6 | Python/framework call graph coverage | Regression examples for properties/decorators/overrides/returned objects/framework registration and meaningful app paths | In progress |
| 7 | Callback invocation verification | Invoked versus merely stored/passed callbacks; unresolved external consumers remain speculative; reporting preserves edge evidence | In progress |
| 8 | Environment and dependency scope | Marker filtering for explicit targets; alternative-version conflicts; runtime/dev provenance; inventory tests on Whoogle | In progress |
| 9 | Non-function/non-Python patches | Explicit change kinds and supported data/class models; unsupported native boundaries cannot become safe negatives | In progress |
| 10 | Reuse computation and explain blockers | Scan-scoped source/graph reuse, content invalidation and concurrency tests, bounded reports with actionable primary blockers | In progress |

Do not mark the goal complete until every row has authoritative evidence.

## Verified checkpoint: v4.2, 2026-09-20

- 161 offline tests passed. Command: `C:/Python10/python.exe -m pytest tests -q
  --basetemp reports/pytest-v4-verified-01`.
- Eight existing real-library probes passed against pinned Requests/Werkzeug;
  evidence: `reports/python-benchmark-v4.2/summary.json`. These are regression
  probes, not an independently labeled broad accuracy corpus (#3 remains open).
- Full CLI on unchanged Whoogle v0.8.2, using the existing complete VDB:
  `reports/whoogle-search/report-v4.2.json`, `.sarif`, `report.html`,
  `run-v4.2.log`, `comparison-v4.2.json`. Exit 2, 43.1 seconds, one graph build,
  44 reuses. 53 findings: 7 reachable, 46 unknown, zero no_path_found.
- Environment filtering selected 34 components instead of combining 36 marker
  alternatives. The 12 removed finding rows are inventory changes, not improved
  reachability. Common finding changes: three old callback positives became
  unknown; two previously unknown paths were found with intermediate sources.
- All 34 declared component sources were obtained. SHA256-verified PEP 658 wheel
  metadata resolved 15 false metadata-incomplete blockers. Remaining: Stem's
  metadata is incomplete and seven dependency requirements lack a selected
  transitive version. Full manifest: `reports/whoogle-search/dependency-sources.json`.
- Callback evidence distinguishes direct parameter invocation, unused arguments,
  escaped values and unresolved consumption. Unknown consumption remains in
  `speculative_paths`, never in positive `paths`. Direct positional/keyword
  binding is checked. Methods, forwarding, generators, closures, decorator
  replacement and stored-then-invoked registries still need broader modeling.
- An escaped callback diagnostic carries bounded candidate targets. An unrelated
  target can have no_path_found only if the callback's entire modeled closure
  has no path or unresolved behavior that could reach it. Hidden dynamic calls
  and missing external bodies are counterexamples covered by tests. General
  dynamic dispatch and missing inventory remain broad blockers (#1 partial).
- Graph reuse is tested across CVEs, parallel callers, failed builds and changed
  application contents. Diagnostic/model samples are bounded, exact totals and
  relevant positive-path evidence retained. Report shrank from 54.99 MiB for
  v4.1 to 4.09 MiB for v4.2. Source metadata, lockfile/runtime scope, full graph
  invalidation coverage and further performance work remain open.

Do not interpret this checkpoint as completion of the ten requirements.

## Additional checkpoint: v4.3 reference discovery

- GitHub advisory references and linked description URLs can resolve candidate
  commits; linked merged pull requests resolve to their immutable merge SHA.
  Advisory/PR identity, merged state, response bounds and withdrawal are checked.
  Response SHA256 and the discovery chain are retained; failures remain visible
  and partial discovery failures block a negative finding.
- An advisory-only live Requests control resolves the known fix and reaches
  `SessionRedirectMixin.rebuild_proxies`. Evidence:
  `reports/fix-discovery-v4.3/requests-advisory-only-report.json` and
  `requests-control.json`. The source checkout is the benchmark's pinned 2.30.0.
- The eight Whoogle findings lacking direct fixes were checked; no extra commits
  were supplied by supported linked resources. Evidence:
  `reports/fix-discovery-v4.3/whoogle-discovery.json`. This preserves unknown,
  rather than inventing a function from advisory prose.
- #4 is still partial: general OSV/CVE lookup, non-GitHub providers, rename-aware
  cross-version mapping and branch selection require further implementation.
  The broad independent corpus, curated sink models, framework coverage and
  typed native/data changes (#3/#5/#6/#9) remain open.

## Verified checkpoint: v4.4-v4.7

- 226 tests pass (`reports/pytest-source-scope-v4-01` run). New counterexamples
  cover source-review mismatches, changed CVE identities, incomplete hunks,
  binary/configuration patches, literal data reads, lexical shadowing, repeated
  and nonliteral rebindings, descriptor objects, custom attribute dispatch,
  callable instances and metadata gaps in unused components.
- Reviewed annotations require package/advisory identity, exact inspected version
  and complete function-source SHA256. Four source versions across Requests and
  Werkzeug were inspected. The report distinguishes exact patch context,
  qualified identity with equal AST, and identity alone. Review annotations are
  separate from candidates and explicitly leave exploit conditions unevaluated.
  Evidence: `scripts/vulnerability_models.json`, real library reports in
  `reports/python-benchmark-v4.5/`, and Whoogle `report-v4.5.json`.
- Patch evidence classifies native code, certificates, configuration, binary and
  metadata-only changes. Unsupported portions cannot create a safe negative.
  Module/class literal data references are modeled separately from function
  calls. Renamed paths can match exact old context; general cross-version symbol
  renames and native-language frontends remain incomplete.
- An independently stored, source-reviewed 30-case corpus reports wrong
  conclusions separately from abstentions. v4.6: zero observed wrong conclusions,
  21/25 determinate labels resolved (84%), four abstentions, five expected
  indeterminate results. Includes eight real-library callers and unchanged
  Whoogle/Linkding cases. Labels and limits: `docs/EVALUATION.md`.
- Builtin property getters on known instances, inherited getters and direct
  callable-instance dispatch are modeled. Class descriptor reads, shadowed
  decorators, custom __getattribute__/__new__/metaclasses and unknown getter
  return types are kept distinct. General framework registrations, closures,
  parameter returns and polymorphic receiver contexts remain open.
- v4.7 scopes source metadata issues away only when exact source is indexed and
  no symbols from that component are reachable. Missing identities and graph
  dynamic gaps remain blocking. Both blocking and nonblocking source issues are
  retained in reports with their scope basis.
- A wheel built successfully with isolated build dependencies and includes both
  reviewed models: `reports/wheel-v4.6/`. System setuptools 65.5 could not satisfy
  the project's >=77 build requirements; the successful build used a temporary
  environment and caches under `reports/wheel-v4.6-temp`, without upgrading the
  system installation. Build log: `reports/wheel-v4.6-isolated-build.log`.
- Offline corpus checks are included in `.github/workflows/tests.yml`. The local
  checks passed; no remote CI run is claimed.

Still not a completion claim: all ten rows require the final requirements audit.
In particular, #4 branch/version discovery, #6 framework/dataflow coverage,
#8 environment/group support and non-Python analysis remain incomplete.


## Verified checkpoint: v4.8-v4.10, 2026-09-21

- Source capture now supplies the exact same bytes to content fingerprints,
  graph construction, patch mapping and reviewed-source matching. The CLI reuses
  one immutable capture per source root and test-scope option during a scan;
  the default library session still re-reads between calls. A new scan re-reads
  content even if file sizes/timestamps were preserved. Capture is explicitly
  not an atomic filesystem transaction. Reports retain input hashes and scope.
- v4.8 full Whoogle: 53 findings, 7 reachable / 46 unknown, identical primary
  statuses to v4.7. One graph build, 44 graph reuses; 35 source captures, 871
  Python files / 11,805,531 bytes, 1,540 source snapshot reuses. Runtime 54.2s
  versus the earlier 62.0s observation, not a controlled performance benchmark.
  Evidence: reports/whoogle-search/report-v4.8.json and run-v4.8.log.
- Plain synchronous functions that return an unchanged parameter now preserve
  callback identity at the caller. Discarding that return does not invoke the
  callback or expose its unknown body; assignment followed by invocation has a
  positive path. Stored/escaping returns, nonidentity bodies, decorators,
  async/generators, unknown bindings and rebindings retain conservative handling.
- Parameter-call diagnostics can be scoped using every modeled reachable call
  site. A callback supplied only by an unreachable dependency function cannot
  contaminate another call. Unknown incoming arguments, callback entry, first-
  party roots and mixed unresolved expressions remain unbounded. Same-line
  supplying calls are distinguished by column; diagnostic evidence lists the
  candidate callbacks, binding sites and scope basis.
- 257 tests passed with reports/pytest-v4-10-full-01. Added tests cover parallel
  capture, failed reads, content edits with preserved timestamps, deletion after
  capture, source encodings, snapshot/input mismatch, returned callbacks, shadowing,
  stores, invalid arguments, separate call sites and hidden unknown consumers.
- The unchanged 30-case corpus now resolves 25/25 determinate labels: 13 positive,
  12 negative; five expected indeterminate results stay unknown. No wrong
  conclusions were observed. Evidence: reports/labeled-corpus-v4.10/summary.json.
  This is coverage of these regression cases, not ecosystem accuracy; corpus
  labels remain assistant-reviewed and have not had external human review.

Remaining work is still tracked by all ten original requirements. These
checkpoints do not establish broad framework/dataflow completeness, complete
lock/environment support, multi-provider fix discovery or a non-Python frontend.


## Verified checkpoint: npm inventory/SCA foundation, 2026-09-21

- Python v4.10 full Whoogle completed with exit 2 in 66.9s. It retains the
  v4.8 primary and mapped-function results: 53 findings, 7 reachable / 46
  unknown, 7 reachable / 74 unknown function rows. Single-run timing is variable;
  the source read counters still establish one capture per root. Evidence:
  reports/whoogle-search/report-v4.10.json and run-v4.10.log. The callback corpus
  improvements did not remove the other blockers in this full application.
- npm v2/v3 lockfile support now preserves installation locations, nested
  versions, aliases, workspace links, required/optional/peer edges, dev/optional
  provenance and explicit OS/CPU filtering. Root declaration mismatch, malformed
  flags/versions, duplicate keys, invalid paths and link cycles are checked.
- A separate `scripts.npm_inventory --scan` command exports CycloneDX and queries
  the existing VDB. The main Python pipeline is not advertised as a JS analyzer.
  Source verification, semver-range/engine checks, JS/TS parsing and reachability
  remain open. All npm findings currently have unsupported reachability.
- Composition lookup reuses a PURL query while retaining every SBOM instance in
  component_refs. Same-version occurrences are preserved in JSON/SARIF/HTML;
  different package versions still have separate finding rows.
- 287 tests passed (reports/pytest-npm-scan-full-01). Real NodeGoat at clean commit
  c5cb68a7084e4ae7dcc60e6a98768720a81841e8 was cloned within tests_local/real_apps.
  No application or install script ran. Linux/x64 without dev: 462 instances,
  379 PURLs, 693 edges, 1,017 omitted, zero tree issues. Strict CycloneDX 1.5
  validation passed. Existing VDB found 68 package/advisory rows, 60 advisories,
  33 affected PURLs; 12 finding rows retain multiple instances. Evidence:
  reports/nodegoat-sca-v1/validation.json and associated reports; docs/NPM.md.

All ten original requirements remain in progress pending their full acceptance
checks. In particular, npm inventory/SCA is not completion of non-Python
reachability, and a green regression corpus is not broad ecosystem validation.


## Verified checkpoint: npm sources and JS/TS syntax, 2026-09-22

- Corrected npm omission propagation: macOS-only fsevents was omitted on Linux,
  but 66 nested bundled instances survived. All descendants are now omitted with
  the parent; unrelated siblings/shared hoisted copies remain. Prior Linux npm
  counts (462 instances/68 findings) are superseded by 396 instances/47 findings.
  This is an inventory correction, not an improvement in reachability.
- Verified exact npm tarball bytes using strongest supported lockfile integrity
  and package.json identity; sources are freshly extracted per scan while archive
  bytes are cached and reverified. Bundled dependencies trace to the containing
  verified artifact. Workspace provenance stays separate. Windows publication
  retries are bounded to the same checked source/destination paths.
- Real NodeGoat Linux/x64: 396/396 source instances, 345 artifacts, zero source
  issues. Separate macOS/x64 control: 463/463, including 66 bundled sources,
  346 artifacts, zero source issues. No target or lifecycle code executed.
- Tree-sitter JS/JSX/TS/TSX syntax extraction preserves captured-byte hashes,
  lexical owners and source spans. CommonJS calls/exports remain unresolved
  candidates until binding analysis. Errors and unsupported encodings are
  explicit. Reports bound long text excerpts while retaining complete ranges.
  Native 0.26.0 crashed reproducibly on Windows; the dependency is constrained
  to >=0.25.2,<0.26, and 0.25.2 passed the failing cases and real-source audit.
- Real AST audit: 1,680 modules, 19,156 functions, 65,949 call expressions,
  5,452 imports, zero parse issues. This is syntax coverage, not a call graph.
- VDB minimum raised to 6.6.1 after the existing venv's 6.6.0 caused full-index
  scans. EXPLAIN confirms the corrected query uses indexed prefix lookup.
  Stopped only the confirmed slow SCA processes, reused completed source/AST
  artifacts and completed SCA in 0.578s. Redundant empty-result PURL queries were
  removed. SCA: 47 package/advisory rows, all with unsupported JS reachability.
- 327 tests passed in the project venv (reports/pytest-node-final-01). CI now
  installs the node extra; no remote CI execution is claimed. Main evidence:
  reports/nodegoat-syntax-v1/validation.json, docs/NPM.md, source manifests and
  the separate Darwin source control.

JS module/entry/export resolution, contextual call graphs and diff mapping still
remain before any JS reachability verdict. The ten original requirements are
not complete; all earlier outstanding acceptance checks remain applicable.


- Final serialization check: 327 tests passed (reports/pytest-node-final-02).
  The compact real-source AST run retained all 1,680 source hashes and the exact
  function/call/import counts, reducing intermediate JSON from 115,159,003 to
  69,768,676 bytes. Evidence: reports/nodegoat-syntax-v1/syntax-compact-validation.json.
  Syntax extraction is still not resolved module/call reachability.


## API review and report usability checkpoint, 2026-10-30

- Added optional post-scan OpenAI Responses, DeepSeek Chat Completions and
  Claude Messages transports. Explicit provider/model and environment key;
  bounded evidence/request counts/output tokens, no automatic retries or tools.
  Preview writes exact request bodies without network. Code excerpts are opt-in.
- Opinions preserve static findings and appear separately in JSON, HTML and
  SARIF. Schema, completion status and evidence IDs are checked. Provider errors
  remain errors; keys/error bodies are not retained. Packets, prompt version,
  timestamp and input digest support review. ID validation does not prove the
  correctness of model reasoning. Live credentialed provider calls remain open.
- Reports now offer status cards, search and combined status/severity/package
  filters, five compact columns, closed evidence/patch/reference disclosures,
  and a suggested next action for primary blocker categories. The package map
  starts closed and hides clean packages; repeated same-version instances share
  a node while preserving their count. Large maps cap drawn nodes at 150 and
  show labels on hover/focus. Star links are labeled as overview links, not
  dependency or call edges. All affected packages remain in the package list.
- 351 Python tests passed before the final text-only triage hints. Offline
  20-case corpus remains seven positives, ten negatives, three expected unknown,
  with no incorrect conclusions in those cases. No target application ran.
- Isolated DOM checks passed for saved NodeGoat (47 findings), Whoogle (53) and
  the exact new CI fixture (all four statuses and 180 components), both with
  local D3 and with no D3. Search/filter combinations, counters, graph cap,
  default collapse, labels and missing-CDN fallback are exercised. The new CI
  job was exercised locally; no remote CI execution is claimed yet.
- Visual viewport inspection is still outstanding: browser policy rejected the
  local file URL. No alternate browser or URL workaround was attempted. Local
  DOM checks do not establish screenshot quality. Artifacts remain under
  reports/report-readability-v1; usage is in docs/AI_REVIEW.md.

All ten original requirements remain open. This checkpoint adds API integration
and usability; it does not complete JS/TS reachability, independently reviewed
application coverage or the other outstanding analysis requirements.


## Verified source context for API review, 2026-10-30

- Added explicit, repeatable --source-root with --include-code. Python source
  context is admitted only when the selected root exactly matches a recorded
  scan snapshot and the recomputed relative-path/content digest agrees. Missing,
  changed or ambiguous snapshots remain source issues. Legacy reports do not
  gain unverified current-code excerpts.
- Capture, digest and extraction share immutable in-memory bytes. Definitions
  are qualified against the scanner module-name contract; duplicate definitions
  cannot borrow identity. Functions, classes, module windows, actual modeled
  paths, speculative paths and scan-wide diagnostics keep distinct roles/scopes.
  Hunk duplicates are grouped before limiting distinct patch targets.
- Excerpts retain original contiguous lines, encoding, file SHA256, UTF-8 excerpt
  SHA256 and scan-root digest. Whole/partial flags and omitted-reference markers
  are explicit. LF/CRLF and non-newline Unicode separators inside literals are
  covered. Resource limits bound files, roots, bytes and excerpts. No target
  module is executed; unselected roots are not captured.
- --dry-run --sbom now produces a clearly labeled local HTML request preview,
  including readable source disclosures; JSON remains the exact request bodies.
  No API key or provider request is needed for preview. HTML source is escaped,
  and completed opinions retain the same inspectable packet in HTML/JSON/SARIF.
- 386 Python tests passed (reports/pytest-review-sources-full-20261030-06).
  The 20-case offline corpus is unchanged: seven positives, ten negatives,
  three expected unknown, zero wrong conclusions in those cases. Provider
  transport tests verify the same source packet enters all three adapters.
- Saved Whoogle v4.10 was not rescanned: seven existing positive findings yielded
  48 source excerpts, independently compared with their original file bytes,
  line ranges and hashes. Packet sizes remain below 48 KB. One finding retains an explicit
  selection-limit issue: four of eight distinct patch targets are selected by
  default. This omission remains visible and is not a negative conclusion. Evidence:
  reports/review-sources-v4/summary.json and per-finding packets. Local preview:
  reports/review-sources-v3/whoogle-openai-preview.html, selected CVE-2023-32681.
  This does not independently validate the underlying static findings or CVEs.
- DOM checks passed for the 53-finding real preview with and without local D3,
  and the new CI fixture checks source-disclosure toggles and escaped code.
  Previous API/report commit 962c986 passed all four remote CI jobs; this source
  extension is pending its own publication/CI run at this checkpoint.

Live account/provider calls and visual viewport checks are still outstanding.
All ten original analysis requirements remain open; source-backed AI review is
an additional triage facility, not completion of non-Python reachability.
