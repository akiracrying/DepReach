# Next implementation steps

Publication checkpoint: 2026-10-13. Python static reachability and the npm
inventory/source/syntax foundation are ready for review. JS/TS reachability is
not implemented. The existing ten requirements remain open; this is their
implementation order, not a completion claim.

## Publication baseline (2026-10-13)

- Local verification: 327 tests passed; offline corpus: 20 cases, seven positive,
  ten negative, three expected indeterminate, zero incorrect conclusions.
- Historical full Whoogle v4.10: 53 findings, seven reachable, 46 unknown,
  zero no_path_found. It was not rescanned for this publication checkpoint.
- Historical NodeGoat: 396 verified source instances, 1,680 parsed modules,
  47 package/advisory findings. All JS reachability verdicts are unsupported.
- Reports, downloaded databases, source archives and application checkouts stay
  local. Reproduction commands and pinned revisions are in REAL_APPS.md,
  EVALUATION.md and NPM.md.

Latest working-tree checkpoint (2026-10-30): 592 tests passed with one Windows
symlink skip; direct CommonJS require identity and optional stable function
target candidates are checked. Detailed scope and
real-application evidence are in IMPLEMENTATION_STATUS.md and NPM.md.

## Priorities and acceptance criteria

1. **Explain and scope unknown results.** For each affected function, report the
   exact missing source, unresolved call or mapping failure that blocks the
   verdict. Unrelated gaps must not poison every finding. Preserve unknown when
   a relevant path remains unmodeled; never rename it to not reachable.
2. **Complete exact-version dependency sources.** Resolve intermediate libraries
   and missing transitive versions from a consistent inventory. Validate against
   real applications with deliberately missing and conflicting dependencies.
3. **Finish fix discovery and version mapping.** Follow advisory/PR/commit
   provenance, select the relevant version branch and handle renamed symbols.
   Add providers beyond supported GitHub references and explicit failure cases.
4. **Separate changed code from vulnerability-specific targets.** A patch can
   contain tests and unrelated refactoring. Preserve evidence levels and expand
   reviewed exact-version target models; a structural path is not exploitability.
5. **Extend Python framework and object flow.** Cover framework registrations,
   decorators, returned instances, closures and receiver contexts with both
   positive examples and hidden-call counterexamples.
6. **Extend callback flow.** Model forwarding and stored-then-invoked callbacks.
   Passing or storing a function alone must not establish invocation.
7. **Complete environment and lock support.** Add unresolved Python lock/group
   coverage and npm semver, engines/libc checks; add pnpm/Yarn after npm v2/v3.
   Keep runtime/dev/optional scope and alternative versions explicit.
8. **Implement JS/TS reachability end to end.** Candidate module lookup is now
   connected to npm CLI and tested against Node for declared 22/24 default
   cases. Direct CommonJS require identity now has lexical scope checks.
   Optional --resolve-symbols now resolves supported stable CJS/ESM values and
   function target candidates. Next establish entrypoints and contextual call
   paths, receiver/return/callback flow, then immutable vulnerability fix maps. Preserve contextual installation
   identity, shadowed require/exports, returned values and callbacks. Native,
   compiler and unsupported loader boundaries remain explicit; npm findings
   still have unsupported reachability. See NPM.md for current scope.
9. **Expand independent real-application evaluation.** Add reviewed positive,
   negative and unknown cases beyond the small current corpus, including JS.
   Measure wrong conclusions and abstentions separately. Current labels have
   not received independent external human review.
10. **Keep scans reusable and reports actionable.** Preserve content-aware cache
    invalidation and per-instance provenance. Measure full scans on fixed inputs;
    show primary blockers and next actions without unbounded intermediate output.

Detailed implementation evidence and outstanding conditions:
[implementation ledger](IMPLEMENTATION_STATUS.md).


## Active extension: optional API review and report readability

The current checkout implements bounded post-scan review through OpenAI,
DeepSeek and Claude, plus compact/filterable reports and an optional package
map. See AI_REVIEW.md for preview, keys, explicit model selection and examples.
This feature is not in the published 0.2.0 package yet.

Remaining checks and work:

1. Verify actual provider calls using a selected account/model and credentials;
   current tests verify mocked wire contracts, not live account access.
2. Inspect report screenshots on desktop/mobile; local file URL access was
   rejected by browser policy. DOM behavior is checked locally and in a
   CI job; commit 962c986 passed that remote job. Visual viewport checks remain
   outstanding.
3. Verify the new snapshot-matched caller/function excerpt workflow in a live
   provider account. Explicit-root selection, preview, source hashes, bounded
   excerpts and readable local HTML preview are implemented and locally tested.
4. Continue contextual JS/TS symbol and call-graph work after the new module
   lookup audit, alongside the remaining ten analysis requirements. AI opinions
   do not replace those implementations.
