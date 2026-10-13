# Next implementation steps

Publication checkpoint: 2026-10-13. Python static reachability and the npm
inventory/source/syntax foundation are ready for review. JS/TS reachability is
not implemented. The existing ten requirements remain open; this is their
implementation order, not a completion claim.

## Current evidence

- Local verification: 327 tests passed; offline corpus: 20 cases, seven positive,
  ten negative, three expected indeterminate, zero incorrect conclusions.
- Historical full Whoogle v4.10: 53 findings, seven reachable, 46 unknown,
  zero no_path_found. It was not rescanned for this publication checkpoint.
- Historical NodeGoat: 396 verified source instances, 1,680 parsed modules,
  47 package/advisory findings. All JS reachability verdicts are unsupported.
- Reports, downloaded databases, source archives and application checkouts stay
  local. Reproduction commands and pinned revisions are in REAL_APPS.md,
  EVALUATION.md and NPM.md.

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
8. **Implement JS/TS reachability end to end.** First test Node module resolution
   (require/import, exports/imports, nested copies, aliases/workspaces) against
   Node itself without executing target modules. Then bind symbols, build call
   paths, map immutable patches and integrate evidence into reports. The local
   node_resolution.py prototype is untested, unconnected and excluded from this
   publication. Native and other unsupported language boundaries stay explicit.
9. **Expand independent real-application evaluation.** Add reviewed positive,
   negative and unknown cases beyond the small current corpus, including JS.
   Measure wrong conclusions and abstentions separately. Current labels have
   not received independent external human review.
10. **Keep scans reusable and reports actionable.** Preserve content-aware cache
    invalidation and per-instance provenance. Measure full scans on fixed inputs;
    show primary blockers and next actions without unbounded intermediate output.

Detailed implementation evidence and outstanding conditions:
[implementation ledger](IMPLEMENTATION_STATUS.md).
