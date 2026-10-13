# Reachability evaluation

Labels live in `tests/corpus/cases.json` and are not generated from scanner
outputs. Each case states its target symbol, structural-path label and source
reasoning. Real-library and application checkouts must match pinned commits and
have clean worktrees. Fixture code and target applications are never executed.

The labels were source-reviewed by the coding assistant, not by an external
human reviewer. This is a regression corpus rather than an ecosystem accuracy
estimate. Scope is all first-party functions and module code, with possible
structural calls; argument-dependent execution and exploitability are separate.
For example, disabled Requests redirects remain structurally connected while
not satisfying the advisory's runtime conditions.

## Reproduce

From `C:/Projects/DepReach`, choose a new output directory:

```powershell
& C:/Python10/python.exe -m scripts.evaluate_corpus --output reports/my-corpus-run
& C:/Python10/python.exe -m scripts.evaluate_corpus --offline --output reports/my-offline-corpus --min-coverage 0.70
```

The full run includes 20 synthetic controls, eight callers against pinned
Requests/Werkzeug source, and two unchanged real applications (Whoogle and
Linkding). Full runs can fetch dependency source distributions and public fix
diffs. Offline runs explicitly exclude ten real-source cases; they do not
pretend those cases passed.

The exit code is nonzero for a wrong positive/negative conclusion, an unsupported
conclusion on an indeterminate label, or coverage below an explicitly supplied
threshold. Unknown/unsupported results on known labels are abstentions. They are
not true negatives and do not inflate decision coverage. Missing denominators
produce null metrics rather than 100%.

## Verified result: v4.6

`reports/labeled-corpus-v4.6/summary.json` records 30 cases: 12 true positives,
9 true negatives, 4 abstentions, and 5 expected indeterminate results. No wrong
conclusions were observed in these cases. Decision coverage is 21/25 = 84%; the
five independently indeterminate labels are excluded from that denominator.
Coverage was 80% before property-getter support. The expected labels did not
change between those runs. The same corpus SHA256 is stored in both summaries.

Remaining known-label abstentions:

- `callback_return_ignored`: target is **absent**, analysis is `unknown`. The returned function is discarded. Passing and returning a function do not invoke it.
- `callback_return_invoked`: target is **present**, analysis is `unknown`. The returned callback is stored and then invoked by the caller.
- `callback_unreachable_supply`: target is **absent**, analysis is `unknown`. Only an uncalled dependency function supplies danger; the live caller supplies safe.
- `escaped_hidden_dispatch`: target is **absent**, analysis is `unknown`. keep returns the function and the caller discards it. Even though its body has an unresolved call, this callback is never invoked by the supplied program.

The application cases establish positive target paths for selected advisories;
they are not whole-application precision measurements. Negative controls use
small programs and real-library callers where the expected absence can be
reviewed directly. Expand labels before using this corpus to justify automated
alert suppression.


## Verified result: v4.10

`reports/labeled-corpus-v4.10/summary.json` records 30 cases: 13 true positives,
12 true negatives and five expected indeterminate results. All 25 determinate
labels were resolved with no observed incorrect conclusions. The case labels
are unchanged from v4.6; this is regression-case coverage, not a claim of 100%
accuracy on arbitrary applications.

The four v4.6 abstentions listed above are resolved by two changes: tracking
unchanged callback returns (including discarded returns), and scoping formal
callback invocation to all modeled reachable argument bindings. Additional
counterexample tests retain uncertainty for unknown callers, stored returns,
shadowing, mixed expressions and arbitrary first-party arguments. General
callback forwarding, closures and framework registries still need wider models
and additional independent application labels.
