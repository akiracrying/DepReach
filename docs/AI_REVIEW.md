# Optional API review

DepReach's scan and static verdicts work without AI. The optional second step
reviews an existing JSON report through OpenAI, DeepSeek or Claude. It appends
`ai_reviews` beside each selected finding; it never changes reachability,
severity, call paths or scan exit codes. AI opinions are triage suggestions,
not proof of exploitability or a reason to suppress an incomplete finding.

## Preview before sending

From C:/Projects/DepReach, choose new output paths:

```powershell
.\venv\Scripts\python.exe -m scripts.ai_review `
  --input reports/nodegoat-syntax-v1/vulnerabilities.json `
  --output reports/nodegoat-ai-request-preview.json `
  --provider openai --model YOUR_MODEL_ID --limit 2 --dry-run
```

This writes the exact endpoint and JSON request bodies without network calls or
credentials. `YOUR_MODEL_ID` is a placeholder: use an actual model ID available
in your provider account. No default model is silently selected.

The input contains bounded advisory text, package identity, static statuses,
mapped symbols, modeled paths, reasons and available patch provenance. Source
files are not opened. Common file/source/root fields and credential-like keys
are excluded from structured evidence. Existing reports can still contain
sensitive information in arbitrary prose: inspect the preview before sending
private-project evidence to a provider. `--include-code` explicitly adds bounded
old patch context and changed-line excerpts already present in the report.
The packet is capped at 48 KB, with explicit truncation/omission markers.

## Run a review

Set the selected provider's key in your process environment, then run:

```powershell
.\venv\Scripts\python.exe -m scripts.ai_review `
  --input reports/nodegoat-syntax-v1/vulnerabilities.json `
  --output reports/nodegoat-reviewed.json `
  --provider openai --model YOUR_MODEL_ID --limit 2 `
  --sbom reports/nodegoat-syntax-v1/sbom.json `
  --sarif reports/nodegoat-reviewed.sarif
```

| Provider flag | Environment variable | API |
| --- | --- | --- |
| openai | OPENAI_API_KEY | OpenAI Responses, JSON schema, store=false |
| deepseek | DEEPSEEK_API_KEY | DeepSeek Chat Completions, JSON mode |
| claude | ANTHROPIC_API_KEY | Anthropic Messages, version 2023-06-01 |

Change both `--provider` and `--model` to use another service. A normal install
already supplies requests; no provider SDK is required. After reinstalling this
checkout, `depreach-review` is also available as a console command.
The new code is in the current checkout; the previously published 0.2.0 package
does not yet contain this feature.

The command writes a new JSON file. `--sbom` also renders its HTML neighbor;
`--sarif` adds a separate SARIF export. Existing input/output files are not
overwritten. Re-reviewing a reviewed JSON appends another opinion, preserving
previous providers and the original static evidence.

Selection and request bounds:

- `--limit` defaults to five findings, maximum 100. Each selected finding causes
  at most one request, sequentially, without automatic retries.
- Repeat `--finding CVE_OR_GHSA` to select specific advisories; selection follows
  report order and is then capped by the limit.
- `--max-tokens` defaults to 1,600 output tokens per request, maximum 16,000.
- `--timeout` sets the read timeout (default 60 seconds); connect timeout is 10.
- Preview returns 0. A completed review batch returns 0; provider/schema errors
  are retained per finding and return 3. These codes concern the review step,
  not the vulnerability status of the scanned application.

## Evidence contract

Each opinion is `supports_static`, `challenges_static` or
`insufficient_evidence`, with a summary, reasoning, cited evidence IDs and next
steps. References to nonexistent evidence IDs and uncited determinate opinions
are rejected. Provider refusal, malformed/truncated output, HTTP errors, timeout
and responses over 1 MB remain errors; they cannot become negative findings.

JSON records provider/model, timestamp, prompt version, input SHA256, bounded
input packet, token usage when available and the separate AI opinion. HTML
shows those opinions under a closed disclosure; SARIF keeps them in
`properties.aiReviews` beside unchanged static properties. Provider error
bodies and API keys are not saved. The code never executes model suggestions
or calls model tools. Evidence citations validate IDs, not the correctness of
the model's reasoning.

Provider contracts were checked against the official documentation:
[OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses),
[DeepSeek JSON output](https://api-docs.deepseek.com/guides/json_mode/),
[Claude Messages](https://platform.claude.com/docs/en/api/messages).
Tests use mocked transports; live calls with user-supplied credentials have not
been verified in this checkpoint.

## Refresh an existing report without a scan or API

```powershell
.\venv\Scripts\python.exe -m scripts.html_report `
  --input reports/nodegoat-syntax-v1/vulnerabilities.json `
  --sbom reports/nodegoat-syntax-v1/sbom.json `
  --output reports/nodegoat-readable.html --project NodeGoat
```

The report starts with status counts and filterable findings. The package map
is closed initially and hides packages with no findings by default. Duplicate
installations of one package version share a node with an instance count.
At most 150 package groups are drawn; the package list retains all packages
with findings. Labels appear on hover/focus in crowded views. Star-shaped lines
show a package overview, not dependency edges or call paths. The list and table
remain usable when the optional D3 CDN is unavailable.

DOM checks (no network resources or target application code execute):

```powershell
npm install --prefix reports/report-dom-tools --ignore-scripts --no-audit --no-fund jsdom@26.1.0 d3@7.9.0
node tests/report_dom_check.cjs reports/report-readability-v1/report.html
```

The checks exercise search, combined filters, status counts, package selection,
graph limits and missing-CDN fallback. They do not establish visual quality at
a particular viewport. A browser visual check is still outstanding because the
in-app browser rejected local file URLs under its URL policy.
