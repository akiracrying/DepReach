import json
import os
import re
import html as html_lib
from collections import defaultdict
from scripts.reachability_result import reachability_status, reachability_value, explain_result, suggested_next_action
from urllib.parse import urlparse


def _reference_url(value):
    value = str(value or "").strip()
    return value if urlparse(value).scheme.lower() in {"http", "https"} else ""


def _severity_rank(sev: str) -> int:
    order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "UNKNOWN": 1,
        "": 1,
        None: 1,
    }
    return order.get((sev or "").upper(), 1)


def _js_json(obj) -> str:
    """
    Serialize Python object to JSON safe to embed into <script> tag.
    """
    s = json.dumps(obj, ensure_ascii=False)
    # escape for script tag
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _clean_description(desc: str, max_len: int = 200) -> str:
    """
    Make vulnerability description compact and readable in HTML:
    - unwrap escaped newlines (\\n, \\r\\n) into spaces
    - strip markdown noise like headings and backticks
    - collapse whitespace
    - truncate to a single concise line
    """
    if not desc:
        return ""

    # normalize literal \n in text
    desc = desc.replace("\\r\\n", " ").replace("\\n", " ").replace("\\t", " ")

    # strip markdown
    desc = re.sub(r"`+", "", desc)
    desc = re.sub(r"\*+", "", desc)
    desc = re.sub(r"#+\s*", "", desc)
    desc = re.sub(r"\[.*?\]\(.*?\)", "", desc)

    # collapse whitespace
    desc = re.sub(r"\s+", " ", desc).strip()

    if len(desc) > max_len:
        desc = desc[: max_len - 1].rstrip() + "…"
    return desc


def generate_html_report(project_name: str, sbom_file: str, json_report_file: str, html_file: str, *, findings_override=None) -> None:
    """
    Generate standalone HTML report with dependency bubble graph and vulnerabilities table.
    """
    if not os.path.exists(sbom_file) or not os.path.exists(json_report_file):
        return

    with open(sbom_file, "r", encoding="utf-8") as f:
        sbom = json.load(f)
    if findings_override is None:
        with open(json_report_file, "r", encoding="utf-8") as f:
            vulns = json.load(f)
    else:
        vulns = findings_override

    # stats per purl
    per_purl = defaultdict(
        lambda: {
            "package": None,
            "version": None,
            "vulnCount": 0,
            "reachableVulnCount": 0,
            "maxSeverity": "UNKNOWN",
            "maxScore": None,
        }
    )
    vulns_by_purl = defaultdict(list)

    total_reachable = 0
    for v in vulns:
        purl = v.get("purl") or v.get("package") or "unknown"
        stats = per_purl[purl]
        stats["package"] = v.get("package") or stats["package"]
        stats["version"] = v.get("installed_version") or stats["version"]
        stats["vulnCount"] += 1

        sev = v.get("severity") or "UNKNOWN"
        score = v.get("score")
        if _severity_rank(sev) > _severity_rank(stats["maxSeverity"]):
            stats["maxSeverity"] = sev
            stats["maxScore"] = score
        elif _severity_rank(sev) == _severity_rank(stats["maxSeverity"]):
            try:
                if score is not None and (stats["maxScore"] is None or float(score) > float(stats["maxScore"])):
                    stats["maxScore"] = score
            except Exception:
                pass

        state = reachability_status(v.get("reachability"))
        is_reachable = reachability_value(v.get("reachability"))
        if is_reachable:
            stats["reachableVulnCount"] += 1
            total_reachable += 1

        # per-purl list for graph
        vulns_by_purl[purl].append(
            {
                "package": v.get("package"),
                "installed_version": v.get("installed_version"),
                "cve": v.get("cve"),
                "severity": v.get("severity"),
                "score": v.get("score"),
                "affected_version": v.get("affected_version"),
                "reachable": is_reachable,
                "reachabilityStatus": state,
                "description": _clean_description(v.get("description", "") or "", max_len=260),
            }
        )

    components = sbom.get("components", [])
    nodes = []
    root_id = "__root__"

    # root node
    nodes.append(
        {
            "id": root_id,
            "label": project_name,
            "purl": None,
            "status": "root",
            "vulnCount": sum(s["vulnCount"] for s in per_purl.values()),
            "reachableVulnCount": total_reachable,
            "maxSeverity": None,
            "maxScore": None,
        }
    )

    links = []
    node_by_id = {}
    for comp in components:
        purl = comp.get("purl")
        name = comp.get("name") or "unknown"
        version = comp.get("version") or ""
        label = f"{name} {version}".strip()
        stats = per_purl.get(purl) if purl else None

        vuln_count = stats["vulnCount"] if stats else 0
        reachable_count = stats["reachableVulnCount"] if stats else 0
        max_sev = stats["maxSeverity"] if stats else "UNKNOWN"
        max_score = stats["maxScore"] if stats else None

        if reachable_count > 0:
            status = "reachable"
        elif vuln_count > 0:
            status = "vulnerable"
        else:
            status = "clean"

        node_id = purl or f"{name}@{version}" or name
        if node_id in node_by_id:
            node_by_id[node_id]["instanceCount"] += 1
            continue
        node_by_id[node_id] = {"instanceCount": 1}
        nodes.append(
            {
                "instanceCount": 1,
                "id": node_id,
                "label": label,
                "purl": purl,
                "status": status,
                "vulnCount": vuln_count,
                "reachableVulnCount": reachable_count,
                "maxSeverity": max_sev,
                "maxScore": max_score,
            }
        )
        node_by_id[node_id] = nodes[-1]
        links.append({"source": root_id, "target": node_id})

    total_components = len(components)
    total_vulns = len(vulns)

    # for client JS
    graph_data = {"nodes": nodes, "links": links}

    from collections import Counter
    status_counts = Counter(reachability_status(v.get("reachability")) for v in vulns)
    summary_cards = "".join(
        f'<button type="button" class="summary-card" data-filter-state="{state}"><strong>{status_counts[state]}</strong>{label}</button>'
        for state, label in (("reachable", "Path found"), ("unknown", "Needs investigation"),
                             ("unsupported", "Unsupported analysis"), ("no_path_found", "No modeled path")))
    package_list = "".join(
        f'<button type="button" class="package-chip pkg-filter" data-package="{html_lib.escape(str(st["package"] or purl), quote=True)}">'
        f'{html_lib.escape(str(st["package"] or purl))} · {st["vulnCount"]}</button>'
        for purl, st in sorted(per_purl.items(), key=lambda item: (-item[1]["vulnCount"], item[0])))
    module_lookup_html = ""
    module_lookup = next((v.get("reachability", {}).get("module_lookup_summary") for v in vulns
                          if isinstance(v.get("reachability"), dict) and v["reachability"].get("module_lookup_summary")), None)
    if isinstance(module_lookup, dict):
        lookup_counts = module_lookup.get("counts", {})
        status_counts = lookup_counts.get("by_status", {})
        statuses = " | ".join(html_lib.escape(str(key) + ": " + str(value)) for key, value in sorted(status_counts.items()))
        module_lookup_html = '<details class="card"><summary>JS/TS module lookup | scan-wide candidates</summary><p>' + statuses + '</p>'
        if module_lookup.get("binding_resolution_scope") == "direct_commonjs_require_identity_only":
            binding_counts = lookup_counts.get("commonjs_bindings", {})
            binding_labels = {"verified_commonjs_wrapper": "Node require binding verified",
                              "shadowed_commonjs_identifier": "Local require binding; value flow pending",
                              "unresolved_commonjs_binding": "Require binding unresolved"}
            labels = " | ".join(html_lib.escape(binding_labels.get(key, key) + ": " + str(value))
                                for key, value in sorted(binding_counts.items()))
            explanation = 'Direct CommonJS loader identity is checked. The optional function-target audit below covers stable value candidates; vulnerability reachability is pending.' if module_lookup.get("symbol_summary") else 'Only direct CommonJS loader identity is checked. Exported values, call paths and vulnerability reachability are pending.'
            module_lookup_html += '<p>' + labels + '</p><p>' + explanation + '</p></details>'
        else:
            module_lookup_html += '<p>CommonJS bindings are unverified. Call-graph construction and vulnerability reachability are pending.</p></details>'
    if isinstance(module_lookup, dict) and isinstance(module_lookup.get("symbol_summary"), dict):
        symbols = module_lookup["symbol_summary"]
        call_counts = symbols.get("counts", {}).get("by_status", {})
        labels = " | ".join(html_lib.escape(str(key) + ": " + str(value)) for key, value in sorted(call_counts.items()))
        module_lookup_html += '<details class="card"><summary>JS function target candidates | scan-wide analysis</summary><p>' + labels + '</p><p>Stable local/imported values only. These are function targets of call expressions, including calls inside unused functions. Entrypoint paths, receiver/callback flow and vulnerability mapping are pending.</p>'
        omitted_calls = symbols.get("counts", {}).get("omitted_records", 0)
        if omitted_calls:
            module_lookup_html += '<p>' + html_lib.escape(str(omitted_calls)) + ' call records were omitted by output limits; coverage is incomplete. See the symbol summary for reasons.</p>'
        examples = symbols.get("application_examples", [])[:8]
        if examples:
            module_lookup_html += '<p>Application examples (candidates, not CVE paths):</p><ul>'
            for example in examples:
                caller = html_lib.escape(str(example.get("caller_file")) + ":" + str(example.get("caller_line")))
                target = html_lib.escape(str(example.get("target_name")))
                location = html_lib.escape(str(example.get("target_instance") or "application") + "/" + str(example.get("target_file")) + ":" + str(example.get("target_line")))
                module_lookup_html += '<li style="overflow-wrap:anywhere"><code>' + caller + '</code> → <code>' + target + '</code><br><small>' + location + '</small></li>'
            module_lookup_html += '</ul>'
        module_lookup_html += '</details>'
    project_name = html_lib.escape(project_name)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>DepReach Report — {project_name}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {{
      color-scheme: dark;
      --bg: #05060a;
      --bg-panel: #0d1117;
      --bg-panel-alt: #161b22;
      --border-subtle: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --danger: #f85149;
      --warning: #f0883e;
      --success: #3fb950;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      padding: 12px 16px;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, #0d1117 0, #020409 55%, #000 100%);
      color: var(--text);
    }}
    h1, h2, h3 {{
      margin: 0 0 8px;
      font-weight: 600;
    }}
    h1 {{
      font-size: 24px;
    }}
    h2 {{
      font-size: 18px;
    }}
    p {{
      margin: 0 0 8px;
      color: var(--text-muted);
    }}
    a {{
      color: var(--accent);
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    .page {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 6px;
      align-items: center;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid var(--border-subtle);
      background: rgba(88, 166, 255, 0.08);
      color: var(--text-muted);
      font-size: 12px;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 500;
    }}
    .pill-critical {{ background: rgba(248,81,73,0.15); color: var(--danger); border: 1px solid rgba(248,81,73,0.5); }}
    .pill-high {{ background: rgba(248,129,73,0.15); color: var(--danger); border: 1px solid rgba(248,129,73,0.5); }}
    .pill-medium {{ background: rgba(240,136,62,0.15); color: var(--warning); border: 1px solid rgba(240,136,62,0.5); }}
    .pill-low {{ background: rgba(63,185,80,0.12); color: var(--success); border: 1px solid rgba(63,185,80,0.5); }}
    .pill-info {{ background: rgba(88,166,255,0.12); color: var(--accent); border: 1px solid rgba(88,166,255,0.5); }}

    .card {{
      background: radial-gradient(circle at top left, #161b22 0, #0d1117 45%, #05060a 100%);
      border-radius: 16px;
      border: 1px solid rgba(240,246,252,0.08);
      padding: 12px 16px;
      box-shadow: 0 18px 45px rgba(0,0,0,0.6);
      margin-bottom: 16px;
    }}
    .card--compact {{
      padding: 10px 16px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-top: 8px;
    }}
    .summary-item {{
      padding: 10px 12px;
      border-radius: 12px;
      background: radial-gradient(circle at top, #161b22 0, #05060a 100%);
      border: 1px solid var(--border-subtle);
    }}
    .summary-label {{
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }}
    .summary-value {{
      font-size: 18px;
      font-weight: 600;
    }}
    .summary-sub {{
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }}

    #graph-container {{
      position: relative;
      height: 420px;
      margin-top: 4px;
    }}
    #graph {{
      width: 100%;
      height: 100%;
      border-radius: 12px;
      background: radial-gradient(circle at top, #0b1020 0, #020409 60%, #000 100%);
      border: 1px solid var(--border-subtle);
      cursor: grab;
    }}
    #graph:active {{
      cursor: grabbing;
    }}
    .node-label {{
      font-size: 12px;
      font-weight: 500;
      pointer-events: none;
      fill: #f0f6fc;
      paint-order: stroke;
      stroke: rgba(1,4,9,0.9);
      stroke-width: 0.8px;
      text-shadow: 0 1px 4px #000;
    }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 8px;
    }}
    .legend-item {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }}
    .legend-dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      display: inline-block;
    }}
    .graph-filter {{
      display: block;
      margin-top: 10px;
      font-size: 12px;
      color: var(--text-muted);
      cursor: pointer;
      user-select: none;
    }}
    .graph-filter input {{
      margin-right: 6px;
      vertical-align: middle;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      line-height: 1.55;
    }}
    thead tr {{
      background: linear-gradient(90deg, rgba(22,27,34,0.9), rgba(13,17,23,0.9));
      position: sticky;
      top: 0;
      z-index: 2;
    }}
    th, td {{
      padding: 6px 8px;
      border-bottom: 1px solid rgba(48,54,61,0.6);
      vertical-align: top;
    }}
    th {{
      text-align: left;
      font-weight: 500;
      color: var(--text-muted);
      white-space: nowrap;
    }}
    tbody tr:nth-child(even) {{
      background: rgba(13,17,23,0.65);
    }}
    tbody tr:nth-child(odd) {{
      background: rgba(1,4,9,0.8);
    }}
    tbody tr:hover {{
      background: rgba(56,139,253,0.18);
    }}
    tbody tr.highlight {{
      outline: 1px solid var(--accent);
      box-shadow: 0 0 0 1px var(--accent);
    }}
    .col-desc {{
      max-width: 380px;
      white-space: normal;
    }}
    .col-refs a {{
      display: block;
      margin-bottom: 2px;
      word-break: break-all;
      font-size: 11px;
    }}
    .more-refs {{
      font-size: 11px;
      color: var(--text-muted);
    }}
    .filter-bar {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
      padding: 14px 18px;
      font-size: 14px;
      background: var(--bg-panel-alt);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      color: var(--text);
    }}
    .filter-bar-label {{
      color: var(--text-muted);
      font-weight: 500;
    }}
    .filter-bar-pkg {{
      font-weight: 600;
      color: var(--accent);
    }}
    .filter-bar-stats {{
      color: var(--text-muted);
      font-size: 13px;
    }}
    .filter-bar button {{
      margin-left: auto;
      padding: 6px 14px;
      cursor: pointer;
      background: var(--bg-muted);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 13px;
    }}
    .filter-bar button:hover {{
      background: var(--border);
    }}
    .col-package .pkg-filter {{
      cursor: pointer;
      text-decoration: none;
      color: var(--accent);
    }}
    .col-package .pkg-filter:hover {{
      text-decoration: underline;
    }}
    .desc-toggle, .refs-toggle {{
      display: inline-block;
      margin-top: 6px;
      font-size: 11px;
      color: var(--text-muted);
      cursor: pointer;
    }}
    .desc-toggle:hover, .refs-toggle:hover {{
      text-decoration: underline;
    }}
    .desc-full, .refs-extra {{
      display: block;
      max-height: 0;
      opacity: 0;
      overflow: hidden;
      transition: max-height 0.22s ease, opacity 0.22s ease;
    }}
    .desc-full.expanded, .refs-extra.expanded {{
      max-height: 600px;
      opacity: 1;
    }}
    .severity-badge {{
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 999px;
      border: 1px solid rgba(99,110,123,0.7);
      display: inline-block;
    }}
    .severity-CRITICAL {{ border-color: rgba(248,81,73,0.8); color: var(--danger); }}
    .severity-HIGH {{ border-color: rgba(248,129,73,0.8); color: var(--danger); }}
    .severity-MEDIUM {{ border-color: rgba(240,136,62,0.8); color: var(--warning); }}
    .severity-LOW {{ border-color: rgba(63,185,80,0.8); color: var(--success); }}

    .reach-pill {{
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 999px;
      border: 1px solid rgba(99,110,123,0.7);
      display: inline-flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
    }}
    /* A missing modeled path is not a safety verdict. */
    .reach-yes {{
      border-color: rgba(248,81,73,0.9);
      background: rgba(248,81,73,0.18);
      color: var(--danger);
    }}
    .reach-no {{
      border-color: rgba(240,136,62,0.9);
      background: rgba(240,136,62,0.16);
      color: var(--warning);
    }}
    .reach-unknown {{ border-color: rgba(139,148,158,0.8); color: var(--text-muted); }}

    .table-wrapper {{
      max-height: 1000px;
      overflow: auto;
      border-radius: 12px;
      border: 1px solid rgba(48,54,61,0.8);
      background: radial-gradient(circle at top, #111827 0, #05060a 50%, #000 100%);
    }}

    @media (max-width: 720px) {{
      .header {{
        flex-direction: column;
        align-items: flex-start;
      }}
      #graph-container {{
        height: 360px;
      }}
      .col-desc {{
        max-width: 260px;
      }}
    }}
    .summary-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:20px 0; }}
    button, input, select {{ font:inherit; }}
    .summary-card {{ text-align:left; border:1px solid var(--border-subtle); border-radius:12px; background:var(--bg-panel); color:var(--text-muted); padding:16px; cursor:pointer; }}
    .summary-card strong {{ display:block; font-size:28px; color:var(--text); margin-bottom:4px; }}
    .toolbar {{ display:flex; flex-wrap:wrap; align-items:end; gap:12px; margin:16px 0; }}
    .toolbar label {{ display:grid; gap:5px; font-size:13px; color:var(--text-muted); }}
    .toolbar input, .toolbar select {{ border:1px solid var(--border-subtle); color:var(--text); background:var(--bg-panel-alt); border-radius:7px; padding:9px; }}
    #finding-search {{ width: min(360px,75vw); }}
    .package-chip {{ margin:4px; padding:6px 10px; background:var(--bg-panel-alt); border:1px solid var(--border-subtle); border-radius:20px; color:var(--accent); cursor:pointer; }}
    .package-list {{ max-height:160px; overflow:auto; margin:12px 0; }}
    details > summary {{ cursor:pointer; padding:8px 0; color:var(--accent); }}
    details pre {{ max-height:360px; overflow:auto; padding:12px; background:var(--bg-panel); border-radius:7px; font-size:12px; overflow-wrap:anywhere; }}
    .col-analysis {{ min-width:230px; max-width:380px; }}
    .col-analysis p {{ font-size:12px; margin-top:8px; line-height:1.5; }}
    .col-package small {{ display:block; color:var(--text-muted); margin-top:5px; }}
    .ai-opinion {{ border-left:2px solid var(--accent); padding-left:10px; margin-top:10px; }}
    .table-wrapper {{ max-height:none; background:var(--bg-panel); }}
    #vuln-table {{ table-layout:auto; }}
    #vuln-table td {{ vertical-align:top; padding:16px 12px; overflow-wrap:anywhere; }}
    #vuln-table th {{ background:var(--bg-panel-alt); }}
    .node-label {{ pointer-events:none; }}
    #graph-note, #results-count {{ font-size:13px; margin:8px 0; }}
    @media(max-width:800px) {{ .summary-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .table-wrapper {{ overflow-x:auto; }} #vuln-table {{ min-width:850px; }} }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div>
        <div class="badge">
          <span>DepReach · Reachability-aware SCA</span>
        </div>
        <h1>Security report for <span style="color: var(--accent)">{project_name}</span></h1>
        <p>Components: {total_components} · Vulnerabilities: {total_vulns} · Reachable: {total_reachable}</p>
      </div>
    </div>

    <div class="summary-grid">{summary_cards}</div>
    {module_lookup_html}
    <p>Static paths and incomplete analysis are shown separately. Select a count to filter findings.</p>
    <details class="card" id="dependency-map">
      <summary>Explore dependencies · {total_components} installed components</summary>
      <div class="package-list">{package_list}</div>
      <h2>Package risk overview</h2>
      <p>Packages are grouped by name and version. Lines connect packages to the project; they do not represent call paths. Hover or focus a node for its label.</p>
      <div id="graph-container">
        <svg id="graph"></svg>
      </div>
      <div class="legend">
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--danger)"></span> reachable vulnerability
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--warning)"></span> vulnerable (no confirmed path)
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--success)"></span> no known vulnerabilities
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--accent)"></span> project root
        </div>
      </div>
      <label class="graph-filter">
        <input type="checkbox" id="hide-clean-nodes" checked> Hide packages with no vulnerabilities
      </label>
      <p id="graph-note" role="status"></p>
    </details>

    <div class="card card--compact">
      <h2>Vulnerabilities</h2>
      <p>Paths found first, then severity. Expand evidence only when you need it.</p>
      <div class="toolbar">
        <label>Search findings<input type="search" id="finding-search" placeholder="Package, CVE, description…" /></label>
        <label>Call analysis<select id="status-filter"><option value="">All statuses</option><option value="reachable">Path found</option><option value="unknown">Needs investigation</option><option value="unsupported">Unsupported</option><option value="no_path_found">No modeled path</option></select></label>
        <label>Severity<select id="severity-filter"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option></select></label>
      </div>
      <p id="results-count" role="status" aria-live="polite"></p>
      <p id="no-matches" hidden>No findings match these filters. Clear the search or change the filters.</p>
      <div id="table-filter-bar" class="filter-bar" style="display:none">
        <span class="filter-bar-label">Filter:</span>
        <span id="filter-pkg-name" class="filter-bar-pkg"></span>
        <span id="filter-stats" class="filter-bar-stats"></span>
        <button type="button" id="clear-filter">Show all</button>
      </div>
      <div class="table-wrapper">
        <table id="vuln-table">
          <thead>
            <tr>
              <th>Package</th>
              <th>Finding</th>
              <th>Call analysis / evidence</th>
              <th class="col-desc">Description</th>
              <th class="col-refs">Advisory details</th>
            </tr>
          </thead>
          <tbody>
"""

    # sort: reachable first, then severity/score
    def _vuln_sort_key(v):
        reachable = reachability_status(v.get("reachability")) == "reachable"
        sev = v.get("severity") or "UNKNOWN"
        score = v.get("score")
        try:
            score_val = float(score) if score is not None else -1.0
        except Exception:
            score_val = -1.0
        return (0 if reachable else 1, -_severity_rank(sev), -score_val)

    vulns_sorted = sorted(vulns, key=_vuln_sort_key)

    for v in vulns_sorted:
        pkg = v.get("package", "")
        ver = v.get("installed_version", "")
        purl = v.get("purl", "")
        cve = v.get("cve", "")
        sev = (v.get("severity") or "UNKNOWN").upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            sev = "UNKNOWN"
        score = v.get("score", "")
        affected = v.get("affected_version", "")
        cwe = v.get("CWE", "") or ""
        desc = v.get("description", "") or ""
        refs = v.get("references") or []
        reach = v.get("reachability") or {}

        # short + full desc
        short_desc = _clean_description(desc, max_len=220)
        full_desc = _clean_description(desc, max_len=4096)
        short_desc_html = html_lib.escape(short_desc)
        full_desc_html = html_lib.escape(full_desc)

        state = reachability_status(reach)
        reach_status = {"reachable": "yes", "no_path_found": "no"}.get(state, "unknown")
        reach_label = state.replace("_", " ")

        pkg_esc = html_lib.escape(pkg)
        purl, ver, cve, affected, cwe = [html_lib.escape(str(value or ""), quote=True) for value in (purl, ver, cve, affected, cwe)]
        reach_attr = reach_status
        html += f'            <tr data-purl="{purl}" data-package="{pkg_esc}" data-reachable="{reach_attr}" data-status="{state}" data-severity="{sev}">\n'
        html += f'              <td class="col-package"><span class="pkg-filter" data-package="{pkg_esc}" title="Filter by this package">{pkg_esc}</span><small>{ver}</small></td>\n'
        html += f'<td>{cve}<br/><span class="severity-badge severity-{sev}">{sev}</span> · {html_lib.escape(str(score or "—"))}</td>'
        html += '<td class="col-analysis">'
        html += f'<span class="reach-pill reach-{reach_status}">{reach_label}</span>'
        html += '<p><strong>Next:</strong> ' + html_lib.escape(suggested_next_action(reach)) + '</p>'
        if isinstance(reach, dict) and (reach.get("reasons") or reach.get("paths")):
            html += '<p>' + html_lib.escape(explain_result(reach)) + '</p>'
            details = []
            if v.get("component_refs"):
                details.append("SBOM instances: " + ", ".join(v["component_refs"]))
            for function in reach.get("function_results", []):
                details.append(function["symbol"] + " — path " + function["call_path_status"] + " (" + function["status"] + ")")
            for mapping in reach.get("mappings", []):
                details.append(f"{mapping['symbol']} @ {mapping['file']}:{mapping['line']} [{mapping['method']}]")
            for review in reach.get("reviewed_targets", []):
                details.append(f"Reviewed model {review['model_id']}: {review['symbol']} [{review['status']}]; exploit conditions not evaluated")
            for mapping in reach.get("mappings", []):
                if mapping.get("mapping_evidence"):
                    details.append(f"{mapping['symbol']}: {mapping['mapping_evidence']}; {mapping['vulnerability_evidence']}")
            for path in reach.get("paths", []):
                details.append(" → ".join(step["symbol"] + (" [possible callback]" if step.get("edge_kind") == "passed_callable_may_be_invoked" else "") for step in path))
            details.extend(reach.get("reasons", []))
            for path in reach.get("speculative_paths", []):
                details.append("Speculative callback path (invocation unverified): " + " -> ".join(step["symbol"] for step in path))
            for path in reach.get("paths", []):
                for step in path:
                    callback = step.get("callback_evidence")
                    if callback:
                        details.append(f"Callback {callback['parameter']} invoked by {callback['consumer']} at {callback['consumer_file']}:{callback['invocation_lines']}")
            explanation = html_lib.escape("\n".join(details))
            html += f'<details><summary>Evidence / limitations</summary><pre style="white-space:pre-wrap">{explanation}</pre></details>'
        if reach.get("patch_evidence"):
            patch_text = []
            for item in reach["patch_evidence"]:
                patch_text.append(f"{item['reference']}\n{item['file']}:{item['old_start']} — {item.get('outcome', 'unmapped')}")
                if item.get("parent_url"):
                    patch_text.append("Fix parent: " + item["parent_url"])
                patch_text.append("Old context:\n" + item["old_context"])
                patch_text.extend(("+" if c["kind"] == "added" else "-") + c["text"] for c in item["changes"])
            html += '<details><summary>Fix diff / function mapping</summary><pre style="white-space:pre-wrap">' + html_lib.escape("\n\n".join(patch_text)) + '</pre></details>'
        for opinion in v.get("ai_reviews", []):
            provider = html_lib.escape(str(opinion.get("provider", "")))
            model = html_lib.escape(str(opinion.get("model", "")))
            preview = opinion.get("status") == "preview"
            heading = "AI request preview" if preview else "AI second opinion"
            html += f'<details class="ai-opinion"><summary>{heading} | {provider}</summary><p>{model} | Static verdict unchanged</p>'
            if preview:
                html += '<p>Local preview only. No API request has been sent.</p>'
            elif opinion.get("status") == "completed":
                html += '<p><strong>' + html_lib.escape(str(opinion.get("assessment", ""))) + '</strong></p>'
                html += '<p>' + html_lib.escape(str(opinion.get("summary", ""))) + '</p>'
                text = str(opinion.get("reasoning", "")) + "\nEvidence: " + ", ".join(opinion.get("evidence_ids", []))
                text += "\n" + "\n".join(opinion.get("next_steps", []))
                html += '<pre>' + html_lib.escape(text) + '</pre>'
            else:
                html += '<p>Review unavailable: ' + html_lib.escape(str(opinion.get("error", "unknown error"))) + '</p>'
            if opinion.get("evidence_packet"):
                for entry in opinion["evidence_packet"].get("evidence", []):
                    value = entry.get("value") or {}
                    if entry.get("kind") != "source_excerpt" or not isinstance(value, dict) or not isinstance(value.get("code"), str):
                        continue
                    label = f"Source {entry.get('id', '')}: {value.get('symbol', '')}"
                    location = f"{value.get('relative_path', '')}:{value.get('excerpt_start_line', '')}-{value.get('excerpt_end_line', '')}"
                    scope = "Whole definition" if value.get("whole_definition") else "Partial context"
                    html += '<details class="source-excerpt"><summary>' + html_lib.escape(label) + '</summary>'
                    html += '<p>' + html_lib.escape(location + " | " + scope + " | " + str(value.get("provenance", ""))) + '</p>'
                    html += '<pre><code>' + html_lib.escape(value["code"]) + '</code></pre>'
                    html += '<p>File SHA256: <code>' + html_lib.escape(str(value.get("file_sha256", ""))) + '</code></p></details>'
                html += '<details><summary>Evidence sent to provider</summary><pre>' + html_lib.escape(json.dumps(opinion["evidence_packet"], ensure_ascii=False, indent=2)) + '</pre></details>'
            html += '</details>'
        html += "</td>\n"
        html += '              <td class="col-desc">\n'
        html += f'                <span class="desc-short">{short_desc_html}</span>\n'
        html += f'                <span class="desc-full">{full_desc_html}</span>\n'
        if full_desc:
            html += '                <span class="desc-toggle">Show more</span>\n'
        html += "              </td>\n"

        html += '              <td class="col-refs">\n'
        html += f'<details><summary>Versions, CWE &amp; links</summary><p>Affected: {affected}</p><p>{cwe}</p>'
        if refs:
            visible_refs = [u for u in refs if (u or '').strip()]
            main_refs = visible_refs[:2]
            extra_refs = visible_refs[2:]
            for url in main_refs:
                clean_url = _reference_url(url)
                if not clean_url:
                    continue
                url_esc = html_lib.escape(clean_url, quote=True)
                html += f'                <a href="{url_esc}" target="_blank" rel="noreferrer noopener">{html_lib.escape(clean_url)}</a><br/>\n'
            if extra_refs:
                html += '                <div class="refs-extra">\n'
                for url in extra_refs:
                    clean_url = _reference_url(url)
                    if not clean_url:
                        continue
                    url_esc = html_lib.escape(clean_url, quote=True)
                    html += f'                  <a href="{url_esc}" target="_blank" rel="noreferrer noopener">{html_lib.escape(clean_url)}</a><br/>\n'
                html += "                </div>\n"
                more = len(extra_refs)
                html += f"                <span class='refs-toggle'>Show all ({more} more)</span>\n"
        html += "              </details></td>\n"
        html += "            </tr>\n"

    html += """          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="https://d3js.org/d3.v7.min.js"></script>
  <script>
    const graphData = """ + _js_json(graph_data) + """;
    const vulnsByPurl = """ + _js_json(vulns_by_purl) + """;

    // graph
    (function() {
      const panel = document.getElementById("dependency-map");
      const checkbox = document.getElementById("hide-clean-nodes");
      function drawGraph() {
      const note = document.getElementById("graph-note");
      if (typeof d3 === "undefined") { note.textContent = "Interactive graph unavailable offline. Use the package list above to filter findings."; return; }
      const svg = d3.select("#graph");
      svg.selectAll("*").remove();
      const container = document.getElementById("graph-container");
      const width = container.clientWidth || 800;
      const height = container.clientHeight || 400;
      svg.attr("width", width).attr("height", height);

      const selected = graphData.nodes.filter(n => !checkbox.checked || n.status !== "clean");
      const nodes = selected.slice(0, 150).map(n => Object.assign({}, n));
      const ids = new Set(nodes.map(n => n.id));
      const links = graphData.links.filter(l => ids.has(l.source) && ids.has(l.target)).map(l => Object.assign({}, l));
      note.textContent = nodes.length + " package groups shown" + (selected.length > 150 ? " · capped at 150; use the package list for every finding" : "") + ". Hover or keyboard-focus nodes for names.";

      function radius(d) {
        if (d.id === "__root__") return 26;
        const base = 10;
        const extra = Math.min(16, (d.vulnCount || 0) * 2);
        return base + extra;
      }

      function color(d) {
        if (d.id === "__root__") return "#58a6ff";
        if (d.status === "reachable") return "#f85149";
        if (d.status === "vulnerable") return "#f0883e";
        if (d.status === "clean") return "#3fb950";
        return "#6e7681";
      }

      const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(90).strength(0.5))
        .force("charge", d3.forceManyBody().strength(-220))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(d => radius(d) + 6));

      const zoomG = svg.append("g");

      const link = zoomG.append("g")
        .attr("stroke", "#30363d")
        .attr("stroke-opacity", 0.5)
        .attr("stroke-width", 1)
        .selectAll("line")
        .data(links)
        .enter()
        .append("line");

      const node = zoomG.append("g")
        .attr("stroke", "#010409")
        .attr("stroke-width", 1.5)
        .selectAll("circle")
        .data(nodes)
        .enter()
        .append("circle")
        .attr("r", d => radius(d))
        .attr("fill", d => color(d))
        .attr("tabindex", 0)
        .attr("role", "button")
        .attr("aria-label", d => d.label + ": " + d.vulnCount + " findings; " + d.instanceCount + " instances")
        .call(d3.drag()
          .on("start", dragstarted)
          .on("drag", dragged)
          .on("end", dragended)
        );

      const label = zoomG.append("g")
        .selectAll("text")
        .data(nodes)
        .enter()
        .append("text")
        .attr("class", "node-label")
        .attr("text-anchor", "middle")
        .attr("dy", d => d.id === "__root__" ? 4 : 3)
        .text(d => d.label.length > 28 ? d.label.slice(0, 26) + "…" : d.label)
        .style("visibility", d => nodes.length <= 14 || d.id === "__root__" ? "visible" : "hidden");
      node.append("title").text(d => d.label + " · " + (d.instanceCount || 1) + " instance(s)");
      node.on("mouseenter focus", (_, d) => label.style("visibility", n => n.id === d.id ? "visible" : "hidden"));
      node.on("mouseleave blur", () => label.style("visibility", d => nodes.length <= 14 || d.id === "__root__" ? "visible" : "hidden"));
      node.on("keydown", function(event, d) { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); this.dispatchEvent(new MouseEvent("click", {bubbles:true})); } });

      svg.call(d3.zoom()
        .scaleExtent([0.25, 4])
        .on("zoom", function(event) {
          zoomG.attr("transform", event.transform);
        }));

      node.on("click", function(event, d) {
        if (!d.purl) {
          clearHighlights();
          if (typeof window.clearVulnPackageFilter === "function") {
            window.clearVulnPackageFilter();
          }
          return;
        }
        const rows = document.querySelectorAll("#vuln-table tbody tr");
        rows.forEach(row => {
          if (row.getAttribute("data-purl") === d.purl) {
            row.classList.add("highlight");
          } else {
            row.classList.remove("highlight");
          }
        });

        if (typeof window.setVulnPackageFilter === "function") {
          const list = vulnsByPurl[d.purl] || [];
          const pkg = list.length ? (list[0].package || null) : null;
          if (pkg) {
            window.setVulnPackageFilter(pkg);
          }
        }
      });

      function clearHighlights() {
        const rows = document.querySelectorAll("#vuln-table tbody tr.highlight");
        rows.forEach(r => r.classList.remove("highlight"));
      }

      simulation.on("tick", () => {
        link
          .attr("x1", d => d.source.x)
          .attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x)
          .attr("y2", d => d.target.y);

        node
          .attr("cx", d => d.x)
          .attr("cy", d => d.y);

        label
          .attr("x", d => d.x)
          .attr("y", d => d.y);
      });

      function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.2).restart();
        d.fx = d.x;
        d.fy = d.y;
      }

      function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
      }

      function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }

      simulation.on("end.cleanup", () => simulation.stop());
      if (window.depreachGraphSimulation) window.depreachGraphSimulation.stop();
      window.depreachGraphSimulation = simulation;
      }
      panel.addEventListener("toggle", () => {
        if (panel.open) drawGraph();
        else if (window.depreachGraphSimulation) window.depreachGraphSimulation.stop();
      });
      checkbox.addEventListener("change", drawGraph);
    })();

    // table toggles
    (function() {
      const table = document.getElementById("vuln-table");
      if (!table) return;

      table.addEventListener("click", function (event) {
        const target = event.target;

        // desc
        if (target.classList.contains("desc-toggle")) {
          const cell = target.closest(".col-desc");
          if (!cell) return;
          const shortEl = cell.querySelector(".desc-short");
          const fullEl = cell.querySelector(".desc-full");
          if (!shortEl || !fullEl) return;

          const expanded = fullEl.classList.contains("expanded");
          if (expanded) {
            fullEl.classList.remove("expanded");
            shortEl.style.display = "";
            target.textContent = "Show more";
          } else {
            fullEl.classList.add("expanded");
            shortEl.style.display = "none";
            target.textContent = "Show less";
          }
          return;
        }

        // refs
        if (target.classList.contains("refs-toggle")) {
          const cell = target.closest(".col-refs");
          if (!cell) return;
          const extra = cell.querySelector(".refs-extra");
          if (!extra) return;

          const expanded = extra.classList.contains("expanded");
          if (expanded) {
            extra.classList.remove("expanded");
            const more = extra.querySelectorAll("a").length;
            target.textContent = "Show all (" + more + " more)";
          } else {
            extra.classList.add("expanded");
            target.textContent = "Show less";
          }
        }
      });
    })();

    // package filter
    (function() {
      let currentFilter = null;
      const search = document.getElementById("finding-search");
      const statusFilter = document.getElementById("status-filter");
      const severityFilter = document.getElementById("severity-filter");
      const filterBar = document.getElementById("table-filter-bar");
      const filterPkgName = document.getElementById("filter-pkg-name");
      const filterStats = document.getElementById("filter-stats");
      const clearBtn = document.getElementById("clear-filter");
      const table = document.getElementById("vuln-table");

      function updateFilterStats() {
        if (!filterStats || !table) return;
        const rows = table.querySelectorAll("tbody tr");
        let visible = 0, reachable = 0;
        rows.forEach(row => {
          if (row.style.display !== "none") {
            visible++;
            if (row.getAttribute("data-reachable") === "yes") reachable++;
          }
        });
        document.getElementById("results-count").textContent = visible + " of " + rows.length + " findings";
        document.getElementById("no-matches").hidden = visible !== 0;
        filterStats.textContent = visible ? (visible + " vuln" + (visible !== 1 ? "s" : "") + ", " + reachable + " reachable") : "";
      }

      function applyFilter() {
        const rows = table ? table.querySelectorAll("tbody tr") : [];
        rows.forEach(row => {
          const pkg = row.getAttribute("data-package");
          const match = (currentFilter === null || pkg === currentFilter)
            && (!statusFilter.value || row.dataset.status === statusFilter.value)
            && (!severityFilter.value || row.dataset.severity === severityFilter.value)
            && (!search.value.trim() || row.textContent.toLowerCase().includes(search.value.trim().toLowerCase()));
          row.style.display = match ? "" : "none";
        });
        updateFilterStats();
      }

      function setFilter(pkg) {
        currentFilter = pkg;
        if (filterBar) {
          filterBar.style.display = "";
          if (filterPkgName) filterPkgName.textContent = pkg;
        }
        applyFilter();
      }

      function clearFilter() {
        currentFilter = null;
        search.value = ""; statusFilter.value = ""; severityFilter.value = "";
        if (filterBar) filterBar.style.display = "none";
        applyFilter();
      }

      search.addEventListener("input", applyFilter);
      statusFilter.addEventListener("change", applyFilter);
      severityFilter.addEventListener("change", applyFilter);
      document.querySelectorAll(".summary-card").forEach(button => button.addEventListener("click", () => {
        currentFilter = null; search.value = ""; severityFilter.value = "";
        statusFilter.value = button.dataset.filterState;
        if (filterBar) filterBar.style.display = "";
        if (filterPkgName) filterPkgName.textContent = "All packages";
        applyFilter();
      }));
      document.querySelectorAll(".package-list .pkg-filter").forEach(button => button.addEventListener("click", () => setFilter(button.dataset.package)));
      applyFilter();
      window.setVulnPackageFilter = setFilter;
      window.clearVulnPackageFilter = clearFilter;

      if (table) {
        table.addEventListener("click", function(event) {
          const target = event.target;
          if (target.classList.contains("pkg-filter")) {
            const pkg = target.getAttribute("data-package");
            if (!pkg) return;
            setFilter(pkg);
          }
        });
      }
      if (clearBtn) {
        clearBtn.addEventListener("click", function() {
          clearFilter();
        });
      }
    })();
  </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(html_file) or ".", exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)



def main(argv=None):
    """Re-render saved scan evidence without rescanning or API requests."""
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--input", required=True, help="Saved findings JSON")
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--output", required=True, help="New HTML file")
    parser.add_argument("--project", default="DepReach")
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists() or not Path(args.input).is_file() or not Path(args.sbom).is_file():
        parser.error("input and SBOM must exist; output must be a new file")
    generate_html_report(args.project, args.sbom, args.input, args.output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
