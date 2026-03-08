import json
import os
import re
import html as html_lib
from collections import defaultdict


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
    return s.replace("</script>", "<\\/script>")


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


def generate_html_report(project_name: str, sbom_file: str, json_report_file: str, html_file: str) -> None:
    """
    Generate standalone HTML report with dependency bubble graph and vulnerabilities table.
    """
    if not os.path.exists(sbom_file) or not os.path.exists(json_report_file):
        return

    with open(sbom_file, "r", encoding="utf-8") as f:
        sbom = json.load(f)
    with open(json_report_file, "r", encoding="utf-8") as f:
        vulns = json.load(f)

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

        reach = v.get("reachability") or {}
        is_reachable = False
        if isinstance(reach, dict):
            for info in reach.values():
                if isinstance(info, dict) and info.get("is_reachable"):
                    is_reachable = True
                    break
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
        nodes.append(
            {
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
        links.append({"source": root_id, "target": node_id})

    total_components = len(components)
    total_vulns = len(vulns)

    # for client JS
    graph_data = {"nodes": nodes, "links": links}

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
      font-size: 12px;
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
    /* reachable = bad (red), not reachable = good (green) */
    .reach-yes {{
      border-color: rgba(248,81,73,0.9);
      background: rgba(248,81,73,0.18);
      color: var(--danger);
    }}
    .reach-no {{
      border-color: rgba(63,185,80,0.9);
      background: rgba(63,185,80,0.16);
      color: var(--success);
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

    <div class="card">
      <h2>Dependency graph</h2>
      <p>Each bubble is a dependency; color shows risk. Drag nodes to explore.</p>
      <div id="graph-container">
        <svg id="graph"></svg>
      </div>
      <div class="legend">
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--danger)"></span> reachable vulnerability
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--warning)"></span> vulnerable (not reachable)
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--success)"></span> no known vulnerabilities
        </div>
        <div class="legend-item">
          <span class="legend-dot" style="background: var(--accent)"></span> project root
        </div>
      </div>
      <label class="graph-filter">
        <input type="checkbox" id="hide-clean-nodes"> Hide packages with no vulnerabilities
      </label>
    </div>

    <div class="card card--compact">
      <h2>Vulnerabilities</h2>
      <p>Sorted by severity; reachable issues are highlighted. Click a package name to filter by it.</p>
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
              <th>Version</th>
              <th>CVE</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Reachable?</th>
              <th class="col-desc">Description</th>
              <th>Affected</th>
              <th>CWE</th>
              <th class="col-refs">References</th>
            </tr>
          </thead>
          <tbody>
"""

    # sort: reachable first, then severity/score
    def _vuln_sort_key(v):
        reach = v.get("reachability") or {}
        reachable = False
        if isinstance(reach, dict):
            for info in reach.values():
                if isinstance(info, dict) and info.get("is_reachable"):
                    reachable = True
                    break
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

        # reachability
        reach_status = "unknown"
        if isinstance(reach, dict) and reach:
            any_yes = any(isinstance(info, dict) and info.get("is_reachable") for info in reach.values())
            any_no = any(isinstance(info, dict) and info.get("is_reachable") is False for info in reach.values())
            if any_yes:
                reach_status = "yes"
            elif any_no:
                reach_status = "no"

        if reach_status == "yes":
            reach_label = "reachable"
        elif reach_status == "no":
            reach_label = "not reachable"
        else:
            reach_label = "unknown"

        pkg_esc = html_lib.escape(pkg)
        reach_attr = "yes" if reach_status == "yes" else "no"
        html += f'            <tr data-purl="{purl}" data-package="{pkg_esc}" data-reachable="{reach_attr}">\n'
        html += f'              <td class="col-package"><span class="pkg-filter" data-package="{pkg_esc}" title="Filter by this package">{pkg_esc}</span></td>\n'
        html += f"              <td>{ver}</td>\n"
        html += f"              <td>{cve}</td>\n"
        html += f'              <td><span class="severity-badge severity-{sev}">{sev}</span></td>\n'
        html += f"              <td>{score}</td>\n"
        html += '              <td>'
        html += f'<span class="reach-pill reach-{reach_status}">{reach_label}</span>'
        html += "</td>\n"
        html += '              <td class="col-desc">\n'
        html += f'                <span class="desc-short">{short_desc_html}</span>\n'
        html += f'                <span class="desc-full">{full_desc_html}</span>\n'
        if full_desc:
            html += '                <span class="desc-toggle">Show more</span>\n'
        html += "              </td>\n"
        html += f"              <td>{affected}</td>\n"
        html += f"              <td>{cwe}</td>\n"
        html += '              <td class="col-refs">\n'
        if refs:
            visible_refs = [u for u in refs if (u or '').strip()]
            main_refs = visible_refs[:2]
            extra_refs = visible_refs[2:]
            for url in main_refs:
                clean_url = (url or '').strip()
                if not clean_url:
                    continue
                url_esc = clean_url.replace('"', "%22")
                html += f'                <a href="{url_esc}" target="_blank" rel="noreferrer noopener">{html_lib.escape(clean_url)}</a><br/>\n'
            if extra_refs:
                html += '                <div class="refs-extra">\n'
                for url in extra_refs:
                    clean_url = (url or '').strip()
                    if not clean_url:
                        continue
                    url_esc = clean_url.replace('"', "%22")
                    html += f'                  <a href="{url_esc}" target="_blank" rel="noreferrer noopener">{html_lib.escape(clean_url)}</a><br/>\n'
                html += "                </div>\n"
                more = len(extra_refs)
                html += f"                <span class='refs-toggle'>Show all ({more} more)</span>\n"
        html += "              </td>\n"
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
      const svg = d3.select("#graph");
      const container = document.getElementById("graph-container");
      const width = container.clientWidth || 800;
      const height = container.clientHeight || 400;
      svg.attr("width", width).attr("height", height);

      const nodes = graphData.nodes;
      const links = graphData.links;

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
        .text(d => d.label.length > 22 ? d.label.slice(0, 20) + "…" : d.label);

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

      const hideCleanCheckbox = document.getElementById("hide-clean-nodes");
      function updateCleanVisibility() {
        const hideClean = hideCleanCheckbox ? hideCleanCheckbox.checked : false;
        node.style("display", d => (hideClean && d.status === "clean") ? "none" : null);
        label.style("display", d => (hideClean && d.status === "clean") ? "none" : null);
        link.style("display", d => {
          if (!hideClean) return null;
          const s = d.source, t = d.target;
          return (s.status === "clean" || t.status === "clean") ? "none" : null;
        });
      }
      if (hideCleanCheckbox) {
        hideCleanCheckbox.addEventListener("change", updateCleanVisibility);
      }
      updateCleanVisibility();
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
        filterStats.textContent = visible ? (visible + " vuln" + (visible !== 1 ? "s" : "") + ", " + reachable + " reachable") : "";
      }

      function applyFilter() {
        const rows = table ? table.querySelectorAll("tbody tr") : [];
        rows.forEach(row => {
          const pkg = row.getAttribute("data-package");
          row.style.display = currentFilter === null || pkg === currentFilter ? "" : "none";
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
        if (filterBar) filterBar.style.display = "none";
        applyFilter();
      }

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

    os.makedirs(os.path.dirname(html_file), exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)

