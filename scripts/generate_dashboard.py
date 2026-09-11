#!/usr/bin/env python3
"""
Generates a professional, self-contained HTML security dashboard from the
scanner outputs (Trivy, Semgrep, Gitleaks, Conftest/OPA). No external
dependencies - everything (fonts fallback, icons, styling) is inline so it
works as a Jenkins-archived artifact with no internet connection required.

Run from the repo root after the scan stages. Reads *-results.json from the
current directory and writes dashboard/report.html.
"""

import json
import os
from datetime import datetime, timezone
from collections import Counter

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLOR = {
    "CRITICAL": "#B91C1C",
    "HIGH": "#C2410C",
    "MEDIUM": "#A16207",
    "LOW": "#15803D",
    "UNKNOWN": "#6B7280",
}
SEVERITY_BG = {
    "CRITICAL": "#FEF2F2",
    "HIGH": "#FFF7ED",
    "MEDIUM": "#FFFBEB",
    "LOW": "#F0FDF4",
    "UNKNOWN": "#F9FAFB",
}

# ---------------------------------------------------------------------------
# Hand-drawn inline icon set (stroke-based, 20x20, currentColor) - no emoji,
# no external icon font/CDN dependency.
# ---------------------------------------------------------------------------
ICONS = {
    "shield": '<path d="M10 2.5 4 4.8v5.2c0 4.2 2.6 7 6 8.5 3.4-1.5 6-4.3 6-8.5V4.8L10 2.5Z"/><path d="m7.3 10 1.9 1.9L12.9 8"/>',
    "alert": '<path d="M10 2.5 18.5 17h-17L10 2.5Z"/><path d="M10 8v3.6"/><circle cx="10" cy="14.2" r="0.15" fill="currentColor"/>',
    "package": '<path d="M10 2.8 3.2 6.4v7.2L10 17.2l6.8-3.6V6.4L10 2.8Z"/><path d="M3.6 6.6 10 10l6.4-3.4"/><path d="M10 10v7.1"/>',
    "key": '<circle cx="6.5" cy="13.5" r="3.5"/><path d="m8.9 11.1 7.6-7.6"/><path d="m13.5 6.5 2 2"/><path d="m11 9 2 2"/>',
    "code": '<path d="M7.5 5.5 2.5 10l5 4.5"/><path d="m12.5 5.5 5 4.5-5 4.5"/>',
    "file-check": '<path d="M6 2.5h6l3.5 3.5V17a.6.6 0 0 1-.6.6H6.6A.6.6 0 0 1 6 17V3.1a.6.6 0 0 1 .6-.6Z"/><path d="M12 2.5V6h3.5"/><path d="m8.3 11.5 1.8 1.8 3.4-3.6"/>',
    "clock": '<circle cx="10" cy="10" r="7.3"/><path d="M10 5.8V10l3 2"/>',
    "git-branch": '<circle cx="5.5" cy="4.5" r="1.8"/><circle cx="5.5" cy="15.5" r="1.8"/><circle cx="14.5" cy="8.5" r="1.8"/><path d="M5.5 6.3v7.4"/><path d="M5.5 9.5c0-2.2 1.8-4 4-4h3.2"/>',
    "check-circle": '<circle cx="10" cy="10" r="7.3"/><path d="m6.8 10.2 2.2 2.2 4.2-4.8"/>',
    "x-circle": '<circle cx="10" cy="10" r="7.3"/><path d="m7.3 7.3 5.4 5.4"/><path d="m12.7 7.3-5.4 5.4"/>',
    "layers": '<path d="M10 2.8 2.8 7 10 11.2 17.2 7 10 2.8Z"/><path d="m2.8 10.5 7.2 4.2 7.2-4.2"/><path d="m2.8 14 7.2 4.2 7.2-4.2"/>',
    "external": '<path d="M8.3 4.5H4.7a1 1 0 0 0-1 1v9.8a1 1 0 0 0 1 1h9.8a1 1 0 0 0 1-1v-3.6"/><path d="M11.8 3.5h4.7v4.7"/><path d="M16.3 3.7 9.8 10.2"/>',
}


def icon(name, size=18, color="currentColor"):
    body = ICONS.get(name, "")
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 20 20" fill="none" '
            f'stroke="{color}" stroke-width="1.6" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>')


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default if default is not None else {}


def trivy_findings():
    data = load_json("trivy-results.json", default={})
    rows = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            rows.append({
                "severity": vuln.get("Severity", "UNKNOWN"),
                "col1": vuln.get("PkgName", ""),
                "col2": vuln.get("VulnerabilityID", ""),
                "col3": vuln.get("Title") or vuln.get("Description", "")[:100],
                "fixed": vuln.get("FixedVersion", "-"),
            })
    return rows


def semgrep_findings():
    data = load_json("semgrep-results.json", default={})
    rows = []
    for res in data.get("results", []):
        sev = res.get("extra", {}).get("severity", "INFO").upper()
        sev = "HIGH" if sev == "ERROR" else ("MEDIUM" if sev == "WARNING" else "LOW")
        rows.append({
            "severity": sev,
            "col1": f'{res.get("path","")}:{res.get("start",{}).get("line","")}',
            "col2": res.get("check_id", ""),
            "col3": res.get("extra", {}).get("message", "")[:100],
            "fixed": "-",
        })
    return rows


def gitleaks_findings():
    data = load_json("gitleaks-results.json", default=[])
    entries = data if isinstance(data, list) else []
    rows = []
    for leak in entries:
        rows.append({
            "severity": "CRITICAL",
            "col1": leak.get("File", ""),
            "col2": leak.get("RuleID", "secret"),
            "col3": leak.get("Description", "Possible hardcoded credential"),
            "fixed": "-",
        })
    return rows


def policy_findings():
    rows = []
    for path, label in [("dockerfile-policy-results.json", "Dockerfile"),
                         ("k8s-policy-results.json", "Kubernetes")]:
        data = load_json(path, default=[])
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                rows.append({
                    "severity": "HIGH",
                    "col1": label,
                    "col2": entry.get("filename", label),
                    "col3": str(failure.get("msg", failure))[:110],
                    "fixed": "-",
                })
    return rows


def kpi_counts(all_rows):
    c = Counter(r["severity"] for r in all_rows)
    return c


def render_table(rows, col_headers):
    if not rows:
        return f'<div class="empty-state">{icon("check-circle", 22, "#15803D")}<p>No findings in this category.</p></div>'
    rows_sorted = sorted(rows, key=lambda r: SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 99)
    body = ""
    for r in rows_sorted:
        color = SEVERITY_COLOR.get(r["severity"], "#6B7280")
        bg = SEVERITY_BG.get(r["severity"], "#F9FAFB")
        body += (
            f'<tr>'
            f'<td><span class="sev-pill" style="color:{color};background:{bg};border-color:{color}22">{r["severity"]}</span></td>'
            f'<td class="mono">{r["col1"]}</td>'
            f'<td class="mono">{r["col2"]}</td>'
            f'<td>{r["col3"]}</td>'
            f'<td class="mono">{r["fixed"]}</td>'
            f'</tr>'
        )
    h1, h2 = col_headers
    return f"""
    <table>
      <thead><tr><th>Severity</th><th>{h1}</th><th>{h2}</th><th>Description</th><th>Fix available</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def main():
    os.makedirs("dashboard", exist_ok=True)

    trivy_rows = trivy_findings()
    semgrep_rows = semgrep_findings()
    gitleaks_rows = gitleaks_findings()
    policy_rows = policy_findings()
    all_rows = trivy_rows + semgrep_rows + gitleaks_rows + policy_rows

    counts = kpi_counts(all_rows)
    total = len(all_rows)
    high_crit = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    gate_passed = high_crit == 0

    # Build metadata - reads real Jenkins env vars if present, sensible
    # local fallbacks otherwise.
    repo_url = os.environ.get("REPO_URL", "https://github.com/KowshikaM/Shift_left_Devsecops")
    jenkins_url = os.environ.get("JENKINS_BUILD_URL", "http://localhost:8080/job/secure-devops-pipeline/")
    branch = os.environ.get("GIT_BRANCH", "main")
    commit = os.environ.get("GIT_COMMIT", "local")[:8]
    build_number = os.environ.get("BUILD_NUMBER", "local")
    job_name = os.environ.get("JOB_NAME", "secure-devops-pipeline")
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    status_label = "Gate passed" if gate_passed else "Gate failed"
    status_icon = "check-circle" if gate_passed else "x-circle"
    status_color = "#15803D" if gate_passed else "#B91C1C"
    status_bg = "#F0FDF4" if gate_passed else "#FEF2F2"

    def kpi_card(label, value, color):
        return f"""
        <div class="kpi-card">
          <div class="kpi-value" style="color:{color}">{value}</div>
          <div class="kpi-label">{label}</div>
        </div>"""

    kpis = "".join([
        kpi_card("Critical", counts.get("CRITICAL", 0), SEVERITY_COLOR["CRITICAL"]),
        kpi_card("High", counts.get("HIGH", 0), SEVERITY_COLOR["HIGH"]),
        kpi_card("Medium", counts.get("MEDIUM", 0), SEVERITY_COLOR["MEDIUM"]),
        kpi_card("Low", counts.get("LOW", 0), SEVERITY_COLOR["LOW"]),
        kpi_card("Total findings", total, "#131A29"),
    ])

    tabs_meta = [
        ("sast", "Static code analysis", "code", semgrep_rows, ("Location", "Rule")),
        ("secrets", "Secret detection", "key", gitleaks_rows, ("File", "Rule")),
        ("container", "Container vulnerabilities", "package", trivy_rows, ("Package", "CVE")),
        ("policy", "Policy enforcement", "file-check", policy_rows, ("Target", "File")),
    ]

    tab_buttons = "".join(
        f'<button class="tab-btn{" active" if i == 0 else ""}" data-tab="{key}">'
        f'<span class="tab-icon">{icon(ic, 16)}</span>{title}'
        f'<span class="tab-count">{len(rows)}</span></button>'
        for i, (key, title, ic, rows, _) in enumerate(tabs_meta)
    )

    tab_panels = "".join(
        f'<div class="tab-panel{" active" if i == 0 else ""}" id="panel-{key}">'
        f'{render_table(rows, headers)}</div>'
        for i, (key, title, ic, rows, headers) in enumerate(tabs_meta)
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Pipeline Report — {job_name}</title>
<style>
  :root {{
    --bg: #F6F7F9;
    --surface: #FFFFFF;
    --border: #E4E7EC;
    --text: #131A29;
    --text-muted: #5B6472;
    --accent: #0E7490;
    --accent-soft: #ECFEFF;
    --radius: 10px;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Inter, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }}
  .mono {{
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.82rem;
  }}
  .wrap {{ max-width: 1120px; margin: 0 auto; padding: 2.5rem 1.75rem 4rem; }}

  header.top {{
    display: flex; justify-content: space-between; align-items: flex-start;
    gap: 1.5rem; margin-bottom: 1.75rem; flex-wrap: wrap;
  }}
  .brand {{ display: flex; align-items: center; gap: 0.65rem; }}
  .brand-mark {{
    width: 38px; height: 38px; border-radius: 9px; background: var(--accent);
    display: flex; align-items: center; justify-content: center; color: white; flex-shrink: 0;
  }}
  .brand h1 {{ font-size: 1.3rem; margin: 0; letter-spacing: -0.01em; }}
  .brand p {{ margin: 0.1rem 0 0; color: var(--text-muted); font-size: 0.88rem; }}

  .meta-row {{
    display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.83rem; color: var(--text-muted);
  }}
  .meta-item {{ display: flex; align-items: center; gap: 0.4rem; }}
  .meta-item a {{ color: var(--accent); text-decoration: none; }}
  .meta-item a:hover {{ text-decoration: underline; }}

  .status-banner {{
    display: flex; align-items: center; gap: 0.6rem;
    background: {status_bg}; color: {status_color};
    border: 1px solid {status_color}33; border-radius: var(--radius);
    padding: 0.7rem 1rem; font-weight: 600; font-size: 0.92rem; margin-bottom: 1.75rem;
  }}

  .kpi-strip {{
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.9rem; margin-bottom: 2rem;
  }}
  .kpi-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1.1rem 1.2rem;
  }}
  .kpi-value {{ font-size: 1.7rem; font-weight: 650; letter-spacing: -0.02em; }}
  .kpi-label {{ font-size: 0.8rem; color: var(--text-muted); margin-top: 0.15rem; }}

  .panel-shell {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden;
  }}
  .tab-bar {{
    display: flex; border-bottom: 1px solid var(--border); overflow-x: auto;
  }}
  .tab-btn {{
    display: flex; align-items: center; gap: 0.45rem;
    background: none; border: none; cursor: pointer;
    padding: 0.9rem 1.15rem; font-size: 0.88rem; font-weight: 500; color: var(--text-muted);
    border-bottom: 2px solid transparent; white-space: nowrap; font-family: inherit;
  }}
  .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab-icon {{ display: flex; }}
  .tab-count {{
    background: var(--border); color: var(--text); font-size: 0.72rem; font-weight: 600;
    padding: 0.05rem 0.45rem; border-radius: 999px; margin-left: 0.15rem;
  }}
  .tab-btn.active .tab-count {{ background: var(--accent-soft); color: var(--accent); }}

  .tab-panel {{ display: none; padding: 0.25rem 0; }}
  .tab-panel.active {{ display: block; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{
    text-align: left; font-weight: 600; color: var(--text-muted);
    padding: 0.7rem 1.15rem; border-bottom: 1px solid var(--border); font-size: 0.78rem;
    text-transform: none;
  }}
  td {{ padding: 0.65rem 1.15rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #FAFBFC; }}

  .sev-pill {{
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.72rem; font-weight: 650; border: 1px solid; letter-spacing: 0.01em;
  }}

  .empty-state {{
    display: flex; flex-direction: column; align-items: center; gap: 0.6rem;
    padding: 3rem 1rem; color: var(--text-muted); text-align: center;
  }}
  .empty-state p {{ margin: 0; font-size: 0.9rem; }}

  footer {{
    margin-top: 2rem; padding-top: 1.25rem; border-top: 1px solid var(--border);
    font-size: 0.78rem; color: var(--text-muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;
  }}

  @media (max-width: 720px) {{
    .kpi-strip {{ grid-template-columns: repeat(2, 1fr); }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="brand">
      <div class="brand-mark">{icon("shield", 20, "white")}</div>
      <div>
        <h1>Security Pipeline Report</h1>
        <p>{job_name}</p>
      </div>
    </div>
    <div class="meta-row">
      <span class="meta-item">{icon("git-branch", 15)} {branch} &middot; <span class="mono">{commit}</span></span>
      <span class="meta-item">{icon("clock", 15)} {timestamp}</span>
      <span class="meta-item">{icon("external", 15)} <a href="{repo_url}" target="_blank" rel="noopener">Repository</a></span>
      <span class="meta-item">{icon("external", 15)} <a href="{jenkins_url}" target="_blank" rel="noopener">Build #{build_number}</a></span>
    </div>
  </header>

  <div class="status-banner">
    {icon(status_icon, 18, status_color)} {status_label} — {high_crit} critical/high finding(s) across {total} total
  </div>

  <div class="kpi-strip">
    {kpis}
  </div>

  <div class="panel-shell">
    <div class="tab-bar">
      {tab_buttons}
    </div>
    {tab_panels}
  </div>

  <footer>
    <span>Generated automatically by the Secure DevOps Pipeline</span>
    <span>Tools: Semgrep &middot; Gitleaks &middot; Trivy &middot; OPA/Conftest</span>
  </footer>

</div>

<script>
  document.querySelectorAll('.tab-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    }});
  }});
</script>
</body>
</html>
"""

    with open("dashboard/report.html", "w") as f:
        f.write(html)

    print("[dashboard] Written to dashboard/report.html")


if __name__ == "__main__":
    main()
