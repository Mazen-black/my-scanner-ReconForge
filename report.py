"""Generate a self-contained, escaped HTML report from ReconForge JSON results."""
import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path


def _e(value, default="—"):
    """HTML-escape untrusted values before placing them in the report."""
    if value is None or value == "":
        value = default
    return html.escape(str(value), quote=True)


def _severity(score):
    if not isinstance(score, (int, float)):
        return "Unknown"
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _score_sort(cve):
    score = cve.get("cvss")
    return score if isinstance(score, (int, float)) else -1


def _cve_rows(cves):
    rows = []
    for cve in sorted(cves or [], key=_score_sort, reverse=True):
        score = cve.get("cvss")
        severity = cve.get("severity") or _severity(score)
        applicability = cve.get("applicability") or {}
        status = applicability.get("status", "candidate_unverified")
        css = {
            "Critical": "critical", "High": "high", "Medium": "medium",
            "Low": "low", "None": "none",
        }.get(severity, "unknown")
        score_text = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
        rows.append(
            '<tr>'
            f'<td><strong>{_e(cve.get("id"))}</strong></td>'
            f'<td><span class="severity {css}">{_e(severity)}</span></td>'
            f'<td class="numeric">{_e(score_text)}</td>'
            f'<td>{_e(status)}</td>'
            f'<td>{_e(cve.get("summary"))}</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="5" class="empty">No CVE results recorded.</td></tr>'


def _exploit_rows(exploits):
    rows = []
    for exploit in exploits or []:
        assessment = exploit.get("assessment") or {}
        rows.append(
            '<tr>'
            f'<td>{_e(exploit.get("id"))}</td>'
            f'<td>{_e(exploit.get("title"))}</td>'
            f'<td>{_e(exploit.get("platform"))}</td>'
            f'<td>{_e(assessment.get("relevance", "unassessed"))}</td>'
            f'<td>{_e(assessment.get("confidence", "low"))}</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="5" class="empty">No matching Exploit-DB entries recorded.</td></tr>'


def render_html_report(results, target="Unknown", generated_at=None):
    """Return a complete standalone HTML report. All source data is escaped."""
    results = results if isinstance(results, list) else []
    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    open_ports = len(results)
    cves = [cve for item in results for cve in (item.get("cve_assessment") or [])]
    exploits = [exploit for item in results for exploit in (item.get("searchsploit_assessment") or [])]
    confirmed_matches = sum(
        1 for cve in cves
        if (cve.get("applicability") or {}).get("status") == "version_match"
    )
    high_critical = sum(
        1 for cve in cves
        if _severity(cve.get("cvss")) in ("High", "Critical")
    )

    service_rows = []
    for item in sorted(results, key=lambda row: (str(row.get("host", "")), int(row.get("port") or 0))):
        service = item.get("service") or {}
        service_rows.append(
            '<tr>'
            f'<td>{_e(item.get("host"))}</td>'
            f'<td class="numeric">{_e(item.get("port"))}</td>'
            f'<td>{_e(service.get("name"))}</td>'
            f'<td>{_e(service.get("product"))}</td>'
            f'<td>{_e(service.get("version"))}</td>'
            f'<td>{_e(item.get("state"))}</td>'
            '</tr>'
        )
    services_html = "".join(service_rows) or '<tr><td colspan="6" class="empty">No open services recorded.</td></tr>'

    limitations = []
    for item in results:
        for note in item.get("assessment_limits") or []:
            if note not in limitations:
                limitations.append(note)
    limitation_html = "".join(f"<li>{_e(note)}</li>" for note in limitations)
    if not limitation_html:
        limitation_html = "<li>Findings require manual validation before remediation or risk decisions.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="ReconForge network reconnaissance and vulnerability assessment report">
<title>ReconForge Report — {_e(target)}</title>
<style>
:root{{--bg:#0b1020;--panel:#131c30;--line:#26344f;--text:#e8eef9;--muted:#9aabc5;--accent:#6ee7b7}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,Segoe UI,Arial,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:34px 22px 60px}}header{{padding:26px 0 22px;border-bottom:1px solid var(--line)}}
.eyebrow{{color:var(--accent);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:12px}}
h1{{font-size:clamp(28px,5vw,42px);margin:8px 0}}h2{{font-size:20px;margin:0 0 16px}}
.sub,.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:22px 0 30px}}
.card,section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.metric{{font-size:30px;font-weight:750;margin-top:5px}}section{{margin:16px 0;overflow:hidden}}
.table-wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;min-width:720px}}th,td{{padding:12px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}tr:last-child td{{border-bottom:0}}
.numeric{{font-variant-numeric:tabular-nums}}.severity{{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;font-weight:700;background:#344155}}
.critical,.high{{background:#542c39;color:#ffb4c0}}.medium{{background:#59472b;color:#ffdb91}}.low{{background:#214b43;color:#9af0d4}}.none{{background:#344155}}.unknown{{background:#344155;color:#c5d0e0}}
.empty{{color:var(--muted);text-align:center;padding:24px}}li{{margin:7px 0;color:var(--muted)}}footer{{color:var(--muted);font-size:12px;padding:20px 2px}}
@media print{{:root{{--bg:#fff;--panel:#fff;--line:#ddd;--text:#111;--muted:#555}}body{{background:#fff;color:#111}}main{{max-width:none;padding:0}}section,.card{{break-inside:avoid}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">ReconForge / Security Assessment</div>
<h1>Network Scan Report</h1>
<div class="sub">Target: <strong>{_e(target)}</strong> · Generated: {_e(generated_at)}</div></header>
<div class="cards">
<div class="card"><div class="muted">Open services</div><div class="metric">{open_ports}</div></div>
<div class="card"><div class="muted">CVE references</div><div class="metric">{len(cves)}</div></div>
<div class="card"><div class="muted">High / Critical CVEs</div><div class="metric">{high_critical}</div></div>
<div class="card"><div class="muted">Version matches</div><div class="metric">{confirmed_matches}</div></div>
<div class="card"><div class="muted">Exploit references</div><div class="metric">{len(exploits)}</div></div>
</div>
<section><h2>Discovered Services</h2><div class="table-wrap"><table>
<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr></thead>
<tbody>{services_html}</tbody></table></div></section>
<section><h2>CVE Assessment</h2><p class="muted">References are ranked by CVSS. Applicability status is based on available NVD CPE evidence.</p>
<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Applicability</th><th>Summary</th></tr></thead>
<tbody>{_cve_rows(cves)}</tbody></table></div></section>
<section><h2>Exploit-DB References</h2><div class="table-wrap"><table><thead><tr><th>EDB ID</th><th>Title</th><th>Platform</th><th>Relevance</th><th>Confidence</th></tr></thead>
<tbody>{_exploit_rows(exploits)}</tbody></table></div></section>
<section><h2>Assessment Limitations</h2><ul>{limitation_html}</ul>
<p class="muted">A CVE or exploit reference is not proof of exploitability. Validate affected versions, configuration, exposure, and vendor advisories before taking action.</p></section>
<footer>Generated by ReconForge · For authorized security testing only · No exploit was executed by this report generator.</footer>
</main></body></html>"""


def write_html_report(results, output_path, target="Unknown"):
    """Write a UTF-8 standalone HTML report and return its path."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html_report(results, target=target), encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser(description="Render a ReconForge JSON scan as a standalone HTML report.")
    parser.add_argument("input", help="Path to ReconForge JSON results")
    parser.add_argument("-o", "--output", default=None, help="HTML output path (default: input filename with .html)")
    parser.add_argument("--target", default=None, help="Target label shown in the report")
    args = parser.parse_args()
    source = Path(args.input)
    results = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(results, list):
        parser.error("Input JSON must contain a list of service results.")
    output = args.output or str(source.with_suffix(".html"))
    target = args.target or (results[0].get("host") if results else "Unknown")
    write_html_report(results, output, target=target)
    print(f"HTML report saved to {output}")


if __name__ == "__main__":
    main()
