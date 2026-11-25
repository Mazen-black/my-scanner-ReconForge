"""Generate a self-contained, escaped HTML report from ReconForge JSON results."""
import argparse
import html
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

from .summary import summarize_findings


def _e(value, default="—"):
    """HTML-escape untrusted values before placing them in the report."""
    if value is None or value == "":
        value = default
    return html.escape(str(value), quote=True)


def _valid_finite_number(value, minimum=None, maximum=None):
    """Reject booleans, non-numeric values, and non-finite numbers."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        if not math.isfinite(value):
            return False
    except OverflowError:
        return False
    return (minimum is None or value >= minimum) and (maximum is None or value <= maximum)


def _valid_cvss(score):
    """Accept only finite CVSS base scores in the standardized 0–10 range."""
    return _valid_finite_number(score, 0, 10)


def _severity(score):
    if not _valid_cvss(score):
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
    return score if _valid_cvss(score) else -1


def _cve_rows(cves):
    rows = []
    for cve in sorted(cves or [], key=_score_sort, reverse=True):
        score = cve.get("cvss")
        # A supplied severity label must not override a valid CVSS base score.
        # Invalid/missing scores remain Unknown rather than trusting stale labels.
        severity = _severity(score)
        applicability = cve.get("applicability") or {}
        status = applicability.get("status", "candidate_unverified")
        priority = cve.get("risk_priority") or {}
        priority_level = priority.get("priority", "Unscored")
        css = {
            "Critical": "critical", "High": "high", "Medium": "medium",
            "Low": "low", "None": "none",
        }.get(severity, "unknown")
        priority_css = {
            "Critical": "critical", "High": "high", "Medium": "medium",
            "Low": "low", "Informational": "none",
        }.get(priority_level, "unknown")
        score_text = f"{score:.1f}" if _valid_cvss(score) else "N/A"
        priority_score = priority.get("priority_score")
        priority_text = f"{priority_score:.1f}" if _valid_finite_number(priority_score, 0, 100) else "N/A"
        contextual = applicability.get("contextual_constraint") or {}
        matched_evidence = applicability.get("evidence") or []
        evidence_lines = []
        for evidence in matched_evidence:
            if not isinstance(evidence, dict):
                continue
            criteria = evidence.get("criteria")
            if not criteria:
                continue
            details = [str(evidence.get("reason") or "evaluated")]
            for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                if evidence.get(key):
                    details.append(f"{key}={evidence[key]}")
            if evidence.get("vulnerable") is True:
                details.append("vulnerable=true")
            evidence_lines.append(f"{criteria} ({'; '.join(details)})")
        limitations = applicability.get("limitations") or []
        query_evidence = cve.get("query_evidence") or []
        query_lines = []
        for query in query_evidence:
            if not isinstance(query, dict):
                continue
            query_value = query.get("query") or query.get("keyword")
            if query_value:
                query_lines.append(f'{query.get("source") or query.get("type") or "NVD"}: {query_value}')
        summary = str(cve.get("summary") or "")
        if contextual.get("condition"):
            summary += " Additional verification required: " + str(contextual["condition"])
        rows.append(
            '<tr>'
            f'<td><strong>{_e(cve.get("id"))}</strong></td>'
            f'<td><span class="severity {css}">{_e(severity)}</span></td>'
            f'<td class="numeric">{_e(score_text)}</td>'
            f'<td><span class="severity {priority_css}">{_e(priority_level)}</span> <span class="muted">({_e(priority_text)})</span>'
            + (f'<div class="muted">Factor: {_e(priority.get("applicability_factor"))}; {_e(priority.get("factor_explanation"))}</div>' if priority else '')
            + f'</td>'
            f'<td>{_e(status)}'
            + f'<div class="muted">Applicability confidence: {_e(applicability.get("applicability_confidence", applicability.get("confidence", "unknown")))}; exploitability: {_e(applicability.get("exploitability_confidence", "unknown"))}</div>'
            + (f'<div class="muted">Sources: {_e("; ".join(applicability.get("evidence_sources") or []))}</div>' if applicability.get("evidence_sources") else '')
            + (f'<div class="muted">Why: {_e("; ".join(applicability.get("confidence_reasons") or []))}</div>' if applicability.get("confidence_reasons") else '')
            + (f'<div class="muted">Evidence gaps: {_e("; ".join(applicability.get("evidence_gaps") or []))}</div>' if applicability.get("evidence_gaps") else '')
            + (f'<div class="muted">CPE: {_e(applicability.get("cpe_version_status"))}; constraint: {_e(contextual.get("kind"))}</div>' if contextual else '')
            + (f'<div class="muted">Matched NVD CPE evidence: {_e(" | ".join(evidence_lines))}</div>' if evidence_lines else '')
            + (f'<div class="muted">Limitations: {_e("; ".join(limitations))}</div>' if limitations else '')
            + (f'<div class="muted">Candidate source: {_e(cve.get("source"))}</div>' if cve.get("source") else '')
            + (f'<div class="muted">Retrieved by NVD query: {_e(" | ".join(query_lines))}</div>' if query_lines else '')
            + '</td>'
            f'<td>{_e(summary)}</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="6" class="empty">No CVE results recorded.</td></tr>'


def _evidence_confidence_sections(results):
    sections = []
    for item in results or []:
        confidence = item.get("evidence_confidence") or {}
        if not confidence:
            continue
        identity = confidence.get("service_identity") or {}
        applicability = confidence.get("cve_applicability") or {}
        linkage = confidence.get("exploit_reference_linkage") or {}
        counts = applicability.get("counts") or {}
        reasons = confidence.get("overall_reasons") or []
        gaps = confidence.get("overall_evidence_gaps") or []
        sections.append(
            '<tr>'
            f'<td>{_e(item.get("host"))}:{_e(item.get("port"))} / {_e((item.get("service") or {}).get("product"))}</td>'
            f'<td>{_e(identity.get("confidence", "unknown"))}<div class="muted">Nmap: {_e(identity.get("nmap_method"))}; score: {_e(identity.get("nmap_confidence"))}</div>'
            f'<div class="muted">{_e("; ".join(identity.get("reasons") or []))}</div></td>'
            f'<td>{_e(applicability.get("confidence", "unknown"))}<div class="muted">Matches: {_e(counts.get("version_match", 0))}; unverified: {_e(counts.get("candidate_unverified", 0))}; not matched: {_e(counts.get("not_matched_by_nvd_cpe", 0))}</div>'
            f'<div class="muted">{_e("; ".join(applicability.get("reasons") or []))}</div></td>'
            f'<td>{_e(linkage.get("confidence", "unknown"))}<div class="muted">Explicit CVE links: {_e(linkage.get("explicit_cve_links", 0))} / references: {_e(linkage.get("exploit_references", 0))}</div>'
            f'<div class="muted">{_e("; ".join(linkage.get("reasons") or []))}</div></td>'
            f'<td>{_e(confidence.get("overall_review_confidence", "unknown"))}<div class="muted">Exploitability: {_e(confidence.get("exploitability_confidence", "unknown"))}</div>'
            f'<div class="muted">{_e("; ".join(reasons))}</div><div class="muted">Gaps: {_e("; ".join(gaps))}</div></td>'
            '</tr>'
        )
    return "".join(sections) or '<tr><td colspan="5" class="empty">No consolidated evidence-confidence records available.</td></tr>'


def _risk_rows(results):
    rows = []
    for item in results or []:
        risk = item.get("risk_assessment") or {}
        score = risk.get("score")
        level = risk.get("level", "Unscored")
        css = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(level, "unknown")
        score_text = f"{score:.1f}" if _valid_finite_number(score, 0, 100) else "N/A"
        context = risk.get("asset_context") or {}
        context_score = context.get("contextual_priority_score")
        context_text = f"{context_score:.1f}" if _valid_finite_number(context_score, 0, 100) else "N/A"
        context_level = context.get("contextual_priority", "Unscored")
        context_css = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(context_level, "unknown")
        service = item.get("service") or {}
        rows.append(
            '<tr>'
            f'<td>{_e(item.get("port"))}/{_e(service.get("name"))}</td>'
            f'<td>{_e(service.get("product"))} {_e(service.get("version"))}</td>'
            f'<td><span class="severity {css}">{_e(level)}</span></td>'
            f'<td class="numeric">{_e(score_text)}</td>'
            f'<td><span class="severity {context_css}">{_e(context_level)}</span> <span class="muted">({_e(context_text)})</span></td>'
            f'<td>{_e(context.get("asset_criticality", "unknown"))} / {_e(context.get("network_exposure", "unknown"))}'
            + (f'<div class="muted">Factors: criticality ×{_e(context.get("criticality_factor"))}; exposure ×{_e(context.get("exposure_factor"))}</div>' if context else '')
            + '</td>'
            f'<td>{_e(risk.get("top_cve"))}'
            + (f'<div class="muted">{_e(risk.get("model"))}: {_e(risk.get("notes", [""])[0])}</div>' if risk.get("model") else '')
            + '</td>'
            f'<td>{_e(risk.get("exploit_reference_count", 0))}</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="8" class="empty">No service risk data recorded.</td></tr>'


def _exploit_rows(exploits, intelligence_by_id=None):
    rows = []
    intelligence_by_id = intelligence_by_id or {}
    for exploit in exploits or []:
        assessment = exploit.get("assessment") or {}
        enriched = intelligence_by_id.get(str(exploit.get("id") or ""), {})
        triage = enriched.get("triage") or {}
        correlation = enriched.get("cve_correlation") or {}
        cve_state = correlation.get("status", "not_correlated")
        platform_state = (enriched.get("platform_compatibility") or {}).get("status", "unknown_target_platform")
        evidence = enriched.get("applicability_evidence") or {}
        requirements_state = evidence.get("requirements_assessment", "unknown_not_documented_in_local_metadata")
        documented_requirements = evidence.get("documented_requirements") or {}
        requirement_values = [
            f"{key}: {value.get('value')}"
            for key, value in documented_requirements.items()
            if isinstance(value, dict) and value.get("value")
        ]
        normalized_requirements = evidence.get("normalized_requirements") or {}
        normalized_values = []
        for key, value in normalized_requirements.items():
            if not isinstance(value, dict):
                continue
            normalized = value.get("status") or value.get("level")
            if normalized and normalized != "unknown":
                normalized_values.append(f"{key}={normalized}")
        if requirement_values:
            requirements_state += " (" + "; ".join(requirement_values) + ")"
        if normalized_values:
            requirements_state += " [" + "; ".join(normalized_values) + "]"
        architecture_state = evidence.get("architecture_assessment", "unknown_not_inferred_from_platform_label")
        target_architecture = evidence.get("target_architecture")
        if isinstance(target_architecture, dict) and target_architecture.get("value"):
            architecture_state += f" ({target_architecture['value']})"
        rows.append(
            '<tr>'
            f'<td>{_e(exploit.get("id"))}</td>'
            f'<td>{_e(exploit.get("title"))}</td>'
            f'<td>{_e(exploit.get("platform"))}</td>'
            f'<td>{_e(assessment.get("relevance", "unassessed"))}</td>'
            f'<td>{_e(assessment.get("confidence", "low"))}</td>'
            f'<td>{_e(triage.get("status", "manual_review_required"))}'
            + f'<div class="muted">Applicability: {_e(triage.get("applicability_confidence", "unknown"))}; exploitability: {_e(triage.get("exploitability_confidence", "unknown"))}</div>'
            + (f'<div class="muted">Sources: {_e("; ".join(triage.get("evidence_sources") or []))}</div>' if triage.get("evidence_sources") else '')
            + (f'<div class="muted">Why: {_e("; ".join(triage.get("confidence_reasons") or []))}</div>' if triage.get("confidence_reasons") else '')
            + (f'<div class="muted">Gaps: {_e("; ".join(triage.get("evidence_gaps") or []))}</div>' if triage.get("evidence_gaps") else '')
            + '</td>'
            f'<td>{_e(platform_state)}</td>'
            f'<td>{_e(requirements_state)} / {_e(architecture_state)}</td>'
            f'<td>{_e(cve_state)}'
            + (f'<div class="muted">{_e(", ".join(correlation.get("matched_scanner_cve_ids") or []))}</div>' if correlation.get("matched_scanner_cve_ids") else '')
            + (f'<div class="muted">Explicit-ID link confidence: {_e(correlation.get("link_confidence"))}</div>' if correlation.get("link_confidence") else '')
            + (f'<div class="muted">Related EDB references: {_e(", ".join(correlation.get("related_exploit_db_ids") or []))}</div>' if correlation.get("related_exploit_db_ids") else '')
            + (f'<div class="muted">Duplicate search observations: {len(correlation.get("duplicate_observations") or [])}</div>' if correlation.get("duplicate_observations") else '')
            + (f'<div class="muted">Conflicting metadata fields: {_e(", ".join(sorted({field for observation in correlation.get("duplicate_observations") or [] if isinstance(observation, dict) for field in (observation.get("metadata_variants") or {})})) )}</div>' if any(isinstance(observation, dict) and observation.get("metadata_variants") for observation in correlation.get("duplicate_observations") or []) else '')
            + '</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="9" class="empty">No matching Exploit-DB entries recorded.</td></tr>'



def _remediation_sections(results):
    sections = []
    for item in results or []:
        guidance = item.get("remediation_guidance") or item.get("remediation") or {}
        service = item.get("service") or {}
        label = f"{item.get('host', 'Unknown')}:{item.get('port', '?')} / {service.get('name') or 'unknown service'}"
        service_tip = guidance.get("service_guidance")
        if service_tip:
            actions = "".join(f"<li>{_e(action)}</li>" for action in service_tip.get("actions", []))
            checks = "".join(f"<li>{_e(step)}</li>" for step in service_tip.get("verification", []))
            sections.append(
                f"<article class=\"remedy\"><h3>{_e(label)} — {_e(service_tip.get('title'))}</h3>"
                f"<p><span class=\"severity medium\">{_e(service_tip.get('priority'))} suggested review</span> "
                f"<span class=\"muted\">Confidence: {_e(service_tip.get('confidence'))}; {_e(service_tip.get('reason'))}</span></p>"
                f'<p class="muted">Evidence: {_e(json.dumps(service_tip.get("evidence") or {}, ensure_ascii=False, sort_keys=True))}</p>'
                f"<h4>Recommended actions</h4><ul>{actions}</ul><h4>How to verify</h4><ul>{checks}</ul></article>"
            )
        for cve_tip in guidance.get("cve_guidance", []):
            actions = "".join(f"<li>{_e(action)}</li>" for action in cve_tip.get("actions", []))
            checks = "".join(f"<li>{_e(step)}</li>" for step in cve_tip.get("verification", []))
            sections.append(
                f"<article class=\"remedy\"><h3>{_e(label)} — {_e(cve_tip.get('title'))}</h3>"
                f"<p><span class=\"severity unknown\">{_e(cve_tip.get('priority'))}</span> "
                f"<span class=\"muted\">Applicability: {_e(cve_tip.get('applicability'))}; confidence: {_e(cve_tip.get('confidence'))}</span></p>"
                f'<p class="muted">Evidence: {_e(json.dumps(cve_tip.get("evidence") or {}, ensure_ascii=False, sort_keys=True))}</p>'
                f"<h4>Recommended actions</h4><ul>{actions}</ul><h4>How to verify</h4><ul>{checks}</ul></article>"
            )
    return "".join(sections) or '<p class="muted">No remediation guidance generated. Confirm service identification and CVE metadata first.</p>'

def _host_os_fingerprints(results, host_os_fingerprints=None):
    """Merge host-level report metadata with legacy per-service OS evidence."""
    fingerprints = {}
    for record in host_os_fingerprints or []:
        if not isinstance(record, dict):
            continue
        host = str(record.get("host") or "Unknown")
        fingerprints[host] = {
            key: value for key, value in record.items() if key != "host"
        }
    for item in results or []:
        host = str(item.get("host") or "Unknown")
        fingerprint = item.get("host_os_fingerprint")
        if not isinstance(fingerprint, dict) or host in fingerprints:
            continue
        fingerprints[host] = fingerprint
    return fingerprints


def _os_fingerprint_rows(results, host_os_fingerprints=None):
    """Render one conservative OS-fingerprint row per host, including hosts without open ports."""
    fingerprints = _host_os_fingerprints(results, host_os_fingerprints)

    rows = []
    for host, fingerprint in sorted(fingerprints.items()):
        accuracy = fingerprint.get("accuracy")
        accuracy_text = f"{accuracy}%" if isinstance(accuracy, (int, float)) else "Unknown"
        threshold = fingerprint.get("minimum_accuracy")
        threshold_text = f"{threshold}%" if isinstance(threshold, (int, float)) else "Not specified"
        status = fingerprint.get("status") or "unknown"
        family = fingerprint.get("platform_family") or "Unknown"
        nmap_name = fingerprint.get("nmap_name") or "No OS match returned"
        rows.append(
            '<tr>'
            f'<td>{_e(host)}</td>'
            f'<td>{_e(nmap_name)}</td>'
            f'<td>{_e(family)}</td>'
            f'<td class="numeric">{_e(accuracy_text)}</td>'
            f'<td class="numeric">{_e(threshold_text)}</td>'
            f'<td>{_e(status)}</td>'
            '</tr>'
        )
    return "".join(rows) or '<tr><td colspan="6" class="empty">No host OS fingerprint data recorded.</td></tr>'


def _accepted_os_host_count(results, host_os_fingerprints=None):
    fingerprints = _host_os_fingerprints(results, host_os_fingerprints)
    return sum(
        fingerprint.get("status") == "accepted_high_confidence"
        and bool(fingerprint.get("platform_family"))
        for fingerprint in fingerprints.values()
    )


def render_html_report(results, target="Unknown", generated_at=None, host_os_fingerprints=None, hosts=None):
    """Return a complete standalone HTML report. All source data is escaped."""
    results = results if isinstance(results, list) else []
    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarize_findings(results, hosts=hosts)
    open_ports = summary["open_services"]
    host_risk_rows = []
    for host_item in summary["host_risk_summary"]:
        host_risk_rows.append(
            "<tr>"
            f"<td>{_e(host_item['host'])}</td>"
            f"<td class=\"numeric\">{host_item['services']}</td>"
            f"<td>{_e(', '.join(host_item['ports']) or '—')}</td>"
            f"<td class=\"numeric\">{host_item['unique_cve_count']}</td>"
            f"<td>{_e(', '.join(host_item['cross_service_cves']) or 'None')}</td>"
            f"<td>{_e(host_item['highest_review_priority'])}"
            + (f" ({host_item['highest_review_priority_score']:.1f}/100)" if host_item['highest_review_priority_score'] is not None else "")
            + "</td></tr>"
        )
    host_risk_html = "".join(host_risk_rows) or '<tr><td colspan="6" class="empty">No host risk data available.</td></tr>'
    cves = [cve for item in results for cve in (item.get("cve_assessment") or [])]
    exploits = [exploit for item in results for exploit in (item.get("searchsploit_assessment") or [])]
    exploit_intelligence_by_id = {
        str((entry.get("reference") or {}).get("id") or ""): entry
        for item in results for entry in (item.get("exploit_intelligence") or [])
        if (entry.get("reference") or {}).get("id")
    }
    confirmed_matches = sum(
        1 for cve in cves
        if (cve.get("applicability") or {}).get("status") == "version_match"
    )
    high_critical = sum(
        1 for cve in cves
        if _severity(cve.get("cvss")) in ("High", "Critical")
    )
    high_priority = sum(
        1 for cve in cves
        if (cve.get("risk_priority") or {}).get("priority") in ("High", "Critical")
    )
    unverified_candidates = sum(
        1 for cve in cves
        if (cve.get("applicability") or {}).get("status") == "candidate_unverified"
    )

    service_rows = []
    for item in sorted(results, key=lambda row: (str(row.get("host", "")), int(row.get("port") or 0))):
        service = item.get("service") or {}
        os_fingerprint = item.get("host_os_fingerprint") or {}
        os_label = os_fingerprint.get("nmap_name") or os_fingerprint.get("status") or "not_recorded"
        os_accuracy = os_fingerprint.get("accuracy")
        if os_accuracy is not None:
            os_label = f"{os_label} ({os_accuracy}%)"
        service_rows.append(
            '<tr>'
            f'<td>{_e(item.get("host"))}</td>'
            f'<td class="numeric">{_e(item.get("port"))}</td>'
            f'<td>{_e(service.get("name"))}</td>'
            f'<td>{_e(service.get("product"))}</td>'
            f'<td>{_e(service.get("version"))}</td>'
            f'<td>{_e(os_label)}</td>'
            f'<td>{_e(item.get("state"))}</td>'
            '</tr>'
        )
    services_html = "".join(service_rows) or '<tr><td colspan="7" class="empty">No open services recorded.</td></tr>'

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
.empty{{color:var(--muted);text-align:center;padding:24px}}li{{margin:7px 0;color:var(--muted)}}.remedy{{padding:14px 0;border-bottom:1px solid var(--line)}}.remedy:last-child{{border:0}}h3{{font-size:16px;margin:8px 0}}h4{{font-size:13px;margin:12px 0 4px;color:var(--muted)}}footer{{color:var(--muted);font-size:12px;padding:20px 2px}}
@media print{{:root{{--bg:#fff;--panel:#fff;--line:#ddd;--text:#111;--muted:#555}}body{{background:#fff;color:#111}}main{{max-width:none;padding:0}}section,.card{{break-inside:avoid}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">ReconForge / Security Assessment</div>
<h1>Network Scan Report</h1>
<div class="sub">Target: <strong>{_e(target)}</strong> · Generated: {_e(generated_at)}</div></header>
<div class="cards">
<div class="card"><div class="muted">Hosts scanned</div><div class="metric">{summary["hosts_scanned"]}</div></div>
<div class="card"><div class="muted">Open services</div><div class="metric">{open_ports}</div></div>
<div class="card"><div class="muted">CVE observations</div><div class="metric">{len(cves)}</div></div>
<div class="card"><div class="muted">Unique CVE candidates per host</div><div class="metric">{summary['unique_host_cves']}</div></div>
<div class="card"><div class="muted">Candidates on multiple services</div><div class="metric">{summary['cross_service_cves']}</div></div>
<div class="card"><div class="muted">Duplicate candidate observations</div><div class="metric">{summary['duplicate_cve_observations']}</div></div>
<div class="card"><div class="muted">High / Critical CVEs</div><div class="metric">{high_critical}</div></div>
<div class="card"><div class="muted">Version matches</div><div class="metric">{confirmed_matches}</div></div>
<div class="card"><div class="muted">High / Critical review priority</div><div class="metric">{high_priority}</div></div>
<div class="card"><div class="muted">Unverified CVE candidates</div><div class="metric">{unverified_candidates}</div></div>
<div class="card"><div class="muted">Exploit references</div><div class="metric">{summary["exploit_references"]}</div></div>
<div class="card"><div class="muted">Exploit intelligence references</div><div class="metric">{summary["exploit_intelligence_references"]}</div></div>
<div class="card"><div class="muted">Network exposure observations</div><div class="metric">{summary["network_exposure_observations"]}</div></div>
<div class="card"><div class="muted">Risk-scored services</div><div class="metric">{summary["risk_scored_services"]}</div></div>
<div class="card"><div class="muted">Services with remediation guidance</div><div class="metric">{summary["remediation_guidance_services"]}</div></div>
<div class="card"><div class="muted">Hosts with accepted OS match</div><div class="metric">{_accepted_os_host_count(results, host_os_fingerprints)}</div></div>
</div>
<section><h2>Host-Level Risk & CVE Correlation</h2><p class="muted">CVE candidates are deduplicated within each host, not across different hosts. A candidate observed on multiple services is shown once in the host total and separately identified as cross-service correlation. These are assessment candidates, not confirmed vulnerabilities. Scores are the highest service review-priority score, not a host compromise probability.</p><div class="table-wrap"><table><thead><tr><th>Host</th><th>Services</th><th>Observed ports</th><th>Unique CVE candidates</th><th>Cross-service candidates</th><th>Highest review priority</th></tr></thead><tbody>{host_risk_html}</tbody></table></div></section>
<section><h2>Discovered Services</h2><div class="table-wrap"><table>
<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Host OS fingerprint</th><th>State</th></tr></thead>
<tbody>{services_html}</tbody></table></div></section>
<section><h2>Host OS Fingerprint</h2>
<p class="muted">OS detection is opt-in. A broad platform family is accepted only when Nmap's match accuracy meets the configured threshold (90% by default). Nmap accuracy is a matching score, not a calibrated probability, and does not establish CPU architecture or vulnerability applicability.</p>
<div class="table-wrap"><table><thead><tr><th>Host</th><th>Nmap OS match</th><th>Platform family</th><th>Match accuracy</th><th>Acceptance threshold</th><th>Status</th></tr></thead>
<tbody>{_os_fingerprint_rows(results, host_os_fingerprints)}</tbody></table></div></section>
<section><h2>Consolidated Evidence Confidence</h2><p class="muted">Confidence grades describe the strength of evidence linkage, not the probability that a host is vulnerable. Exploitability remains unknown unless independently validated.</p>
<div class="table-wrap"><table><thead><tr><th>Service</th><th>Service identity</th><th>CVE applicability</th><th>Exploit reference linkage</th><th>Overall review confidence</th></tr></thead>
<tbody>{_evidence_confidence_sections(results)}</tbody></table></div></section>
<section><h2>Risk Prioritization</h2><p class="muted">Technical priority uses the highest CVE review-priority score. Contextual priority adjusts it only with explicitly supplied asset criticality and exposure. Unknown context is neutral. Neither score is CVSS or proof of exploitability.</p>
<div class="table-wrap"><table><thead><tr><th>Port / Service</th><th>Product / Version</th><th>Technical priority</th><th>Technical score</th><th>Contextual priority</th><th>Asset / Exposure</th><th>Top CVE</th><th>EDB refs</th></tr></thead>
<tbody>{_risk_rows(results)}</tbody></table></div></section>
<section><h2>CVE Assessment</h2><p class="muted">CVSS base severity and ReconForge review priority are separate. Priority discounts unverified applicability; it does not prove exploitability.</p>
<div class="table-wrap"><table><thead><tr><th>CVE</th><th>CVSS Severity</th><th>CVSS</th><th>Review Priority</th><th>Applicability</th><th>Summary</th></tr></thead>
<tbody>{_cve_rows(cves)}</tbody></table></div></section>
<section><h2>Exploit-DB References</h2><p class="muted">Exploit references are research leads. Triage and CVE correlation do not establish exploitability.</p><div class="table-wrap"><table><thead><tr><th>EDB ID</th><th>Title</th><th>Platform</th><th>Relevance</th><th>Confidence</th><th>Triage</th><th>Platform compatibility</th><th>Requirements / architecture</th><th>CVE correlation</th></tr></thead>
<tbody>{_exploit_rows(exploits, exploit_intelligence_by_id)}</tbody></table></div></section>
<section><h2>Remediation Guidance</h2><p class="muted">Advisory guidance only. ReconForge does not execute changes, does not invent fixed versions, and requires vendor/change-control validation.</p>
{_remediation_sections(results)}</section>
<section><h2>Assessment Limitations</h2><ul>{limitation_html}</ul>
<p class="muted">A CVE or exploit reference is not proof of exploitability. Validate affected versions, configuration, exposure, and vendor advisories before taking action.</p></section>
<footer>Generated by ReconForge · For authorized security testing only · No exploit was executed by this report generator.</footer>
</main></body></html>"""


def write_html_report(results, output_path, target="Unknown", host_os_fingerprints=None, hosts=None):
    """Write a UTF-8 standalone HTML report and return its path."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_html_report(results, target=target, host_os_fingerprints=host_os_fingerprints, hosts=hosts),
        encoding="utf-8",
    )
    return output


def main():
    parser = argparse.ArgumentParser(description="Render a ReconForge JSON scan as a standalone HTML report.")
    parser.add_argument("input", help="Path to ReconForge JSON results")
    parser.add_argument("-o", "--output", default=None, help="HTML output path (default: input filename with .html)")
    parser.add_argument("--target", default=None, help="Target label shown in the report")
    args = parser.parse_args()
    source = Path(args.input)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(f"Unable to read valid JSON report: {exc}")
    if isinstance(payload, dict):
        # Current ReconForge JSON uses a versioned envelope; older releases wrote a list.
        schema_version = payload.get("schema_version")
        if schema_version is not None:
            match = re.fullmatch(r"(\d+)\.(\d+)", str(schema_version))
            if not match:
                parser.error("Report schema_version must use MAJOR.MINOR format.")
            major, minor = map(int, match.groups())
            if major != 1 or minor > 16:
                parser.error(
                    f"Unsupported report schema version {schema_version!r}; "
                    "this version supports schema 1.0 through 1.16."
                )
        results = payload.get("findings")
        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            parser.error("ReconForge report metadata must be a JSON object.")
        detected_target = metadata.get("requested_target")
        host_os_fingerprints = metadata.get("host_os_fingerprints") or []
        if not isinstance(host_os_fingerprints, list):
            parser.error("ReconForge report metadata 'host_os_fingerprints' must be a list.")
    elif isinstance(payload, list):
        results = payload
        host_os_fingerprints = []
        detected_target = results[0].get("host") if results else "Unknown"
    else:
        parser.error("Input JSON must be a ReconForge report object or a legacy list of findings.")
    if not isinstance(results, list):
        parser.error("ReconForge report is missing a valid 'findings' list.")
    output = args.output or str(source.with_suffix(".html"))
    target = args.target or detected_target or "Unknown"
    write_html_report(
        results, output, target=target,
        host_os_fingerprints=host_os_fingerprints,
        hosts=metadata.get("resolved_hosts", []) if isinstance(payload, dict) else None,
    )
    print(f"HTML report saved to {output}")


if __name__ == "__main__":
    main()
