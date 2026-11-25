"""Canonical finding and host-level summary aggregation."""

import math
import re

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _records(value):
    return value if isinstance(value, list) else []


def _valid_score(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        score = float(value)
    except (OverflowError, ValueError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 100 else None


def _host_risk_summary(findings, resolved_hosts):
    hosts = {}
    for host in sorted(resolved_hosts):
        hosts[host] = {
            "host": host,
            "services": 0,
            "ports": [],
            "unique_cves": [],
            "cve_service_counts": {},
            "cve_evidence": {},
            "highest_review_priority_score": None,
            "highest_review_priority": "Unscored",
        }

    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("host"):
            continue
        host = str(finding["host"])
        entry = hosts.setdefault(host, {
            "host": host, "services": 0, "ports": [], "unique_cves": [],
            "cve_service_counts": {}, "cve_evidence": {},
            "highest_review_priority_score": None,
            "highest_review_priority": "Unscored",
        })
        entry["services"] += 1
        port = finding.get("port")
        if port is not None and str(port) not in entry["ports"]:
            entry["ports"].append(str(port))

        risk = finding.get("risk_assessment")
        score = _valid_score(risk.get("score")) if isinstance(risk, dict) else None
        if score is not None and (entry["highest_review_priority_score"] is None or score > entry["highest_review_priority_score"]):
            entry["highest_review_priority_score"] = score
            entry["highest_review_priority"] = str(risk.get("priority") or risk.get("level") or risk.get("priority_label") or "Unspecified")

        observed_on_service = {}
        service = finding.get("service") if isinstance(finding.get("service"), dict) else {}
        service_evidence = {
            "port": str(port) if port is not None else None,
            "service": str(service.get("name") or finding.get("service_name") or "unknown"),
            "product": str(service.get("product") or "") or None,
            "version": str(service.get("version") or "") or None,
        }
        for cve in _records(finding.get("cve_assessment")):
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("id") or cve.get("cve_id")
            if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id.strip()):
                continue
            cve_id = cve_id.strip().upper()
            evidence = observed_on_service.setdefault(cve_id, {**service_evidence, "applicability_statuses": set(), "cvss_base_scores": set()})
            applicability = cve.get("applicability")
            status = applicability.get("status") if isinstance(applicability, dict) else None
            if isinstance(status, str) and status:
                evidence["applicability_statuses"].add(status)
            cvss = cve.get("cvss")
            if isinstance(cvss, (int, float)) and not isinstance(cvss, bool):
                try:
                    cvss_value = float(cvss)
                except (OverflowError, ValueError):
                    cvss_value = None
                if cvss_value is not None and math.isfinite(cvss_value) and 0 <= cvss_value <= 10:
                    evidence["cvss_base_scores"].add(cvss_value)
        for cve_id, evidence in observed_on_service.items():
            entry["cve_service_counts"][cve_id] = entry["cve_service_counts"].get(cve_id, 0) + 1
            host_evidence = entry["cve_evidence"].setdefault(cve_id, [])
            host_evidence.append({
                **{key: value for key, value in evidence.items() if key not in {"applicability_statuses", "cvss_base_scores"}},
                "applicability_statuses": sorted(evidence["applicability_statuses"]),
                "cvss_base_scores": sorted(evidence["cvss_base_scores"]),
            })

    output = []
    for host, entry in sorted(hosts.items()):
        entry["ports"].sort(key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))
        entry["unique_cves"] = sorted(entry["cve_service_counts"])
        entry["unique_cve_count"] = len(entry["unique_cves"])
        entry["cve_evidence"] = [
            {"cve_id": cve_id, "service_observations": entry["cve_evidence"][cve_id]}
            for cve_id in sorted(entry["cve_evidence"])
        ]
        entry["cross_service_cves"] = sorted(
            cve for cve, count in entry["cve_service_counts"].items() if count > 1
        )
        entry["duplicate_cve_observations"] = sum(
            count - 1 for count in entry["cve_service_counts"].values()
        )
        del entry["cve_service_counts"]
        output.append(entry)
    return output


def summarize_findings(findings, hosts=None):
    """Return stable counts plus per-host CVE correlation and risk summaries.

    CVEs are deduplicated per host, not globally: the same CVE on two hosts
    remains two affected assets. Raw candidate counts remain available as
    ``cve_candidates`` for backwards compatibility.
    """
    findings = [item for item in _records(findings) if isinstance(item, dict)]
    resolved_hosts = {str(host) for host in (hosts or []) if host}
    if not resolved_hosts:
        resolved_hosts = {str(item.get("host")) for item in findings if item.get("host")}
    host_risk = _host_risk_summary(findings, resolved_hosts)
    unique_cve_total = sum(item["unique_cve_count"] for item in host_risk)
    cross_service_cve_total = sum(len(item["cross_service_cves"]) for item in host_risk)
    duplicate_observations = sum(item["duplicate_cve_observations"] for item in host_risk)

    def items(item, key):
        return _records(item.get(key))

    return {
        "hosts_scanned": len(resolved_hosts),
        "open_services": len(findings),
        "cve_candidates": sum(len(items(item, "cve_assessment")) for item in findings),
        "unique_host_cves": unique_cve_total,
        "cross_service_cves": cross_service_cve_total,
        "duplicate_cve_observations": duplicate_observations,
        "hosts_with_cves": sum(bool(item["unique_cves"]) for item in host_risk),
        "exploit_references": sum(len(items(item, "searchsploit_assessment")) for item in findings),
        "exploit_intelligence_references": sum(len(items(item, "exploit_intelligence")) for item in findings),
        "network_exposure_observations": sum(len(items(item, "network_exposure")) for item in findings),
        "risk_scored_services": sum(
            isinstance(item.get("risk_assessment"), dict)
            and _valid_score(item["risk_assessment"].get("score")) is not None
            for item in findings
        ),
        "remediation_guidance_services": sum(
            bool(item.get("remediation_guidance") or item.get("remediation"))
            for item in findings
        ),
        "host_risk_summary": host_risk,
    }
