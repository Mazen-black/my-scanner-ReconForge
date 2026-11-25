"""Canonical finding summary aggregation shared by scanner and HTML reports."""


def summarize_findings(findings, hosts=None):
    """Return stable report counts derived from findings and resolved hosts."""
    findings = findings if isinstance(findings, list) else []
    resolved_hosts = {str(host) for host in (hosts or []) if host}
    if not resolved_hosts:
        resolved_hosts = {str(item.get("host")) for item in findings if item.get("host")}

    def items(item, key):
        value = item.get(key) or []
        return value if isinstance(value, list) else []

    return {
        "hosts_scanned": len(resolved_hosts),
        "open_services": len(findings),
        "cve_candidates": sum(len(items(item, "cve_assessment")) for item in findings),
        "exploit_references": sum(len(items(item, "searchsploit_assessment")) for item in findings),
        "exploit_intelligence_references": sum(len(items(item, "exploit_intelligence")) for item in findings),
        "network_exposure_observations": sum(len(items(item, "network_exposure")) for item in findings),
        "risk_scored_services": sum(
            isinstance(item.get("risk_assessment"), dict)
            and item["risk_assessment"].get("score") is not None
            for item in findings
        ),
        "remediation_guidance_services": sum(
            bool(item.get("remediation_guidance") or item.get("remediation"))
            for item in findings
        ),
    }
