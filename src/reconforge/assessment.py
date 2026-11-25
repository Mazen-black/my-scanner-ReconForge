"""Compatibility facade for ReconForge assessment helpers.

Implementation is split by evidence domain; imports remain stable for existing
callers and the legacy top-level assessment.py compatibility module.
"""
from .cpe_assessment import (
    CVE_CONTEXT_CONSTRAINTS,
    _combine_states,
    _compare_versions,
    _evaluate_config_node,
    _version_match,
    _version_tuple,
    apply_contextual_cve_constraints,
    assess_cve_applicability,
    cpe22_to_cpe23,
)
from .exploit_assessment import (
    NETWORK_SERVICE_RULES,
    _deduplicate_exploit_references,
    _explicit_exploit_cve_ids,
    assess_exploit_platform,
    assess_network_exposure,
    build_exploit_intelligence,
    build_technology_fingerprint,
    classify_exploit,
)
from .web_assessment import analyze_http_security, analyze_web_content


def build_report_entry(host, port, state, service, product, version, cpes_tested, cves, exploits, fingerprint=None, http_assessment=None, web_intelligence=None, network_exposure=None, exploit_intelligence=None, host_os_fingerprint=None):
    """Stable, readable JSON shape for one discovered service."""
    return {
        "host": host,
        "port": port,
        "state": state,
        "service": {
            "name": service or None,
            "product": product or None,
            "version": version or None,
        },
        "identification_evidence": {
            "source": "Nmap service detection",
            "cpe_queries_tested": cpes_tested,
            "technology_fingerprint": fingerprint or {},
        },
        "host_os_fingerprint": host_os_fingerprint or {"status": "not_requested"},
        "http_assessment": http_assessment,
        "web_intelligence": web_intelligence,
        "network_exposure": network_exposure or [],
        "cve_assessment": cves,
        "searchsploit_assessment": exploits,
        "exploit_intelligence": exploit_intelligence or [],
        "assessment_limits": [
            "Nmap product/version banners may be incomplete or spoofed.",
            "A matching CVE or exploit reference is not confirmation of a vulnerability.",
            "No exploit was executed by this report generator.",
        ],
    }
