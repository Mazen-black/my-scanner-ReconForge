"""Conservative, explainable confidence summaries for reconnaissance evidence.

Confidence describes the strength of evidence linkage, never the probability that
an asset is vulnerable or that an exploit will succeed.
"""


def _level(value):
    return value if value in ("low", "medium", "high", "unknown") else "unknown"


def _as_mapping(value):
    return value if isinstance(value, dict) else {}


def _unique(values):
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def build_evidence_confidence(fingerprint, cves, exploits, exploit_intelligence):
    """Summarize service identity, CVE applicability, and explicit exploit links."""
    fingerprint = _as_mapping(fingerprint)
    observed = _as_mapping(fingerprint.get("observed"))
    product = bool(observed.get("product"))
    version = bool(observed.get("version"))
    service = bool(observed.get("service"))
    method = str(observed.get("method") or "").strip().lower()
    raw_nmap_conf = observed.get("nmap_confidence")
    try:
        nmap_conf = float(raw_nmap_conf) if raw_nmap_conf is not None and not isinstance(raw_nmap_conf, bool) else None
    except (TypeError, ValueError, OverflowError):
        nmap_conf = None
    if nmap_conf is not None and not 0 <= nmap_conf <= 10:
        nmap_conf = None

    identity_reasons, identity_gaps = [], []
    if product and version and method == "probed" and nmap_conf is not None and nmap_conf >= 8:
        identity_level = "high"
        identity_reasons.append("Nmap actively probed the service and reported a strong service-match score.")
    elif product and version:
        identity_level = "medium"
        identity_reasons.append("Nmap reported both product and version, but active probe confidence is unavailable or insufficiently strong.")
    elif product or service:
        identity_level = "low"
        identity_reasons.append("Only partial service identity is available; product/version evidence is incomplete.")
    else:
        identity_level = "unknown"
        identity_reasons.append("No usable service identity evidence was recorded.")
    if not version:
        identity_gaps.append("Exact service version is missing.")
    if method != "probed":
        identity_gaps.append("Nmap identification method is not recorded as an active probe.")
    if nmap_conf is None:
        identity_gaps.append("A valid Nmap service-match confidence score is unavailable.")
    identity_gaps.extend([
        "A service banner can be modified, proxied, or different from the installed binary.",
        "Package provenance and vendor backport status are not established by service detection.",
    ])

    cves = [item for item in (cves or []) if isinstance(item, dict)]
    states = [str(_as_mapping(item.get("applicability")).get("status") or "candidate_unverified") for item in cves]
    matched = sum(state == "version_match" for state in states)
    unverified = sum(state == "candidate_unverified" for state in states)
    not_matched = sum(state == "not_matched_by_nvd_cpe" for state in states)
    if matched:
        applicability_level = "medium"
        applicability_reasons = [f"{matched} CVE record(s) have an evaluated vulnerable CPE/version path match."]
        applicability_gaps = ["CPE/version matching does not verify installed package provenance, backports, build options, or runtime configuration."]
    elif unverified:
        applicability_level = "low"
        applicability_reasons = [f"{unverified} CVE candidate(s) remain unverified; no complete vulnerable-product path was established."]
        applicability_gaps = ["Vendor advisories and full host/environment configuration require manual validation."]
    elif cves:
        applicability_level = "low"
        applicability_reasons = [f"No CVE among the {len(cves)} returned record(s) matched the evaluated NVD CPE path."]
        applicability_gaps = ["No CPE match is not proof that the service is free of vulnerabilities."]
    else:
        applicability_level = "unknown"
        applicability_reasons = ["No NVD CVE applicability evidence was available for this service."]
        applicability_gaps = ["NVD lookup may have been skipped, rate-limited, or returned no candidates."]

    intelligence = [item for item in (exploit_intelligence or []) if isinstance(item, dict)]
    explicit_links = sum(
        len(_as_mapping(item.get("cve_correlation")).get("matched_scanner_cve_ids") or [])
        for item in intelligence
    )
    exploit_count = len([item for item in (exploits or []) if isinstance(item, dict)])
    if explicit_links:
        exploit_link_level = "high_for_identifier_link_only"
        exploit_link_reasons = [f"{explicit_links} explicit CVE identifier link(s) connect Exploit-DB references to scanner CVE records."]
    elif exploit_count:
        exploit_link_level = "low"
        exploit_link_reasons = ["Exploit-DB results are research leads; no explicit CVE identifier link to a scanner result was established."]
    else:
        exploit_link_level = "unknown"
        exploit_link_reasons = ["No Exploit-DB reference evidence was available."]

    # A positive final review level is capped at medium: passive service/CPE evidence
    # cannot prove the affected installed build or successful exploitation.
    if identity_level in ("medium", "high") and applicability_level == "medium":
        overall = "medium"
        overall_reasons = ["Service identity and at least one NVD vulnerable CPE/version path are both supported by recorded evidence."]
    else:
        overall = "low" if identity_level != "unknown" or applicability_level != "unknown" else "unknown"
        overall_reasons = ["The available evidence is partial or unresolved; manual validation is required before treating this as an applicable vulnerability."]

    return {
        "model": "ReconForge-EC1",
        "scope": "Evidence linkage confidence only; not vulnerability probability or exploit success likelihood.",
        "service_identity": {
            "confidence": identity_level,
            "nmap_method": method or None,
            "nmap_confidence": nmap_conf,
            "reasons": _unique(identity_reasons),
            "evidence_gaps": _unique(identity_gaps),
        },
        "cve_applicability": {
            "confidence": applicability_level,
            "counts": {"version_match": matched, "candidate_unverified": unverified, "not_matched_by_nvd_cpe": not_matched},
            "reasons": _unique(applicability_reasons),
            "evidence_gaps": _unique(applicability_gaps),
        },
        "exploit_reference_linkage": {
            "confidence": exploit_link_level,
            "exploit_references": exploit_count,
            "explicit_cve_links": explicit_links,
            "reasons": _unique(exploit_link_reasons),
            "evidence_gaps": ["An explicit CVE ID link does not establish exploit compatibility, prerequisites, reliability, or target exploitability."],
        },
        "overall_review_confidence": overall,
        "exploitability_confidence": "unknown",
        "overall_reasons": _unique(overall_reasons),
        "overall_evidence_gaps": [
            "Installed package/build identity and vendor patch/backport state are not independently verified.",
            "Runtime configuration, mitigations, authentication requirements, and exploit prerequisites are not fully assessed.",
            "No exploit was executed; successful exploitation has not been tested.",
        ],
    }
