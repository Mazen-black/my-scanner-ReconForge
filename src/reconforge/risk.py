"""Transparent risk-prioritization heuristics for ReconForge findings.

This is not a CVSS recalculation or proof of exploitability. It combines the
published CVSS base score with NVD applicability evidence to help order manual
review. Exploit-DB references remain a separate signal and never create a score.
"""

import math


APPLICABILITY_FACTORS = {
    "version_match": 1.0,
    "candidate_unverified": 0.65,
    "not_matched_by_nvd_cpe": 0.0,
}
UNKNOWN_APPLICABILITY_FACTOR = 0.5


def _priority(score):
    if score is None:
        return "Unscored"
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def score_cve(cve):
    """Attach a review-priority score without changing the original CVSS score."""
    cve = cve if isinstance(cve, dict) else {}
    applicability = cve.get("applicability")
    applicability = applicability if isinstance(applicability, dict) else {}
    raw_status = applicability.get("status", "candidate_unverified")
    status = raw_status if raw_status in APPLICABILITY_FACTORS else "unknown_status"
    factor = APPLICABILITY_FACTORS.get(status, UNKNOWN_APPLICABILITY_FACTOR)
    cvss = cve.get("cvss")
    valid_cvss = (
        isinstance(cvss, (int, float))
        and not isinstance(cvss, bool)
        and math.isfinite(cvss)
        and 0 <= cvss <= 10
    )
    score = round(float(cvss) * 10 * factor, 1) if valid_cvss else None
    explanations = {
        "version_match": "Full review factor: NVD product/version criteria matched; exploitability remains unproven.",
        "candidate_unverified": "Discounted factor: CVE is a candidate but applicability conditions remain unverified.",
        "not_matched_by_nvd_cpe": "Zero factor: NVD CPE criteria did not match the detected product/version.",
        "unknown_status": "Conservative fallback factor: applicability status is unrecognized and needs manual review.",
    }
    return {
        "cvss_base_score": float(cvss) if valid_cvss else None,
        "applicability_status": status,
        "applicability_factor": factor,
        "priority_score": score,
        "priority": _priority(score),
        "formula": "CVSS base score × 10 × applicability factor",
        "factor_explanation": explanations[status],
        "model": "ReconForge-RP1",
        "rationale": (
            "This is a review-priority heuristic, not a CVSS score, probability, "
            "or proof of exploitability."
        ),
    }


def assess_service_risk(cves, exploits):
    """Summarize the highest CVE review priority and keep exploit references separate."""
    valid_cves = [item for item in (cves or []) if isinstance(item, dict)]
    valid_exploits = [item for item in (exploits or []) if isinstance(item, dict)]
    assessed = [score_cve(cve) for cve in valid_cves]
    scored = [
        (index, item) for index, item in enumerate(assessed)
        if item["priority_score"] is not None and item["applicability_status"] != "not_matched_by_nvd_cpe"
    ]
    top_index, top = max(
        scored,
        key=lambda pair: pair[1]["priority_score"],
        default=(None, None),
    )
    exact_refs = sum(
        1 for exploit in valid_exploits
        if isinstance(exploit.get("assessment"), dict)
        and exploit["assessment"].get("relevance") == "product_and_version_match"
    )
    unverified = sum(
        1 for item in assessed if item["applicability_status"] in {"candidate_unverified", "unknown_status"}
    )
    return {
        "score": top["priority_score"] if top else None,
        "level": top["priority"] if top else "Unscored",
        "top_cve": (valid_cves[top_index].get("id") if top_index is not None else None),
        "top_cve_cvss_base_score": (assessed[top_index]["cvss_base_score"] if top_index is not None else None),
        "top_cve_applicability_status": (assessed[top_index]["applicability_status"] if top_index is not None else None),
        "top_cve_applicability_factor": (assessed[top_index]["applicability_factor"] if top_index is not None else None),
        "scored_cve_count": len(scored),
        "unverified_cve_count": unverified,
        "invalid_cve_entries_ignored": len(cves or []) - len(valid_cves),
        "invalid_exploit_entries_ignored": len(exploits or []) - len(valid_exploits),
        "exploit_reference_count": len(valid_exploits),
        "exact_product_version_reference_count": exact_refs,
        "exploit_references_affect_score": False,
        "model": "ReconForge-RP1",
        "notes": [
            "CVSS base severity is kept separate from ReconForge review priority.",
            "Unverified or unrecognized applicability is discounted, not treated as false.",
            "Exploit-DB title matches are supporting research leads and do not increase the numeric score.",
            "Network exposure and business impact are not inferred from an open port.",
        ],
    }


def assess_cves(cves):
    """Return shallow-copied CVE records with their separate priority assessment."""
    return [
        {**cve, "risk_priority": score_cve(cve)}
        for cve in (cves or []) if isinstance(cve, dict)
    ]
