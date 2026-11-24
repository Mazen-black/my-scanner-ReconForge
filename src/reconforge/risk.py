"""Transparent risk-prioritization heuristics for ReconForge findings.

This is not a CVSS recalculation or proof of exploitability. It combines the
published CVSS base score with NVD applicability evidence to help order manual
review. Exploit-DB references remain a separate signal and never create a score.
"""


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
    cvss = cve.get("cvss")
    applicability = cve.get("applicability") or {}
    status = applicability.get("status", "candidate_unverified")
    factors = {
        "version_match": 1.0,
        "candidate_unverified": 0.65,
        "not_matched_by_nvd_cpe": 0.0,
    }
    factor = factors.get(status, 0.5)
    valid_cvss = isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and 0 <= cvss <= 10
    score = round(float(cvss) * 10 * factor, 1) if valid_cvss else None
    return {
        "cvss_base_score": float(cvss) if valid_cvss else None,
        "applicability_status": status,
        "applicability_factor": factor,
        "priority_score": score,
        "priority": _priority(score),
        "model": "ReconForge-RP1",
        "rationale": (
            "CVSS base score scaled by NVD applicability evidence; "
            "this is a review-priority heuristic, not a CVSS score."
        ),
    }


def assess_service_risk(cves, exploits):
    """Summarize the highest CVE review priority and keep exploit references separate."""
    assessed = [score_cve(cve) for cve in (cves or [])]
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
        1 for exploit in (exploits or [])
        if ((exploit.get("assessment") or {}).get("relevance") == "product_and_version_match")
    )
    unverified = sum(
        1 for item in assessed if item["applicability_status"] == "candidate_unverified"
    )
    return {
        "score": top["priority_score"] if top else None,
        "level": top["priority"] if top else "Unscored",
        "top_cve": (cves[top_index].get("id") if top_index is not None else None),
        "scored_cve_count": len(scored),
        "unverified_cve_count": unverified,
        "exploit_reference_count": len(exploits or []),
        "exact_product_version_reference_count": exact_refs,
        "exploit_references_affect_score": False,
        "model": "ReconForge-RP1",
        "notes": [
            "CVSS base severity is kept separate from ReconForge review priority.",
            "Unverified applicability is discounted, not treated as false.",
            "Exploit-DB title matches are supporting research leads and do not increase the numeric score.",
            "Network exposure and business impact are not inferred from an open port.",
        ],
    }


def assess_cves(cves):
    """Return shallow-copied CVE records with their separate priority assessment."""
    return [
        {**cve, "risk_priority": score_cve(cve)}
        for cve in (cves or [])
    ]
