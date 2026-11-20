"""Contextual prioritization using explicitly supplied asset and exposure data.

This layer never infers internet exposure or business criticality from open ports.
The technical CVE priority remains available separately from contextual priority.
"""

CRITICALITY_FACTORS = {
    "unknown": 1.0,
    "low": 0.80,
    "medium": 1.00,
    "high": 1.15,
    "critical": 1.30,
}

EXPOSURE_FACTORS = {
    "unknown": 1.0,
    "internal": 0.90,
    "internet": 1.15,
}


def _level(score):
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


def assess_asset_context(technical_risk, criticality="unknown", exposure="unknown"):
    """Return an explainable context-adjusted review priority (not CVSS/business risk)."""
    criticality = str(criticality or "unknown").lower()
    exposure = str(exposure or "unknown").lower()
    if criticality not in CRITICALITY_FACTORS:
        raise ValueError(f"Unsupported asset criticality: {criticality}")
    if exposure not in EXPOSURE_FACTORS:
        raise ValueError(f"Unsupported exposure: {exposure}")

    technical_score = (technical_risk or {}).get("score")
    valid_score = (
        isinstance(technical_score, (int, float))
        and not isinstance(technical_score, bool)
        and 0 <= technical_score <= 100
    )
    criticality_factor = CRITICALITY_FACTORS[criticality]
    exposure_factor = EXPOSURE_FACTORS[exposure]
    contextual_score = (
        round(min(100.0, float(technical_score) * criticality_factor * exposure_factor), 1)
        if valid_score else None
    )
    return {
        "model": "ReconForge-AC1",
        "asset_criticality": criticality,
        "network_exposure": exposure,
        "technical_priority_score": float(technical_score) if valid_score else None,
        "criticality_factor": criticality_factor,
        "exposure_factor": exposure_factor,
        "contextual_priority_score": contextual_score,
        "contextual_priority": _level(contextual_score),
        "is_cvss": False,
        "rationale": (
            "Contextual priority = technical review priority × explicit asset criticality factor "
            "× explicit exposure factor, capped at 100. Unknown context uses neutral factors."
        ),
        "limitations": [
            "Criticality and exposure are operator-supplied labels, not discovered facts.",
            "An open port does not establish internet reachability.",
            "This contextual score is a review aid, not CVSS or a quantified business-loss estimate.",
        ],
    }
