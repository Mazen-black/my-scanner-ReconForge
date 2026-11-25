"""Conservative CPE conversion and NVD CVE applicability evaluation."""
import re
from urllib.parse import unquote


def cpe22_to_cpe23(uri):
    """Convert CPE 2.2 URI to a valid 13-component CPE 2.3 formatted string."""
    uri = (uri or "").strip()
    if not uri:
        return None
    if uri.startswith("cpe:2.3:"):
        parts = uri.split(":")
        if len(parts) < 5:
            return None
        attrs = parts[2:]
        if len(attrs) > 11:
            return None
        attrs += ["*"] * (11 - len(attrs))
        return "cpe:2.3:" + ":".join(attrs)
    if not uri.startswith("cpe:/"):
        return None
    # CPE 2.2 URI uses escaped separators and percent-encoding.
    raw = uri[5:]
    fields, current, escaped = [], [], False
    for ch in raw:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    fields = [unquote(x) if x else "*" for x in fields]
    if len(fields) < 3 or fields[0] not in ("a", "o", "h"):
        return None
    fields = fields[:11]
    fields += ["*"] * (11 - len(fields))
    return "cpe:2.3:" + ":".join(fields)


def _version_tuple(value):
    """Return a numeric tuple for simple dotted versions; None for ambiguous forms."""
    value = (value or "").strip()
    if not value or value == "*":
        return None
    # Vendor/distribution suffixes may encode security backports; do not discard them.
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)", value, re.I)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _has_vendor_revision(value):
    """Detect common downstream package revisions that may contain security backports."""
    text = (value or "").strip().lower()
    if not text:
        return False
    # Nmap may append distro package data after whitespace (e.g. "5.9p1 Debian 5ubuntu1.10").
    markers = (
        r"(?:^|[\s+~_.-])ubuntu(?:[0-9]|[\s+~_.-]|$)",
        r"(?:^|[\s+~_.-])debian(?:[0-9]|[\s+~_.-]|$)",
        r"(?:^|[\s+~_.-])(?:el|fc|amzn|suse|opensuse)[0-9]*(?:[\s+~_.-]|$)",
        r"(?:^|[\s+~_.-])(?:deb|ds)[0-9]*(?:[\s+~_.-]|$)",
    )
    return any(re.search(pattern, text) for pattern in markers)


def _compare_versions(left, right):
    a, b = _version_tuple(left), _version_tuple(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _version_match(match, detected_version):
    """Return (state, evidence, reason): state is True, False, or None (unknown)."""
    criteria = match.get("criteria") or match.get("cpe23Uri") or ""
    fields = criteria.split(":")
    criteria_version = fields[5] if len(fields) > 5 else "*"
    # Exact textual equality is not enough for downstream package revisions: a
    # distro may backport a fix without changing the upstream version component.
    if _has_vendor_revision(detected_version) or _has_vendor_revision(criteria_version):
        return None, None, f"{criteria}: vendor/distribution package revision may contain backported fixes and is not verified"
    bounds = [
        (match.get("versionStartIncluding"), ">="),
        (match.get("versionStartExcluding"), ">"),
        (match.get("versionEndIncluding"), "<="),
        (match.get("versionEndExcluding"), "<"),
    ]
    if criteria_version not in ("*", "-", ""):
        cmp = _compare_versions(detected_version, criteria_version)
        if cmp is None:
            if detected_version != criteria_version:
                return None, None, f"{criteria}: version format is not safely comparable"
        elif cmp != 0:
            return False, None, None
        reason = "exact_version"
    else:
        if not any(value for value, _ in bounds):
            return None, None, f"{criteria}: wildcard version without explicit version bounds"
        for bound, op in bounds:
            if not bound:
                continue
            cmp = _compare_versions(detected_version, bound)
            if cmp is None:
                return None, None, f"{criteria}: version bounds cannot be compared safely"
            if ((op == ">=" and cmp < 0) or (op == ">" and cmp <= 0)
                    or (op == "<=" and cmp > 0) or (op == "<" and cmp >= 0)):
                return False, None, None
        reason = "version_range_match"
    evidence = {
        "criteria": criteria,
        "reason": reason,
        "vulnerable": match.get("vulnerable") is True,
        "versionStartIncluding": match.get("versionStartIncluding"),
        "versionStartExcluding": match.get("versionStartExcluding"),
        "versionEndIncluding": match.get("versionEndIncluding"),
        "versionEndExcluding": match.get("versionEndExcluding"),
    }
    return True, evidence, None


def _combine_states(states, operator):
    """Kleene three-valued logic: unknown is never promoted to a positive match."""
    if not states:
        return None
    op = str(operator or "OR").upper()
    if op == "AND":
        if False in states:
            return False
        return True if all(state is True for state in states) else None
    if op == "OR":
        if True in states:
            return True
        return False if all(state is False for state in states) else None
    return None


def _evaluate_config_node(node, vendor, product, detected_version, part):
    """Evaluate an NVD node without discarding AND/OR/negate semantics."""
    if not isinstance(node, dict):
        return None, [], ["Malformed NVD configuration node"]
    states, evidence, uncertain = [], [], []
    expected = (part, vendor.lower(), product.lower())
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict):
            states.append(None)
            uncertain.append("Malformed cpeMatch entry")
            continue
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        fields = criteria.split(":")
        if len(fields) != 13 or fields[0:2] != ["cpe", "2.3"]:
            states.append(None)
            uncertain.append("CPE criteria is incomplete or malformed; expected all 11 CPE 2.3 attributes")
            continue
        identity = (fields[2].lower(), fields[3].lower(), fields[4].lower())
        if identity != expected:
            # We only know the detected service, not the rest of the host inventory.
            states.append(None)
            uncertain.append(f"Required environment CPE not assessed: {criteria}")
            continue
        state, item_evidence, reason = _version_match(match, detected_version)
        if state is True:
            # Service fingerprinting does not identify all CPE 2.3 attributes.
            # A constrained update/edition/OS/hardware value must remain unknown.
            constrained = [
                (name, value)
                for name, value in zip(
                    ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"),
                    fields[6:13],
                )
                if value not in ("*", "")
            ]
            if constrained:
                details = ", ".join(f"{name}={value}" for name, value in constrained)
                state, item_evidence = None, None
                reason = f"{criteria}: constrained CPE attributes were not identified by the service scan ({details})"
        states.append(state)
        if item_evidence:
            evidence.append(item_evidence)
        if reason:
            uncertain.append(reason)
    for child in node.get("children") or node.get("nodes") or []:
        child_state, child_evidence, child_uncertain = _evaluate_config_node(
            child, vendor, product, detected_version, part
        )
        states.append(child_state)
        evidence.extend(child_evidence)
        uncertain.extend(child_uncertain)
    state = _combine_states(states, node.get("operator", "OR"))
    if node.get("negate") is True:
        state = None if state is None else not state
        if state is True:
            # A negated condition is not affirmative evidence that this product is vulnerable.
            state = None
            uncertain.append("Negated NVD condition cannot establish vulnerable-product applicability")
    return state, evidence, uncertain


def assess_cve_applicability(cve, vendor, product, detected_version, part="a"):
    """Conservatively evaluate complete NVD configuration logic for one detected product."""
    configurations = cve.get("configurations") or []
    root_states, matched_evidence, uncertain = [], [], []
    for config in configurations:
        if not isinstance(config, dict):
            root_states.append(None)
            uncertain.append("Malformed NVD configuration")
            continue
        nodes = config.get("nodes") or []
        node_states, config_evidence, config_uncertain = [], [], []
        for node in nodes:
            state, evidence, reasons = _evaluate_config_node(
                node, vendor, product, detected_version, part
            )
            node_states.append(state)
            config_evidence.extend(evidence)
            config_uncertain.extend(reasons)
        config_state = _combine_states(node_states, config.get("operator", "OR"))
        if config.get("negate") is True:
            config_state = None if config_state is None else not config_state
            if config_state is True:
                config_state = None
                config_uncertain.append("Negated top-level NVD condition is not positive vulnerability evidence")
        root_states.append(config_state)
        if config_state is True:
            matched_evidence.extend(item for item in config_evidence if item.get("vulnerable") is True)
        uncertain.extend(config_uncertain)

    # NVD configuration objects are alternatives: one fully satisfied vulnerable path is sufficient.
    overall = _combine_states(root_states, "OR")
    if overall is True and matched_evidence:
        reasons = [
            "A complete NVD configuration path matched the detected product and version.",
            "The matched vulnerable CPE criteria and version comparison are retained as evidence.",
        ]
        gaps = [
            "Vendor backport or downstream patch status has not been verified.",
            "Build options, runtime configuration, and network exposure have not been verified.",
            "A service banner does not prove the installed binary is the affected build.",
        ]
        return {
            "status": "version_match",
            "confidence": "medium",
            "applicability_confidence": "medium",
            "exploitability_confidence": "unknown",
            "evidence": matched_evidence,
            "evidence_sources": ["NVD CPE configuration and version-range metadata", "Nmap service/product/version identification"],
            "confidence_reasons": reasons,
            "evidence_gaps": gaps,
            "limitations": [
                "The complete evaluated NVD configuration path matched, but this is still not proof of exploitability.",
                "Verify vendor backports, build options, platform constraints, and runtime exposure.",
            ],
        }
    if overall is True and not matched_evidence:
        uncertain.append("Configuration matched, but no vulnerable=true CPE for the detected product was established")
    # In three-valued logic, a known false branch makes an AND expression false
    # even when another environmental component is unknown (False AND Unknown = False).
    if overall is None or (overall is True and not matched_evidence):
        gaps = list(dict.fromkeys(uncertain)) + [
            "A complete vulnerable-product applicability path could not be established from available inventory."
        ]
        return {
            "status": "candidate_unverified",
            "confidence": "low",
            "applicability_confidence": "low",
            "exploitability_confidence": "unknown",
            "evidence": [],
            "evidence_sources": ["NVD CPE configuration metadata", "Nmap service/product/version identification"],
            "confidence_reasons": ["Available evidence is incomplete or contains unresolved configuration conditions."],
            "evidence_gaps": gaps,
            "limitations": gaps + [
                "Incomplete host inventory or ambiguous NVD logic prevents a confirmed applicability match."
            ],
        }
    return {
        "status": "not_matched_by_nvd_cpe",
        "confidence": "low",
        "applicability_confidence": "low",
        "exploitability_confidence": "unknown",
        "evidence": [],
        "evidence_sources": ["NVD CPE configuration and version-range metadata", "Nmap service/product/version identification"],
        "confidence_reasons": ["The evaluated NVD configuration did not establish an applicable vulnerable-product path."],
        "evidence_gaps": ["NVD coverage and vendor-specific backports may be incomplete or differ from upstream versioning."],
        "limitations": [
            "No complete vulnerable NVD configuration path matched the detected product/version.",
            "This is not proof the product is safe.",
        ],
    }


CVE_CONTEXT_CONSTRAINTS = {
    "CVE-2011-2523": {
        "kind": "build_provenance",
        "condition": (
            "The backdoored vsftpd 2.3.4 source archives were downloaded between "
            "2011-06-30 and 2011-07-03; version 2.3.4 alone does not establish that provenance."
        ),
        "required_evidence": [
            "Package or source-archive download/build provenance for the affected date window.",
            "Binary/package hash or trusted vendor package metadata.",
            "Confirmation that the installed build is the backdoored upstream artifact, not a clean rebuild or vendor package."
        ],
        "source": "CVE/NVD description and CNA/vendor advisory context",
    },
}


def apply_contextual_cve_constraints(cve_id, applicability, summary=""):
    """Downgrade broad CPE matches when a CVE also requires build/provenance evidence."""
    result = dict(applicability or {})
    constraint = CVE_CONTEXT_CONSTRAINTS.get(str(cve_id or "").upper())
    if not constraint:
        return result
    if result.get("status") == "version_match":
        result["cpe_version_status"] = "version_match"
        result["status"] = "candidate_unverified"
        result["confidence"] = "low"
        result["applicability_confidence"] = "low"
        result["exploitability_confidence"] = "unknown"
        result["confidence_reasons"] = list(result.get("confidence_reasons") or []) + [
            "A contextual build/provenance condition is not established by the CPE version match."
        ]
        result["evidence_gaps"] = list(result.get("evidence_gaps") or []) + list(constraint.get("required_evidence") or [])
        result["evidence_sources"] = list(dict.fromkeys(
            list(result.get("evidence_sources") or []) + [constraint.get("source", "CVE contextual advisory metadata")]
        ))
        result["contextual_constraint"] = dict(constraint)
        result["limitations"] = list(result.get("limitations") or []) + [
            "The NVD CPE version matched, but this CVE has an additional build/provenance condition that cannot be verified from a service banner.",
            "Do not report this as confirmed affected until the contextual condition is independently established.",
        ]
    return result
