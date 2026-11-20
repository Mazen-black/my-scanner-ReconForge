"""Conservative offline helpers for CPE, CVE applicability, and exploit relevance."""
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
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)(?:[-+_].*)?", value, re.I)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


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
        if len(fields) < 6 or fields[0:2] != ["cpe", "2.3"]:
            states.append(None)
            uncertain.append("CPE criteria is missing or malformed")
            continue
        identity = (fields[2].lower(), fields[3].lower(), fields[4].lower())
        if identity != expected:
            # We only know the detected service, not the rest of the host inventory.
            states.append(None)
            uncertain.append(f"Required environment CPE not assessed: {criteria}")
            continue
        state, item_evidence, reason = _version_match(match, detected_version)
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
        return {
            "status": "version_match",
            "confidence": "medium",
            "evidence": matched_evidence,
            "limitations": [
                "The complete evaluated NVD configuration path matched, but this is still not proof of exploitability.",
                "Verify vendor backports, build options, platform constraints, and runtime exposure.",
            ],
        }
    if overall is True and not matched_evidence:
        uncertain.append("Configuration matched, but no vulnerable=true CPE for the detected product was established")
    if overall is None or uncertain:
        return {
            "status": "candidate_unverified",
            "confidence": "low",
            "evidence": [],
            "limitations": list(dict.fromkeys(uncertain)) + [
                "Incomplete host inventory or ambiguous NVD logic prevents a confirmed applicability match."
            ],
        }
    return {
        "status": "not_matched_by_nvd_cpe",
        "confidence": "low",
        "evidence": [],
        "limitations": [
            "No complete vulnerable NVD configuration path matched the detected product/version.",
            "This is not proof the product is safe.",
        ],
    }

def classify_exploit(row, product, version):
    """Classify Searchsploit rows conservatively using title/product/version evidence."""
    title = str(row.get("Title") or "")
    haystack = re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()
    product_words = [w for w in re.sub(r"[^a-z0-9]+", " ", (product or "").lower()).split() if len(w) > 1]
    version = (version or "").strip()
    matched_words = [w for w in product_words if re.search(r"\b" + re.escape(w) + r"\b", haystack)]
    # Search the original title for version punctuation (e.g. dots); haystack normalization removes it.
    version_match = bool(version and re.search(
        r"(?<![0-9a-z])" + re.escape(version.lower()) + r"(?![0-9a-z])", title.lower()
    ))
    if not product_words or not matched_words:
        relevance, confidence = "weak_or_unrelated", "low"
    elif len(matched_words) == len(product_words) and version_match:
        relevance, confidence = "product_and_version_match", "medium"
    elif len(matched_words) == len(product_words):
        relevance, confidence = "product_match_version_unconfirmed", "low"
    else:
        relevance, confidence = "partial_product_match", "low"
    return {
        "relevance": relevance,
        "confidence": confidence,
        "evidence": {
            "product_tokens_matched": matched_words,
            "product_tokens_expected": product_words,
            "version_text_match": version_match,
            "title": title,
        },
        "limitations": ["Searchsploit title matching is heuristic; validate affected versions, platform, prerequisites, and exploit behavior before treating as applicable."],
    }


def build_report_entry(host, port, state, service, product, version, cpes_tested, cves, exploits):
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
        },
        "cve_assessment": cves,
        "searchsploit_assessment": exploits,
        "assessment_limits": [
            "Nmap product/version banners may be incomplete or spoofed.",
            "A matching CVE or exploit reference is not confirmation of a vulnerability.",
            "No exploit was executed by this report generator.",
        ],
    }
