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


def _evaluate_cpe_match(match, vendor, product, detected_version, part):
    """Return True/False/None for a vulnerable CPE entry; None means insufficient host data."""
    criteria = match.get("criteria") or match.get("cpe23Uri") or ""
    expected = f"cpe:2.3:{part}:{vendor}:{product}:"
    if not criteria.startswith(expected):
        return None
    if match.get("vulnerable") is False:
        return None

    fields = criteria.split(":")
    criteria_version = fields[5] if len(fields) > 5 else "*"
    if criteria_version not in ("*", "-", ""):
        cmp = _compare_versions(detected_version, criteria_version)
        if cmp is None:
            return True if detected_version == criteria_version else None
        return cmp == 0

    bounds = [
        (match.get("versionStartIncluding"), ">="),
        (match.get("versionStartExcluding"), ">"),
        (match.get("versionEndIncluding"), "<="),
        (match.get("versionEndExcluding"), "<"),
    ]
    active_bounds = [(value, op) for value, op in bounds if value]
    if not active_bounds:
        return None

    for bound, op in active_bounds:
        cmp = _compare_versions(detected_version, bound)
        if cmp is None:
            return None
        if ((op == ">=" and cmp < 0) or (op == ">" and cmp <= 0)
                or (op == "<=" and cmp > 0) or (op == "<" and cmp >= 0)):
            return False
    return True


def _combine_logic(values, operator):
    """Three-valued AND/OR: None represents an unknown environmental condition."""
    if not values:
        return None
    if str(operator or "OR").upper() == "AND":
        if False in values:
            return False
        return True if all(value is True for value in values) else None
    if True in values:
        return True
    return False if all(value is False for value in values) else None


def _evaluate_node(node, vendor, product, detected_version, part):
    values, evidence, uncertain = [], [], []
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict):
            continue
        result = _evaluate_cpe_match(match, vendor, product, detected_version, part)
        values.append(result)
        if result is True:
            evidence.append({
                "criteria": match.get("criteria") or match.get("cpe23Uri"),
                "reason": "exact_version" if (match.get("criteria") or match.get("cpe23Uri") or "").split(":")[5:6] not in ([], ["*"], ["-"], [""]) else "version_range_match",
                "versionStartIncluding": match.get("versionStartIncluding"),
                "versionStartExcluding": match.get("versionStartExcluding"),
                "versionEndIncluding": match.get("versionEndIncluding"),
                "versionEndExcluding": match.get("versionEndExcluding"),
            })
        elif result is None:
            uncertain.append(match.get("criteria") or match.get("cpe23Uri") or "unknown CPE condition")

    for child in node.get("children") or node.get("nodes") or []:
        if isinstance(child, dict):
            child_result, child_evidence, child_uncertain = _evaluate_node(
                child, vendor, product, detected_version, part
            )
            values.append(child_result)
            evidence.extend(child_evidence)
            uncertain.extend(child_uncertain)

    result = _combine_logic(values, node.get("operator", "OR"))
    if node.get("negate") is True and result is not None:
        result = not result
    return result, evidence, uncertain


def assess_cve_applicability(cve, vendor, product, detected_version, part="a"):
    """Evaluate NVD configuration logic conservatively; never flatten AND/OR expressions."""
    configurations = cve.get("configurations") or []
    if not configurations:
        return {
            "status": "candidate_unverified",
            "confidence": "low",
            "evidence": [],
            "limitations": ["The CVE record has no usable configuration tree; applicability cannot be established."],
        }

    config_results, all_evidence, all_uncertain = [], [], []
    for config in configurations:
        if not isinstance(config, dict):
            continue
        nodes = config.get("nodes") or []
        if not nodes:
            config_results.append(None)
            all_uncertain.append("Configuration has no evaluable nodes")
            continue
        node_results = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            result, evidence, uncertain = _evaluate_node(
                node, vendor, product, detected_version, part
            )
            node_results.append(result)
            all_evidence.extend(evidence)
            all_uncertain.extend(uncertain)
        config_results.append(_combine_logic(node_results, config.get("operator", "OR")))

    # NVD configuration entries are alternatives unless the configuration object says otherwise.
    overall = _combine_logic(config_results, "OR")
    if overall is True:
        return {
            "status": "version_match",
            "confidence": "medium",
            "evidence": all_evidence,
            "limitations": [
                "The target CPE/version matched an NVD vulnerable configuration path.",
                "A CPE/configuration match is not proof of exploitability; review vendor backports, build options, runtime exposure, and the complete environment.",
            ],
        }
    if overall is False:
        return {
            "status": "not_matched_by_nvd_cpe",
            "confidence": "low",
            "evidence": [],
            "limitations": ["No NVD vulnerable configuration path matched the detected product/version; this is not proof the product is safe."],
        }
    return {
        "status": "candidate_unverified",
        "confidence": "low",
        "evidence": [],
        "limitations": [
            "The NVD configuration contains conditions for other products or versions that cannot be verified from this single service banner.",
            "Review the complete NVD configuration and the target's operating-system/environment details manually.",
        ] + list(dict.fromkeys(all_uncertain))[:10],
    }


def classify_exploit(row, product, version):
    """Classify Searchsploit rows conservatively using title/product/version evidence."""
    title = str(row.get("Title") or "")
    haystack = re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()
    product_words = [w for w in re.sub(r"[^a-z0-9]+", " ", (product or "").lower()).split() if len(w) > 1]
    version = (version or "").strip()
    matched_words = [w for w in product_words if re.search(r"\b" + re.escape(w) + r"\b", haystack)]
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
