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


def _walk_cpe_matches(value):
    """Yield cpeMatch records from NVD configurations without assuming node shape."""
    if isinstance(value, dict):
        for match in value.get("cpeMatch") or []:
            if isinstance(match, dict):
                yield match
        for key in ("nodes", "children"):
            for child in value.get(key) or []:
                yield from _walk_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpe_matches(child)


def assess_cve_applicability(cve, vendor, product, detected_version, part="a"):
    """Assess only vulnerable CPE entries for this product; ambiguous version logic stays candidate."""
    expected = f"cpe:2.3:{part}:{vendor}:{product}:"
    evidence = []
    uncertain = []
    configs = cve.get("configurations") or []
    for match in _walk_cpe_matches(configs):
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        if not criteria.startswith(expected):
            continue
        if match.get("vulnerable") is False:
            continue
        fields = criteria.split(":")
        criteria_version = fields[5] if len(fields) > 5 else "*"
        reason = None
        if criteria_version not in ("*", "-", ""):
            cmp = _compare_versions(detected_version, criteria_version)
            if cmp is None:
                if detected_version == criteria_version:
                    reason = "exact_version"
                else:
                    uncertain.append(f"{criteria}: version format is not safely comparable")
                    continue
            elif cmp == 0:
                reason = "exact_version"
            else:
                continue
        else:
            lower_inc = match.get("versionStartIncluding")
            lower_exc = match.get("versionStartExcluding")
            upper_inc = match.get("versionEndIncluding")
            upper_exc = match.get("versionEndExcluding")
            bounds = [(lower_inc, ">="), (lower_exc, ">"), (upper_inc, "<="), (upper_exc, "<")]
            if not any(v for v, _ in bounds):
                uncertain.append(f"{criteria}: wildcard version without explicit version bounds")
                continue
            valid = True
            for bound, op in bounds:
                if not bound:
                    continue
                cmp = _compare_versions(detected_version, bound)
                if cmp is None:
                    valid = False
                    break
                if (op == ">=" and cmp < 0) or (op == ">" and cmp <= 0) or (op == "<=" and cmp > 0) or (op == "<" and cmp >= 0):
                    valid = False
                    break
            if not valid:
                if any(_compare_versions(detected_version, b) is None for b, _ in bounds if b):
                    uncertain.append(f"{criteria}: version bounds cannot be compared safely")
                continue
            reason = "version_range_match"
        evidence.append({
            "criteria": criteria,
            "reason": reason,
            "versionStartIncluding": match.get("versionStartIncluding"),
            "versionStartExcluding": match.get("versionStartExcluding"),
            "versionEndIncluding": match.get("versionEndIncluding"),
            "versionEndExcluding": match.get("versionEndExcluding"),
        })
    if evidence:
        return {
            "status": "version_match",
            "confidence": "medium",
            "evidence": evidence,
            "limitations": ["CPE/version-range match is not proof of exploitability; review full NVD configuration logic, vendor backports, build options, and runtime exposure."],
        }
    if uncertain:
        return {
            "status": "candidate_unverified",
            "confidence": "low",
            "evidence": [],
            "limitations": uncertain + ["NVD search result alone does not establish that this installed version is vulnerable."],
        }
    return {
        "status": "not_matched_by_nvd_cpe",
        "confidence": "low",
        "evidence": [],
        "limitations": ["No matching vulnerable CPE/version range was found in the returned NVD configuration data; this is not proof the product is safe."],
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
