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


def build_technology_fingerprint(port_data):
    """Summarize observed Nmap identity and conservative technology hints with provenance."""
    data = port_data if isinstance(port_data, dict) else {}
    service = str(data.get("name") or "").strip()
    product = str(data.get("product") or "").strip()
    version = str(data.get("version") or "").strip()
    extrainfo = str(data.get("extrainfo") or "").strip()
    tunnel = str(data.get("tunnel") or "").strip()
    method = str(data.get("method") or "").strip()
    confidence = data.get("conf")
    cpes = [str(value) for value in (data.get("cpe") or []) if value]

    observations = []
    for field, value in (
        ("product", product), ("service", service),
        ("extrainfo", extrainfo), ("tunnel", tunnel),
    ):
        if value:
            observations.append({"source": f"nmap.{field}", "value": value})

    stack = []
    haystacks = (
        ("nmap.product", product, "high"),
        ("nmap.extrainfo", extrainfo, "medium"),
        ("nmap.service", service, "medium"),
    )
    rules = (
        ("web_server", r"\b(apache|httpd|nginx|iis|caddy|lighttpd)\b"),
        ("application_server", r"\b(tomcat|jetty|wildfly|jboss|weblogic)\b"),
        ("php_runtime", r"\bphp(?:/[0-9][\w.]*)?\b"),
        ("openssl", r"\bopenssl(?:/[0-9][\w.]*)?\b"),
        ("openssh", r"\bopenssh(?:_[0-9][\w.]*)?\b"),
        ("database", r"\b(mysql|mariadb|postgresql|mongodb|redis|microsoft sql server)\b"),
        ("reverse_proxy", r"\b(haproxy|traefik|envoy)\b"),
        ("container_platform", r"\b(docker|containerd|podman)\b"),
    )
    seen = set()
    for source, value, confidence_level in haystacks:
        for category, pattern in rules:
            match = re.search(pattern, value, re.I)
            if match and (category, match.group(0).lower()) not in seen:
                seen.add((category, match.group(0).lower()))
                stack.append({
                    "category": category,
                    "technology": match.group(0),
                    "source": source,
                    "confidence": confidence_level,
                })

    if tunnel.lower() in ("ssl", "tls") or service.lower() in ("https", "ssl", "tls"):
        stack.append({
            "category": "encrypted_transport",
            "technology": "TLS/SSL",
            "source": "nmap.tunnel" if tunnel else "nmap.service",
            "confidence": "medium",
        })

    return {
        "observed": {
            "service": service or None,
            "product": product or None,
            "version": version or None,
            "extrainfo": extrainfo or None,
            "tunnel": tunnel or None,
            "method": method or None,
            "nmap_confidence": confidence,
            "cpes": cpes,
        },
        "evidence": observations,
        "technology_stack": stack,
        "limitations": [
            "Technology labels are hints derived from Nmap service metadata, not proof of installed components.",
            "Banners may be incomplete, modified, proxied, or intentionally misleading.",
            "No active HTTP probing or application-layer fingerprinting is performed by this stage.",
        ],
    }


def analyze_http_security(headers, set_cookie_headers=None, is_https=False):
    """Analyze HTTP hardening headers and cookie attributes without retaining cookie values."""
    normalized = {str(key).lower(): str(value).strip() for key, value in (headers or {}).items()}
    findings = []
    checks = (
        ("content-security-policy", "Content-Security-Policy", "medium", "Define a restrictive Content Security Policy to reduce script injection impact."),
        ("x-content-type-options", "X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff."),
        ("x-frame-options", "X-Frame-Options", "low", "Set X-Frame-Options or use CSP frame-ancestors to control framing."),
        ("referrer-policy", "Referrer-Policy", "low", "Set an explicit Referrer-Policy appropriate for the application."),
        ("permissions-policy", "Permissions-Policy", "informational", "Consider restricting browser features that the application does not need."),
    )
    for key, label, severity, recommendation in checks:
        value = normalized.get(key)
        if not value:
            findings.append({"id": f"missing_{key.replace('-', '_')}", "title": f"Missing {label}",
                             "severity": severity, "status": "not_observed", "evidence": None,
                             "recommendation": recommendation})
        elif key == "content-security-policy":
            lowered = value.lower()
            weak = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in lowered]
            if weak:
                findings.append({"id": "csp_permissive_directives", "title": "Potentially permissive Content Security Policy",
                                 "severity": "low", "status": "review", "evidence": {"directives_to_review": weak},
                                 "recommendation": "Review broad CSP sources and unsafe script directives; validate against application requirements."})
        elif key == "x-content-type-options" and value.lower() != "nosniff":
            findings.append({"id": "weak_x_content_type_options", "title": "Unexpected X-Content-Type-Options value",
                             "severity": "low", "status": "review", "evidence": value[:120],
                             "recommendation": "Use the nosniff value."})

    if is_https and "strict-transport-security" not in normalized:
        findings.append({"id": "missing_strict_transport_security", "title": "Missing Strict-Transport-Security",
                         "severity": "low", "status": "not_observed", "evidence": None,
                         "recommendation": "Consider HSTS after confirming HTTPS is correctly deployed across the intended host scope."})
    elif "strict-transport-security" in normalized and not re.search(
            r"(?i)(?:^|;)\s*max-age\s*=\s*\d+", normalized["strict-transport-security"]):
        findings.append({"id": "hsts_missing_max_age", "title": "HSTS max-age is missing or invalid",
                         "severity": "low", "status": "review", "evidence": normalized["strict-transport-security"][:160],
                         "recommendation": "Set a deliberate max-age after validating HTTPS deployment."})

    cookies = []
    for raw_cookie in set_cookie_headers or []:
        parts = [part.strip() for part in str(raw_cookie).split(";") if part.strip()]
        if not parts:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip()
        attrs = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        same_site = next((part.split("=", 1)[1].strip() for part in parts[1:]
                          if "=" in part and part.split("=", 1)[0].strip().lower() == "samesite"), None)
        cookie = {"name": cookie_name[:100] or "(unnamed)", "secure": "secure" in attrs,
                  "httponly": "httponly" in attrs, "samesite": same_site}
        cookies.append(cookie)
        checks_cookie = (
            ("secure", is_https, "cookie_missing_secure", "Cookie missing Secure attribute",
             "Set Secure on cookies intended to be sent only over HTTPS."),
            ("httponly", True, "cookie_missing_httponly", "Cookie missing HttpOnly attribute",
             "Set HttpOnly when client-side JavaScript does not need to read the cookie."),
            ("samesite", True, "cookie_missing_samesite", "Cookie missing SameSite attribute",
             "Choose an appropriate SameSite policy based on application flows."),
        )
        for attr, applicable, finding_id, title, recommendation in checks_cookie:
            if applicable and not cookie[attr]:
                findings.append({"id": finding_id, "title": title, "severity": "low", "status": "review",
                                 "evidence": {"cookie_name": cookie["name"]}, "recommendation": recommendation})

    return {
        "status": "analyzed",
        "http_headers_observed": sorted(normalized.keys()),
        "server_banner": normalized.get("server"),
        "powered_by": normalized.get("x-powered-by"),
        "cookies": cookies,
        "findings": findings,
        "limitations": [
            "Only response headers from a single HEAD request to / were inspected.",
            "Missing hardening headers are configuration observations, not proof of an exploitable vulnerability.",
            "Cookie values are never stored in this report.",
            "No redirects, crawling, form submissions, or active vulnerability payloads are used.",
        ],
    }


def build_report_entry(host, port, state, service, product, version, cpes_tested, cves, exploits, fingerprint=None, http_assessment=None):
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
        "http_assessment": http_assessment,
        "cve_assessment": cves,
        "searchsploit_assessment": exploits,
        "assessment_limits": [
            "Nmap product/version banners may be incomplete or spoofed.",
            "A matching CVE or exploit reference is not confirmation of a vulnerability.",
            "No exploit was executed by this report generator.",
        ],
    }
