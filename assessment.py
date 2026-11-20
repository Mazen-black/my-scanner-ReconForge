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
    # In three-valued logic, a known false branch makes an AND expression false
    # even when another environmental component is unknown (False AND Unknown = False).
    if overall is None or (overall is True and not matched_evidence):
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

# NVD CPE ranges can be broader than the actual condition described by a CNA.
# Keep known build/provenance conditions explicit instead of treating a CPE hit as proof.
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
        result["contextual_constraint"] = dict(constraint)
        result["limitations"] = list(result.get("limitations") or []) + [
            "The NVD CPE version matched, but this CVE has an additional build/provenance condition that cannot be verified from a service banner.",
            "Do not report this as confirmed affected until the contextual condition is independently established.",
        ]
    return result


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
    version_candidates = list(dict.fromkeys(re.findall(
        r"(?<![0-9a-z])v?\d+(?:\.\d+){1,3}(?:[-+][a-z0-9._-]+)?(?![0-9a-z])",
        title.lower(),
    )))
    if not product_words or not matched_words:
        relevance, confidence = "weak_or_unrelated", "low"
    elif len(matched_words) == len(product_words) and version_match:
        relevance, confidence = "product_and_version_match", "low"
    elif len(matched_words) == len(product_words) and version_candidates and version:
        relevance, confidence = "product_match_different_version_in_title", "low"
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
            "detected_version": version or None,
            "version_candidates_in_title": version_candidates,
            "title": title,
        },
        "limitations": [
            "Searchsploit title matching is heuristic and does not validate affected build, platform, configuration, prerequisites, or exploit reliability.",
            "An exact product/version string in a title is a research lead, not proof that the target is vulnerable.",
        ],
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
    raw_cpes = data.get("cpe") or []
    # python-nmap may expose a single CPE as a string; iterating it directly
    # would incorrectly turn the identifier into a list of characters.
    if isinstance(raw_cpes, str):
        raw_cpes = [raw_cpes]
    elif not isinstance(raw_cpes, (list, tuple, set)):
        raw_cpes = []
    cpes = [str(value).strip() for value in raw_cpes if value and str(value).strip()]

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





def analyze_web_content(html, robots_txt=None, sitemap_xml=None):
    """Extract conservative CMS/library hints and limited robots/sitemap metadata from fetched text."""
    from html.parser import HTMLParser
    from urllib.parse import urlparse

    class PageSignals(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.meta = []
            self.assets = []
            self.links = []
        def handle_starttag(self, tag, attrs):
            attrs = {str(k).lower(): v for k, v in attrs}
            if tag.lower() == "meta":
                self.meta.append(attrs)
            for key in ("src", "href"):
                value = attrs.get(key)
                if value and isinstance(value, str):
                    self.assets.append(value[:500])

    parser = PageSignals()
    try:
        parser.feed((html or "")[:262144])
    except Exception:
        pass

    technologies = []
    evidence = []
    def add(name, category, source, confidence="medium", version=None):
        item = {"name": name, "category": category, "confidence": confidence,
                "evidence": source}
        if version:
            item["version"] = version[:40]
        if item not in technologies:
            technologies.append(item)

    for meta in parser.meta:
        name = (meta.get("name") or "").lower()
        content = (meta.get("content") or "").strip()
        if name == "generator" and content:
            generator = content[:120]
            evidence.append({"type": "meta_generator", "value": generator})
            match = re.search(r"(?i)(wordpress|drupal|joomla)(?:\s+|/)?([0-9][\w.\-]*)?", generator)
            if match:
                add({"wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla"}[match.group(1).lower()], "cms", "meta_generator", "medium", match.group(2))

    all_assets = "\n".join(parser.assets)
    asset_patterns = (
        (r"(?i)(?:^|[/])wp-content[/]", "WordPress", "cms", None),
        (r"(?i)(?:^|[/])wp-includes[/]", "WordPress", "cms", None),
        (r"(?i)(?:^|[/])sites/default/files[/]", "Drupal", "cms", None),
        (r"(?i)(?:^|[/])media/system/js[/]", "Joomla", "cms", None),
        (r"(?i)(?:^|[/])jquery(?:[-.]([0-9]+(?:\.[0-9]+){0,3}))?(?:\.min)?\.js", "jQuery", "javascript_library", 1),
        (r"(?i)(?:^|[/])react(?:[-.]([0-9]+(?:\.[0-9]+){0,3}))?(?:\.production)?(?:\.min)?\.js", "React", "javascript_library", 1),
        (r"(?i)(?:^|[/])vue(?:[-.]([0-9]+(?:\.[0-9]+){0,3}))?(?:\.min)?\.js", "Vue.js", "javascript_library", 1),
        (r"(?i)(?:^|[/])angular(?:[-.]([0-9]+(?:\.[0-9]+){0,3}))?(?:\.min)?\.js", "Angular", "javascript_library", 1),
    )
    for pattern, name, category, version_group in asset_patterns:
        match = re.search(pattern, all_assets)
        if match:
            version = match.group(version_group) if version_group else None
            source = "asset_url_pattern"
            add(name, category, source, "medium" if version else "low", version)
            evidence.append({"type": source, "technology": name,
                             "asset_path_hint": urlparse(match.group(0)).path[:160]})

    robots = {"fetched": robots_txt is not None, "disallow_directives": 0,
              "sitemap_directives": 0}
    if robots_txt is not None:
        for line in (robots_txt or "").splitlines()[:2000]:
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, _ = line.split(":", 1)
            if key.strip().lower() == "disallow":
                robots["disallow_directives"] += 1
            elif key.strip().lower() == "sitemap":
                robots["sitemap_directives"] += 1

    sitemap = {"fetched": sitemap_xml is not None, "url_count": 0}
    if sitemap_xml is not None:
        sitemap["url_count"] = min(len(re.findall(r"<(?:\w+:)?loc\b", sitemap_xml, re.I)), 100000)

    return {
        "status": "analyzed",
        "technologies": technologies,
        "evidence": evidence,
        "robots_txt": robots,
        "sitemap_xml": sitemap,
        "limitations": [
            "Technology identification uses visible HTML metadata and asset URL patterns only; it is heuristic and can be spoofed.",
            "No JavaScript files, external hosts, or linked pages are fetched.",
            "robots.txt and sitemap.xml are fetched only from fixed same-origin paths; discovered URLs are not crawled.",
            "robots.txt directives are not access controls and must not be treated as authorization boundaries.",
        ],
    }


NETWORK_SERVICE_RULES = {
    21: ("legacy_cleartext_service", "FTP service exposed", "medium",
         "FTP commonly transmits credentials and data without encryption. Prefer SFTP or FTPS and restrict source networks."),
    23: ("legacy_cleartext_service", "Telnet service exposed", "high",
         "Telnet provides no transport encryption. Disable it and use SSH with key-based authentication."),
    111: ("rpc_service_exposed", "RPC portmapper exposed", "medium",
          "Restrict RPC portmapper to trusted internal networks and disable unused RPC services."),
    135: ("windows_management_exposure", "Windows RPC endpoint mapper exposed", "medium",
          "Limit RPC access with host/network firewalls and verify that only required management paths are reachable."),
    139: ("file_sharing_exposure", "NetBIOS session service exposed", "medium",
          "Restrict NetBIOS/SMB to trusted networks and disable legacy protocols where possible."),
    445: ("file_sharing_exposure", "SMB service exposed", "medium",
          "Restrict SMB to trusted networks, disable SMBv1, enforce signing where appropriate, and patch the host."),
    1433: ("database_exposure", "Microsoft SQL Server port exposed", "high",
           "Do not expose database listeners to untrusted networks; bind to private interfaces and enforce network allowlists."),
    1521: ("database_exposure", "Oracle database listener exposed", "high",
           "Restrict database listener access to application and administration networks; require strong authentication."),
    3306: ("database_exposure", "MySQL/MariaDB port exposed", "high",
           "Keep database listeners off public interfaces and allow only required application hosts."),
    5432: ("database_exposure", "PostgreSQL port exposed", "high",
           "Restrict PostgreSQL to trusted application/admin networks and review pg_hba.conf access rules."),
    6379: ("database_exposure", "Redis port exposed", "high",
           "Bind Redis to trusted interfaces, use ACL authentication, and firewall the listener; never expose it publicly."),
    27017: ("database_exposure", "MongoDB port exposed", "high",
            "Restrict MongoDB to private networks, enable authentication and authorization, and verify bindIp settings."),
    9200: ("search_service_exposure", "Elasticsearch HTTP API exposed", "high",
           "Restrict Elasticsearch to trusted networks and enable authentication/TLS; avoid direct public exposure."),
    2375: ("container_management_exposure", "Docker remote API exposed without TLS convention", "critical",
           "Disable unauthenticated remote Docker API access. Use a protected Unix socket or mutually authenticated TLS on a restricted management network."),
    2376: ("container_management_exposure", "Docker remote API port exposed", "high",
           "Restrict Docker API access to dedicated management hosts and require mutual TLS authentication."),
    3389: ("remote_access_exposure", "RDP service exposed", "high",
           "Place RDP behind VPN or a zero-trust gateway, enforce MFA/NLA, and restrict source IPs."),
    5900: ("remote_access_exposure", "VNC service exposed", "high",
           "Restrict VNC to trusted networks or a VPN and use strong authentication with encrypted transport."),
    11211: ("cache_service_exposure", "Memcached service exposed", "high",
            "Bind Memcached to private interfaces and block untrusted access at the network perimeter."),
}

def assess_network_exposure(port, service="", product=""):
    """Return conservative exposure observations for well-known sensitive TCP services."""
    try:
        number = int(port)
    except (TypeError, ValueError):
        return []
    rule = NETWORK_SERVICE_RULES.get(number)
    if not rule:
        return []
    finding_id, title, severity, recommendation = rule
    return [{
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": "exposed_service_observed",
        "evidence": {
            "tcp_port": number,
            "nmap_service": str(service or "")[:80] or None,
            "nmap_product": str(product or "")[:120] or None,
        },
        "recommendation": recommendation,
        "limitations": [
            "An open TCP port is an exposure observation, not proof of a vulnerability or successful compromise.",
            "Confirm the service identity, intended network boundary, firewall policy, and business requirement.",
        ],
    }]


def build_exploit_intelligence(exploits, cves):
    """Enrich local exploit references with CVE applicability context and safe triage guidance."""
    cve_by_id = {
        str(item.get("id") or "").upper(): item
        for item in (cves or [])
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(item.get("id") or ""), re.I)
    }
    intelligence = []
    for exploit in exploits or []:
        if not isinstance(exploit, dict):
            continue
        edb_id = str(exploit.get("id") or "").strip()
        title = str(exploit.get("title") or "")
        explicit_ids = sorted(set(re.findall(r"(?i)\bCVE-\d{4}-\d{4,}\b", title)))
        linked_ids = [value.upper() for value in explicit_ids if value.upper() in cve_by_id]
        linked_assessments = []
        for cve_id in linked_ids:
            cve = cve_by_id[cve_id]
            applicability = cve.get("applicability") or {}
            linked_assessments.append({
                "cve_id": cve_id,
                "applicability_status": applicability.get("status", "candidate_unverified"),
                "confidence": applicability.get("confidence", "low"),
                "cvss": cve.get("cvss"),
                "contextual_constraint": applicability.get("contextual_constraint"),
            })
        if not explicit_ids:
            correlation_status = "no_explicit_cve_link"
            triage_status = "manual_cve_correlation_required"
        elif not linked_ids:
            correlation_status = "explicit_cve_not_in_scanner_results"
            triage_status = "cve_not_returned_by_scanner"
        elif any(item["applicability_status"] == "version_match" for item in linked_assessments):
            correlation_status = "explicit_title_and_scanner_match"
            triage_status = "cve_version_match_still_requires_manual_validation"
        elif any(item["applicability_status"] == "candidate_unverified" for item in linked_assessments):
            correlation_status = "explicit_cve_match_applicability_unverified"
            triage_status = "cve_candidate_unverified"
        else:
            correlation_status = "explicit_cve_match_not_applicable"
            triage_status = "cve_not_matched_by_nvd_cpe"
        valid_edb_id = edb_id if re.fullmatch(r"\d{1,8}", edb_id) else None
        source_assessment = (exploit.get("assessment") or {}).copy()
        intelligence.append({
            "reference": {
                "source": "Exploit-DB",
                "id": valid_edb_id,
                "url": f"https://www.exploit-db.com/exploits/{valid_edb_id}" if valid_edb_id else None,
                "title": title[:300],
                "type": str(exploit.get("type") or "")[:80] or None,
                "platform": str(exploit.get("platform") or "")[:80] or None,
            },
            "cve_correlation": {
                "explicit_cve_ids_in_title": explicit_ids,
                "matched_scanner_cve_ids": linked_ids,
                "matched_cve_applicability": linked_assessments,
                "status": correlation_status,
            },
            "source_assessment": source_assessment,
            "triage": {
                "status": triage_status,
                "confidence": "low",
                "meaning": "Research relevance only; this is not a vulnerability confirmation.",
            },
            "validation_guidance": [
                "Confirm the vendor advisory's affected product, exact version, build provenance, and platform.",
                "Check exploit prerequisites, required privileges, configuration, mitigations, and whether the exploit applies to this implementation.",
                "If a CVE has additional build/provenance conditions, verify those independently; a CPE version match is insufficient.",
                "Validate only through non-invasive checks or in an isolated lab under an explicitly authorized test plan.",
            ],
            "execution_status": "not_executed",
            "limitations": [
                "An Exploit-DB reference or title match does not prove target vulnerability or exploit reliability.",
                "CVE correlation is based only on explicit CVE identifiers in the exploit title.",
                "NVD CPE applicability is kept separate from exploit applicability and may omit build-specific conditions.",
                "No exploit payload was downloaded, launched, or executed by ReconForge.",
            ],
        })
    return intelligence


def build_report_entry(host, port, state, service, product, version, cpes_tested, cves, exploits, fingerprint=None, http_assessment=None, web_intelligence=None, network_exposure=None, exploit_intelligence=None):
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
