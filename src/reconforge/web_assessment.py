"""Offline HTTP hardening and bounded web-content analysis helpers."""
import re


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
