"""Bounded HTTP and same-origin web intelligence probes."""

import requests

SCANNER_VERSION = "0.10.11"


HTTP_PROBE_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


def probe_http_metadata(host, port, port_data, requests_module=None, scanner_version=SCANNER_VERSION):
    """Make one bounded HEAD request to the service root; never follow redirects."""
    requests_module = requests_module or requests
    service = str((port_data or {}).get("name") or "").lower()
    tunnel = str((port_data or {}).get("tunnel") or "").lower()
    if port not in HTTP_PROBE_PORTS and not any(token in service for token in ("http", "https")):
        return {"status": "skipped", "reason": "not_recognized_as_http"}
    is_https = tunnel in ("ssl", "tls") or service in ("https", "https-alt") or port in (443, 8443)
    scheme = "https" if is_https else "http"
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"{scheme}://{url_host}:{port}/"
    try:
        response = requests_module.head(
            url, timeout=(3, 5), allow_redirects=False, verify=True,
            headers={"User-Agent": f"ReconForge/{scanner_version} (authorized security assessment)"},
        )
    except requests.exceptions.SSLError:
        return {"status": "probe_error", "error": "tls_validation_failed",
                "limitations": ["TLS certificate validation failed; no insecure retry was attempted."]}
    except requests.exceptions.Timeout:
        return {"status": "probe_error", "error": "request_timeout"}
    except requests.exceptions.RequestException:
        return {"status": "probe_error", "error": "http_request_failed"}

    try:
        set_cookie_headers = []
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            set_cookie_headers = raw_headers.getlist("Set-Cookie")
        elif response.headers.get("Set-Cookie"):
            set_cookie_headers = [response.headers.get("Set-Cookie")]
        from .assessment import analyze_http_security
        analysis = analyze_http_security(response.headers, set_cookie_headers, is_https=is_https)
        return {
            "status": "response_received", "scheme": scheme, "status_code": response.status_code,
            "redirect_location_present": bool(response.headers.get("Location")),
            "security_analysis": analysis,
        }
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


WEB_BODY_LIMIT = 262144


WEB_TEXT_LIMIT = 65536


def bounded_same_origin_get(url, limit, requests_module=None, scanner_version=SCANNER_VERSION):
    """Fetch one fixed same-origin path, without redirects, retaining at most limit bytes."""
    requests_module = requests_module or requests
    try:
        response = requests_module.get(
            url, timeout=(3, 5), allow_redirects=False, verify=True, stream=True,
            headers={"User-Agent": f"ReconForge/{scanner_version} (authorized security assessment)"},
        )
    except requests.exceptions.SSLError:
        return None, "tls_validation_failed"
    except requests.exceptions.Timeout:
        return None, "request_timeout"
    except requests.exceptions.RequestException:
        return None, "http_request_failed"
    try:
        if response.status_code < 200 or response.status_code >= 300:
            return None, f"http_status_{response.status_code}"
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = limit - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
            if total >= limit:
                break
        raw = b"".join(chunks)
        encoding = getattr(response, "encoding", None) or "utf-8"
        return raw.decode(encoding, errors="replace"), None
    finally:
        response.close()


def probe_web_intelligence(host, port, port_data, bounded_get=None, scanner_version=SCANNER_VERSION):
    """Fetch only /, /robots.txt and /sitemap.xml on the scanned host; no crawling."""
    bounded_get = bounded_get or bounded_same_origin_get
    service = str((port_data or {}).get("name") or "").lower()
    tunnel = str((port_data or {}).get("tunnel") or "").lower()
    if port not in HTTP_PROBE_PORTS and not any(token in service for token in ("http", "https")):
        return {"status": "skipped", "reason": "not_recognized_as_http"}
    is_https = tunnel in ("ssl", "tls") or service in ("https", "https-alt") or port in (443, 8443)
    scheme = "https" if is_https else "http"
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    base = f"{scheme}://{url_host}:{port}"
    html, root_error = bounded_get(base + "/", WEB_BODY_LIMIT)
    if html is None:
        return {"status": "probe_error", "error": root_error,
                "limitations": ["The root document could not be retrieved; no alternate path or redirect was followed."]}

    robots, robots_error = bounded_get(base + "/robots.txt", WEB_TEXT_LIMIT)
    sitemap, sitemap_error = bounded_get(base + "/sitemap.xml", WEB_TEXT_LIMIT)
    from .assessment import analyze_web_content
    analysis = analyze_web_content(html, robots, sitemap)
    return {
        "status": "response_received",
        "scheme": scheme,
        "root_document_bytes_limit": WEB_BODY_LIMIT,
        "robots_status": "fetched" if robots is not None else robots_error,
        "sitemap_status": "fetched" if sitemap is not None else sitemap_error,
        "web_analysis": analysis,
    }


