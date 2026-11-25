"""NVD API access, CPE query construction, and CVE candidate assessment."""

import math
import re
import time
from collections import deque

import requests

from .assessment import (
    apply_contextual_cve_constraints,
    assess_cve_applicability,
    cpe22_to_cpe23,
)
from .cpe_assessment import _cpe23_fields


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


NVD_RATE_WINDOW = 30.0        # نافذة الـ Rate limit: 30 ثانية


NVD_LIMIT_NO_KEY = 5          # بدون API Key: 5 طلبات / 30 ثانية


NVD_LIMIT_WITH_KEY = 50       # مع API Key: 50 طلب / 30 ثانية


HTTP_TIMEOUT = (10, 30)       # (connect, read) بالثواني


MAX_RETRIES = 4


BACKOFF_BASE = 5.0


MAX_CVE_RESULTS = 10


MAX_CPE_QUERIES_PER_PORT = 5


PRODUCT_CPE_MAP = {
    "openssh": "openbsd:openssh",
    "dropbear sshd": "matt_johnston:dropbear_ssh",
    "vsftpd": "vsftpd_project:vsftpd",
    "proftpd": "proftpd_project:proftpd",
    "pure-ftpd": "pureftpd:pure-ftpd",
    "filezilla ftpd": "filezilla-project:filezilla_server",
    "microsoft ftp service": "microsoft:ftp_service",
    "nginx": "f5:nginx",
    "apache httpd": "apache:http_server",
    "lighttpd": "lighttpd:lighttpd",
    "caddy": "caddyserver:caddy",
    "microsoft iis httpd": "microsoft:iis",
    "apache tomcat": "apache:tomcat",
    "jetty": "eclipse:jetty",
    "gunicorn": "gunicorn:gunicorn",
    "postfix smtpd": "postfix:postfix",
    "postfix": "postfix:postfix",
    "exim": "exim:exim",
    "sendmail": "sendmail:sendmail",
    "samba smbd": "samba:samba",
    "bind": "isc:bind",
    "dnsmasq": "dnsmasq:dnsmasq",
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql db": "postgresql:postgresql",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "memcache": "danga:memcached",
    "elasticsearch": "elastic:elasticsearch",
    "docker": "docker:docker",
    "openvpn": "openvpn:openvpn",
    "kibana": "elastic:kibana",
    "grafana": "grafana:grafana",
    "jenkins": "jenkins:jenkins",
    "gitlab": "gitlab:gitlab",
    "wordpress": "wordpress:wordpress",
    "phpmyadmin": "phpmyadmin:phpmyadmin",
}


SERVICE_FALLBACK_MAP = {
    "ftp": "vsftpd_project:vsftpd",
    "ssh": "openbsd:openssh",
    "http": "apache:http_server",
    "https": "apache:http_server",
    "domain": "isc:bind",
    "smtp": "postfix:postfix",
    "netbios-ssn": "samba:samba",
    "mysql": "oracle:mysql",
    "ms-sql-s": "microsoft:sql_server",
    "redis": "redis:redis",
    "postgres": "postgresql:postgresql",
}


def _cpe_slug(text):
    """تطبيع اسم لمكوّن CPE: حروف صغيرة والمسافات والمحارف الغريبة تبقى _"""
    slug = text.strip().lower()
    slug = re.sub(r"[^a-z0-9_.\-]+", "_", slug)
    slug = re.sub(r"_{2,}", "_", slug).strip("_")
    return slug or "*"


def _vendor_product(product):
    """يحاول يطلّع vendor:product من اسم nmap product"""
    mapped = PRODUCT_CPE_MAP.get(product.strip().lower())
    if mapped:
        return mapped
    words = [w for w in re.split(r"\s+", product.strip()) if w]
    if len(words) >= 2:
        # مثال: "Apache Tomcat" → apache:tomcat
        return f"{_cpe_slug(words[0])}:{_cpe_slug(' '.join(words[1:]))}"
    if words:
        slug = _cpe_slug(words[0])
        return f"{slug}:{slug}"
    return None


def _cpe22_to_cpe23(uri):
    """Compatibility wrapper; conversion and field-count validation live in assessment.py."""
    return cpe22_to_cpe23(uri)


def _cpe23(ptype, vendor_product, version):
    """Build a CPE 2.3 binding, escaping delimiters inside individual attributes."""
    vendor, product = vendor_product.split(":", 1)

    def escape_component(value):
        return str(value).replace("\\", "\\\\").replace(":", "\\:")

    return (
        f"cpe:2.3:{ptype}:{escape_component(vendor)}:{escape_component(product)}:"
        f"{escape_component(version)}:*:*:*:*:*:*:*"
    )


def _version_candidates(version):
    """نسخ احتياطية للنسخة: النسخة كاملة + أول رقمين (مثال: 7.9p1 → 7.9p1 و 7.9)"""
    v = (version or "").strip()
    if not v or v == "*":
        return []
    cands = []
    tokens = v.split()
    if len(tokens) == 1:
        cands.append(v)
    else:
        # nmap أحياناً بيرجّع نسخة فيها لاحقة توزيعة زي "5.9p1 Debian 5ubuntu1.10"
        # لا تصلح كمكوّن CPE - فباخد أول توكين بس
        cands.append(tokens[0])
    base = cands[0]
    m = re.match(r"^(\d+(?:\.\d+)*)", base)
    if m:
        parts = m.group(1).split(".")
        if len(parts) >= 2:
            short = ".".join(parts[:2])
            if short not in cands:
                cands.append(short)
    return cands


class NVDRateLimiter:
    """يحافظ على حد NVD: X طلبات لكل نافذة زمنية (سلو رولينج)"""

    def __init__(self, max_calls, window):
        self.max_calls = max_calls
        self.window = window
        self.calls = deque()

    def wait(self):
        now = time.monotonic()
        while self.calls and now - self.calls[0] > self.window:
            self.calls.popleft()
        if len(self.calls) >= self.max_calls:
            sleep_for = self.window - (now - self.calls[0]) + 0.5
            if sleep_for > 0:
                print(f"    Rate limit NVD - انتظار {sleep_for:.0f} ثانية")
                time.sleep(sleep_for)
        self.calls.append(time.monotonic())


def nvd_fetch(session, params, api_key, limiter):
    """طلب NVD مع timeout و rate limit و retry/backoff على 429 و 5xx وأخطاء الشبكة"""
    headers = {"apiKey": api_key} if api_key else {}
    backoff = BACKOFF_BASE
    for attempt in range(1, MAX_RETRIES + 1):
        limiter.wait()
        try:
            resp = session.get(NVD_URL, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        except (requests.Timeout, requests.ConnectionError) as e:
            print(f"    خطأ شبكة (محاولة {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "").strip()
            try:
                wait = float(retry_after) if retry_after else backoff
            except ValueError:
                wait = backoff
            print(f"    429 Too Many Requests - انتظار {wait:.0f} ثانية (محاولة {attempt}/{MAX_RETRIES})")
            time.sleep(wait)
            backoff *= 2
            continue
        if resp.status_code >= 500:
            print(f"    خطأ سيرفر NVD {resp.status_code} - إعادة المحاولة (محاولة {attempt}/{MAX_RETRIES})")
            time.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code != 200:
            print(f"    استجابة غير متوقعة {resp.status_code}: {resp.text[:120]}")
            return None
        try:
            return resp.json()
        except ValueError:
            print("    رد JSON مش صالح من NVD")
            return None
    print("    فشلت كل محاولات الاتصال بـ NVD")
    return None


def _cvss_of(cve):
    """يفكّ CVSS من الـ metrics بأولوية V31 → V30 → V2"""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            entry = arr[0]
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            severity = entry.get("baseSeverity") or data.get("baseSeverity") or ""
            if (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(score)
                or not 0 <= score <= 10
            ):
                score = None
            return score, severity, key
    return None, "", ""


def check_cve_nvd(session, port_data, api_key, limiter, results_per_page, fetcher=None):
    """يبني CPE candidates من بيانات البورت ويستعلم NVD ويرجّع (cves, cpes_tested)"""
    fetch = fetcher or nvd_fetch
    bases = []  # (ptype, vendor:product, source)
    raw_cpes = port_data.get("cpe") or []
    # python-nmap may return one CPE as a string rather than a list.
    if isinstance(raw_cpes, str):
        raw_cpes = [raw_cpes]
    elif not isinstance(raw_cpes, (list, tuple, set)):
        raw_cpes = []
    for uri in raw_cpes:
        cpe23 = _cpe22_to_cpe23(uri)
        if cpe23:
            parts = _cpe23_fields(cpe23)
            if not parts:
                continue
            # This lookup assesses a detected service/product and its service
            # version. OS/hardware CPEs are environmental evidence, not service
            # identities; comparing them to the service banner version is invalid.
            # Parse escaped delimiters as component data, never as field boundaries.
            if parts[2] != "a":
                continue
            bases.append((parts[2], f"{parts[3]}:{parts[4]}", "cpe من nmap"))
    product = (port_data.get("product") or "").strip()
    service = (port_data.get("name") or "").strip()
    vp = _vendor_product(product) if product else None
    if vp:
        bases.append(("a", vp, "من product"))
    if not bases and service:
        mapped = SERVICE_FALLBACK_MAP.get(service)
        if mapped:
            bases.append(("a", mapped, "fallback بالخدمة (أقل دقة)"))

    # إزالة التكرار مع الحفاظ على الترتيب (nmap-cpe أولاً لأنه الأدق)
    seen_bases = set()
    dedup_bases = []
    for b in bases:
        key = (b[0], b[1])
        if key not in seen_bases:
            seen_bases.add(key)
            dedup_bases.append(b)
    if not dedup_bases:
        return [], []

    versions = _version_candidates(port_data.get("version"))
    if not versions:
        print("    مفيش نسخة محددة - هستغنى عن استعلام NVD (نتايج عامة مش دقيقة)")
        return [], []

    queries = []
    for ptype, vendor_product, source in dedup_bases:
        for ver in versions:
            queries.append((_cpe23(ptype, vendor_product, ver), source))
    seen_q = set()
    unique_queries = []
    for q, source in queries:
        if q not in seen_q:
            seen_q.add(q)
            unique_queries.append((q, source))
    unique_queries = unique_queries[:MAX_CPE_QUERIES_PER_PORT]

    found = {}
    tried = []
    for cpe, source in unique_queries:
        tried.append(cpe)
        print(f"    NVD [{source}]: {cpe}")
        params = {
            "virtualMatchString": cpe,
            "resultsPerPage": results_per_page,
            "startIndex": 0,
        }
        data = fetch(session, params, api_key, limiter)
        if not data:
            continue
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            query_evidence = {"type": "cpe", "query": cpe, "source": source}
            if cve_id in found:
                if query_evidence not in found[cve_id]["query_evidence"]:
                    found[cve_id]["query_evidence"].append(query_evidence)
                continue
            score, severity, metric = _cvss_of(cve)
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = (d.get("value") or "")[:150]
                    break
            found[cve_id] = {
                "id": cve_id,
                "cvss": score,
                "severity": severity,
                "metric": metric,
                "published": (cve.get("published") or "")[:10],
                "summary": desc,
                "configurations": cve.get("configurations") or [],
                "source": "NVD CPE query",
                "query_evidence": [query_evidence],
            }

    # لو مفيش نتايج من الـ CPE: محاولة أخيرة بـ keywordSearch (أقل دقة)
    if not found:
        keyword = f"{product or service} {versions[0]}".strip()
        if keyword:
            print(f"    مفيش نتايج من الـ CPE - أجرب keywordSearch: {keyword}")
            tried.append(f"keywordSearch:{keyword}")
            data = fetch(
                session,
                {"keywordSearch": keyword, "resultsPerPage": results_per_page, "startIndex": 0},
                api_key,
                limiter,
            )
            if data:
                for item in data.get("vulnerabilities") or []:
                    cve = item.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id or cve_id in found:
                        continue
                    score, severity, metric = _cvss_of(cve)
                    found[cve_id] = {
                        "id": cve_id,
                        "cvss": score,
                        "severity": severity,
                        "metric": metric,
                        "published": (cve.get("published") or "")[:10],
                        "summary": "",
                        "configurations": cve.get("configurations") or [],
                        "source": "NVD keyword search (candidate only)",
                    }

    # Evaluate each result against the detected product/version; query hits alone are not applicability.
    for item in found.values():
        assessments = []
        for ptype, vendor_product, source in dedup_bases:
            try:
                vendor, cpe_product = vendor_product.split(":", 1)
            except ValueError:
                continue
            assessments.append(assess_cve_applicability(
                item, vendor, cpe_product, port_data.get("version") or "", ptype
            ))
        matched = next((a for a in assessments if a.get("status") == "version_match"), None)
        if matched:
            item["applicability"] = apply_contextual_cve_constraints(
                item.get("id"), matched, item.get("summary", "")
            )
        elif str(item.get("source", "")).startswith("NVD keyword search"):
            item["applicability"] = {
                "status": "candidate_unverified",
                "confidence": "low",
                "evidence": [],
                "limitations": ["This result came from keyword search, not a validated vulnerable CPE/version match.", "Check the vendor advisory and complete NVD version ranges manually."],
            }
        elif assessments:
            # A definite mismatch for one candidate identity must not hide an
            # unresolved assessment for another plausible identity. Only report
            # not_matched when every evaluated identity is a definite mismatch.
            selected = next(
                (a for a in assessments if a.get("status") == "candidate_unverified"),
                assessments[0],
            )
            item["applicability"] = apply_contextual_cve_constraints(
                item.get("id"), selected, item.get("summary", "")
            )
        else:
            item["applicability"] = {
                "status": "candidate_unverified",
                "confidence": "low",
                "evidence": [],
                "limitations": ["No product-specific vulnerable CPE evidence could be evaluated."],
            }
        # Raw NVD configuration trees are large; keep assessment evidence in the final report.
        item.pop("configurations", None)

    cves = sorted(
        found.values(),
        key=lambda c: (
            0 if (c.get("applicability") or {}).get("status") == "version_match" else 1,
            -(c["cvss"] if c["cvss"] is not None else -1.0),
            c["id"],
        ),
    )[:MAX_CVE_RESULTS]
    return cves, tried


