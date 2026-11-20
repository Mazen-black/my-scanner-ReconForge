#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
بورت سكانر محسّن: nmap -sV + CVEs من NVD + بحث Exploit-DB محلي (searchsploit)

التحسينات عن النسخة القديمة:
1. بناء CPE دقيق من مخرجات nmap نفسها (حقل cpe / product / version)
   بدل الخريطة الثابتة اللي كانت تفترض ftp=vsftpd و ssh=OpenSSH إلخ.
2. دعم NVD API Key (من --nvd-api-key أو متغير البيئة NVD_API_KEY)
   + Rate limiting محترم للحدود (5 طلبات/30 ثانية بدون Key، 50 طلب/30 ثانية بـ Key)
   + إعادة محاولة مع Backoff على 429 و 5xx وأخطاء الشبكة.
3. ترتيب نتائج الـ CVEs تنازلياً حسب CVSS baseScore بدل أول 5 نتايج عشوائية.
4. timeout على كل طلبات requests (بدون timeout كانت ممكن تتعلّق للأبد).
5. exit() اتبدلت بـ sys.exit(1) وكل الكود اتحط جوه main().
6. بحث محلي في Exploit-DB عن طريق searchsploit (بدون أي Rate limits).
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from datetime import datetime, timezone

import requests
import nmap

from asset_context import assess_asset_context
from remediation import build_remediation
from report import write_html_report
from risk import assess_cves, assess_service_risk

from assessment import (
    assess_cve_applicability,
    apply_contextual_cve_constraints,
    build_report_entry,
    classify_exploit,
    cpe22_to_cpe23,
    build_technology_fingerprint,
    assess_network_exposure,
    build_exploit_intelligence,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_WINDOW = 30.0        # نافذة الـ Rate limit: 30 ثانية
NVD_LIMIT_NO_KEY = 5          # بدون API Key: 5 طلبات / 30 ثانية
NVD_LIMIT_WITH_KEY = 50       # مع API Key: 50 طلب / 30 ثانية
HTTP_TIMEOUT = (10, 30)       # (connect, read) بالثواني
MAX_RETRIES = 4
BACKOFF_BASE = 5.0
MAX_CVE_RESULTS = 10
MAX_EXPLOIT_RESULTS = 10
MAX_CPE_QUERIES_PER_PORT = 5
REPORT_SCHEMA_VERSION = "1.12"
SCANNER_VERSION = "0.10.3"

# خريطة أسماء nmap "product" لأسماء CPE الرسمية في NVD
# (nmap بيقول مثلاً "Apache httpd" لكن اسم الـ CPE الرسمي apache:http_server)
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

# آخر احتياط: لو مفيش product خالص من nmap نرجّع للخريطة القديمة (بالخدمة بس - أقل دقة)
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
    """يبني CPE 2.3 كامل من النوع + vendor:product + النسخة"""
    vendor, product = vendor_product.split(":", 1)
    return f"cpe:2.3:{ptype}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


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
            if not isinstance(score, (int, float)):
                score = None
            return score, severity, key
    return None, "", ""


def check_cve_nvd(session, port_data, api_key, limiter, results_per_page):
    """يبني CPE candidates من بيانات البورت ويستعلم NVD ويرجّع (cves, cpes_tested)"""
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
            parts = cpe23.split(":")
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
        data = nvd_fetch(session, params, api_key, limiter)
        if not data:
            continue
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id or cve_id in found:
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
            }

    # لو مفيش نتايج من الـ CPE: محاولة أخيرة بـ keywordSearch (أقل دقة)
    if not found:
        keyword = f"{product or service} {versions[0]}".strip()
        if keyword:
            print(f"    مفيش نتايج من الـ CPE - أجرب keywordSearch: {keyword}")
            tried.append(f"keywordSearch:{keyword}")
            data = nvd_fetch(
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
            item["applicability"] = apply_contextual_cve_constraints(
                item.get("id"), assessments[0], item.get("summary", "")
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


EXPLOITDB_EXPLOITS_ROOT = "/usr/share/exploitdb/exploits"
EXPLOIT_HEADER_FIELDS = {
    "target architecture": "target_architecture",
    "target arch": "target_architecture",
    "architecture": "architecture",
    "arch": "architecture",
    "payload architecture": "payload_architecture",
    "required privileges": "required_privileges",
    "privileges required": "required_privileges",
    "authentication required": "authentication_required",
    "authentication": "authentication",
    "user interaction": "user_interaction",
    "requirements": "requirements",
    "prerequisites": "prerequisites",
}


def extract_exploit_metadata(path, exploit_root=EXPLOITDB_EXPLOITS_ROOT):
    """Read only allowlisted key/value comments from a local Exploit-DB file header.

    No exploit source is imported, evaluated, or executed. Paths outside the
    configured Exploit-DB exploits directory are ignored.
    """
    if not path or not exploit_root:
        return {}
    try:
        root = os.path.realpath(exploit_root)
        candidate = os.path.realpath(path)
        if os.path.commonpath([root, candidate]) != root or candidate == root:
            return {}
        if not os.path.isfile(candidate):
            return {}
        metadata = {}
        with open(candidate, "r", encoding="utf-8", errors="replace") as source:
            for line_number, line in enumerate(source, 1):
                if line_number > 80:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                # Accept only leading comment metadata, never parse source statements.
                if stripped.startswith("#"):
                    content = stripped.lstrip("#").strip()
                elif stripped.startswith("//"):
                    content = stripped[2:].strip()
                elif stripped.startswith("*"):
                    content = stripped[1:].strip()
                else:
                    if stripped.startswith("/*") or stripped.startswith("##"):
                        continue
                    break
                match = re.match(r"^([A-Za-z][A-Za-z _-]{1,40})\s*:\s*(.{1,240})$", content)
                if not match:
                    continue
                field = re.sub(r"\s+", " ", match.group(1).strip().lower())
                key = EXPLOIT_HEADER_FIELDS.get(field)
                value = match.group(2).strip()
                if key and value and key not in metadata:
                    metadata[key] = {
                        "value": value,
                        "source": "local_exploitdb_file_header",
                        "line": line_number,
                    }
        return metadata
    except (OSError, ValueError):
        return {}


def searchsploit_lookup(product, version, limit=MAX_EXPLOIT_RESULTS):
    """بحث محلي في Exploit-DB عن طريق searchsploit (بدون Rate limits)"""
    if shutil.which("searchsploit") is None:
        print("    searchsploit مش متسطّب - بيتخطى بحث Exploit-DB (apt install exploitdb)")
        return []
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return []
    # أول بحث محدد (product + version) وبعدين بحث عام (product بس) مع دمج النتايج
    searches = [[product] + ([version] if version else []), [product]]
    seen = set()
    out = []
    for terms in searches:
        try:
            proc = subprocess.run(
                ["searchsploit", "--json", *terms],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"    خطأ في searchsploit: {e}")
            continue
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            continue
        rows = (data.get("RESULTS_EXPLOIT") or [])[:limit]
        for row in rows:
            edb = str(row.get("EDB-ID") or "").strip()
            title = str(row.get("Title") or "").strip()
            key = edb or title
            if not key or key in seen:
                continue
            seen.add(key)
            relevance = classify_exploit(row, product, version)
            # Discard titles with no meaningful product-token match instead of filling the report with noise.
            if relevance["relevance"] == "weak_or_unrelated":
                continue
            out.append({
                "id": edb,
                "title": title,
                "type": row.get("Type") or "",
                "platform": row.get("Platform") or "",
                "path": row.get("Path") or "",
                "local_metadata": extract_exploit_metadata(row.get("Path") or ""),
                "assessment": relevance,
            })
            if len(out) >= limit:
                return out
    return out


def validate_target(value):
    """Accept one IP address, CIDR network, or DNS hostname; reject option/shell-like input."""
    target = (value or "").strip()
    if not target or target != value or any(ch.isspace() or ord(ch) < 32 for ch in target):
        raise ValueError("Target must be a single IP, CIDR network, or hostname without whitespace.")
    if target.startswith("-") or "://" in target or any(ch in target for ch in ";|&`$<>\\\\"):
        raise ValueError("Target contains unsupported characters.")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    hostname = target[:-1] if target.endswith(".") else target
    if len(hostname) > 253 or not hostname:
        raise ValueError("Hostname length is invalid.")
    labels = hostname.split(".")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not all(label_re.fullmatch(label) for label in labels):
        raise ValueError("Target is not a valid IP, CIDR network, or DNS hostname.")
    return target


def validate_ports(value):
    """Validate a comma-separated list of TCP port numbers/ranges."""
    ports = (value or "").strip()
    if not ports or ports != value:
        raise ValueError("Ports cannot be empty or contain surrounding whitespace.")
    for item in ports.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", item):
            raise ValueError(f"Invalid port expression: {item!r}")
        parts = [int(part) for part in item.split("-")]
        if any(port < 1 or port > 65535 for port in parts):
            raise ValueError(f"Port numbers must be between 1 and 65535: {item!r}")
        if len(parts) == 2 and parts[0] > parts[1]:
            raise ValueError(f"Port range start exceeds end: {item!r}")
    return ports


def normalize_nmap_args(value):
    """Parse and safely re-quote user-supplied Nmap arguments for python-nmap's shell command."""
    try:
        tokens = shlex.split(value or "")
    except ValueError as exc:
        raise ValueError(f"Invalid --nmap-args quoting: {exc}") from exc
    if not tokens:
        raise ValueError("--nmap-args cannot be empty.")
    if any(any(ord(ch) < 32 for ch in token) for token in tokens):
        raise ValueError("--nmap-args cannot contain control characters.")
    return shlex.join(tokens)


def build_host_os_fingerprint(os_matches, requested=False, minimum_accuracy=90):
    """Preserve raw Nmap OS evidence while only accepting high-confidence family labels."""
    if not isinstance(os_matches, (list, tuple)) or not os_matches:
        return {
            "status": "no_match" if requested else "not_requested",
            "platform_family": None,
            "nmap_name": None,
            "accuracy": None,
            "minimum_accuracy": minimum_accuracy,
            "source": "Nmap OS detection",
        }
    match = os_matches[0] if isinstance(os_matches[0], dict) else {}
    try:
        accuracy = int(match.get("accuracy"))
    except (TypeError, ValueError):
        accuracy = None
    platform = infer_target_platform(os_matches, minimum_accuracy=minimum_accuracy)
    return {
        "status": "accepted_high_confidence" if platform else "unconfirmed_low_confidence_or_unknown_family",
        "platform_family": platform,
        "nmap_name": str(match.get("name") or "")[:200] or None,
        "accuracy": accuracy,
        "minimum_accuracy": minimum_accuracy,
        "source": "Nmap OS detection",
    }


def infer_target_platform(os_matches, minimum_accuracy=90):
    """Infer a broad OS family only from a high-confidence Nmap OS match."""
    if not isinstance(os_matches, (list, tuple)) or not os_matches:
        return None
    match = os_matches[0] if isinstance(os_matches[0], dict) else {}
    try:
        accuracy = int(match.get("accuracy"))
    except (TypeError, ValueError):
        return None
    if accuracy < minimum_accuracy:
        return None
    os_name = str(match.get("name") or "").lower()
    if any(token in os_name for token in ("windows", "microsoft")):
        return "windows"
    if "linux" in os_name:
        return "linux"
    if any(token in os_name for token in ("freebsd", "openbsd", "netbsd", "solaris", "unix")):
        return "unix"
    if any(token in os_name for token in ("mac os", "macos", "darwin")):
        return "macos"
    return None


def scanned_hosts(scanner):
    """Return Nmap's resolved host list (which may contain IPs instead of the input hostname)."""
    hosts = list(scanner.all_hosts())
    if not hosts:
        raise RuntimeError("Nmap did not return any hosts. Check target reachability and scan options.")
    return hosts


def write_json_report(filename, results):
    """Write reports atomically so an interrupted scan cannot leave a truncated JSON file."""
    output_path = os.path.abspath(filename)
    output_dir = os.path.dirname(output_path) or os.curdir
    os.makedirs(output_dir, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output_dir,
            prefix=".reconforge-", suffix=".tmp", delete=False
        ) as handle:
            temp_path = handle.name
            json.dump(results, handle, indent=4, ensure_ascii=False)
            handle.write("\
")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, output_path)
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise




HTTP_PROBE_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


def probe_http_metadata(host, port, port_data):
    """Make one bounded HEAD request to the service root; never follow redirects."""
    service = str((port_data or {}).get("name") or "").lower()
    tunnel = str((port_data or {}).get("tunnel") or "").lower()
    if port not in HTTP_PROBE_PORTS and not any(token in service for token in ("http", "https")):
        return {"status": "skipped", "reason": "not_recognized_as_http"}
    is_https = tunnel in ("ssl", "tls") or service in ("https", "https-alt") or port in (443, 8443)
    scheme = "https" if is_https else "http"
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"{scheme}://{url_host}:{port}/"
    try:
        response = requests.head(
            url, timeout=(3, 5), allow_redirects=False, verify=True,
            headers={"User-Agent": f"ReconForge/{SCANNER_VERSION} (authorized security assessment)"},
        )
    except requests.exceptions.SSLError:
        return {"status": "probe_error", "error": "tls_validation_failed",
                "limitations": ["TLS certificate validation failed; no insecure retry was attempted."]}
    except requests.exceptions.Timeout:
        return {"status": "probe_error", "error": "request_timeout"}
    except requests.exceptions.RequestException:
        return {"status": "probe_error", "error": "http_request_failed"}

    set_cookie_headers = []
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    elif response.headers.get("Set-Cookie"):
        set_cookie_headers = [response.headers.get("Set-Cookie")]
    from assessment import analyze_http_security, analyze_web_content
    analysis = analyze_http_security(response.headers, set_cookie_headers, is_https=is_https)
    return {
        "status": "response_received", "scheme": scheme, "status_code": response.status_code,
        "redirect_location_present": bool(response.headers.get("Location")),
        "security_analysis": analysis,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="بورت سكانر محسّن: nmap + CVEs من NVD + بحث Exploit-DB محلي")
    parser.add_argument("--target", required=True, help="الـ IP أو الدومين المستهدف")
    parser.add_argument("--ports", default="1-1000", help="رينج البورتات (مثال: 1-1000 أو 22,80,443)")
    parser.add_argument("--nvd-api-key", default=None,
                        help="NVD API Key (أو متغير البيئة NVD_API_KEY) - بيرفع الحد لـ 50 طلب/30 ثانية")
    parser.add_argument("--nmap-args", default="-sV", help="أرجومنتس لـ nmap (الافتراضي: -sV)")
    parser.add_argument("--os-detection", action="store_true",
                        help="فعّل Nmap OS detection (-O)؛ قد يحتاج صلاحيات root/raw sockets")
    parser.add_argument("--results-per-page", type=int, default=10,
                        help="عدد نتائج NVD لكل استعلام (من 1 إلى 2000)")
    parser.add_argument("--http-probe", action="store_true",
                        help="حلل HTTP headers وخصائص cookies بطلب HEAD واحد فقط لكل خدمة ويب")
    parser.add_argument("--web-intel", action="store_true",
                        help="حلل HTML وCMS/JS hints وrobots.txt وsitemap.xml بطلبات محدودة لنفس الـhost")
    parser.add_argument("--no-exploitdb", action="store_true",
                        help="عطّل بحث searchsploit المحلي")
    parser.add_argument("--no-nvd", action="store_true",
                        help="تخطّى استعلامات NVD (مفيد للاختبار دون اتصال أو عند تعطل الخدمة)")
    parser.add_argument("--html-output", default=None,
                        help="اسم ملف تقرير HTML مستقل (اختياري)")
    parser.add_argument("--asset-criticality", choices=("unknown", "low", "medium", "high", "critical"), default="unknown",
                        help="أهمية الأصل حسب تقييمك؛ لا يتم استنتاجها تلقائياً")
    parser.add_argument("--exposure", choices=("unknown", "internal", "internet"), default="unknown",
                        help="مدى تعرض الأصل حسب معلومات مؤكدة منك؛ لا يُستنتج من المنافذ")
    parser.add_argument("--output", "-o", default=None,
                        help="اسم ملف النتائج JSON (اختياري)")
    args = parser.parse_args(argv)
    try:
        args.target = validate_target(args.target)
        args.ports = validate_ports(args.ports)
        args.nmap_args = normalize_nmap_args(args.nmap_args)
        if args.os_detection:
            nmap_tokens = shlex.split(args.nmap_args)
            if "-O" not in nmap_tokens and "--osscan-guess" not in nmap_tokens:
                nmap_tokens.append("-O")
            args.nmap_args = shlex.join(nmap_tokens)
        if not 1 <= args.results_per_page <= 2000:
            raise ValueError("--results-per-page must be between 1 and 2000.")
        if args.output is not None and not args.output.strip():
            raise ValueError("--output cannot be empty.")
        if args.html_output is not None and not args.html_output.strip():
            raise ValueError("--html-output cannot be empty.")
    except ValueError as exc:
        parser.error(str(exc))
    return args


WEB_BODY_LIMIT = 262144
WEB_TEXT_LIMIT = 65536


def _bounded_same_origin_get(url, limit):
    """Fetch one fixed same-origin path, without redirects, retaining at most limit bytes."""
    try:
        response = requests.get(
            url, timeout=(3, 5), allow_redirects=False, verify=True, stream=True,
            headers={"User-Agent": f"ReconForge/{SCANNER_VERSION} (authorized security assessment)"},
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


def probe_web_intelligence(host, port, port_data):
    """Fetch only /, /robots.txt and /sitemap.xml on the scanned host; no crawling."""
    service = str((port_data or {}).get("name") or "").lower()
    tunnel = str((port_data or {}).get("tunnel") or "").lower()
    if port not in HTTP_PROBE_PORTS and not any(token in service for token in ("http", "https")):
        return {"status": "skipped", "reason": "not_recognized_as_http"}
    is_https = tunnel in ("ssl", "tls") or service in ("https", "https-alt") or port in (443, 8443)
    scheme = "https" if is_https else "http"
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    base = f"{scheme}://{url_host}:{port}"
    html, root_error = _bounded_same_origin_get(base + "/", WEB_BODY_LIMIT)
    if html is None:
        return {"status": "probe_error", "error": root_error,
                "limitations": ["The root document could not be retrieved; no alternate path or redirect was followed."]}

    robots, robots_error = _bounded_same_origin_get(base + "/robots.txt", WEB_TEXT_LIMIT)
    sitemap, sitemap_error = _bounded_same_origin_get(base + "/sitemap.xml", WEB_TEXT_LIMIT)
    from assessment import analyze_web_content
    analysis = analyze_web_content(html, robots, sitemap)
    return {
        "status": "response_received",
        "scheme": scheme,
        "root_document_bytes_limit": WEB_BODY_LIMIT,
        "robots_status": "fetched" if robots is not None else robots_error,
        "sitemap_status": "fetched" if sitemap is not None else sitemap_error,
        "web_analysis": analysis,
    }



def main():
    args = parse_args()
    api_key = (args.nvd_api_key or os.environ.get("NVD_API_KEY") or "").strip() or None
    if api_key:
        print("NVD API Key موجود - الحد: 50 طلب / 30 ثانية")
    else:
        print("مفيش NVD API Key - الحد: 5 طلبات / 30 ثانية (حط NVD_API_KEY في البيئة لو عايز أسرع)")
    limiter = NVDRateLimiter(NVD_LIMIT_WITH_KEY if api_key else NVD_LIMIT_NO_KEY, NVD_RATE_WINDOW)
    session = requests.Session()

    target = args.target
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    print(f"بدء فحص: {target} على البورتات: {args.ports} (nmap args: {args.nmap_args})")

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, args.ports, arguments=args.nmap_args)
    except Exception as e:
        print(f"حصل خطأ أثناء الفحص: {e}")
        print("تأكد إن التارجت متصل وإنك شغال بصلاحيات sudo")
        sys.exit(1)

    try:
        hosts = scanned_hosts(scanner)
    except RuntimeError as e:
        print(str(e))
        sys.exit(1)

    results = []
    for host in hosts:
        try:
            ports = scanner[host].all_tcp()
        except (AttributeError, KeyError):
            ports = list(scanner[host].get("tcp", {}).keys())
        for port in ports:
            port_data = scanner[host]["tcp"][port]
            state = port_data.get("state")
            if state != "open":
                continue
            service = port_data.get("name") or ""
            product = (port_data.get("product") or "").strip()
            version = (port_data.get("version") or "").strip()
            print(f"Port {port}: مفتوح - الخدمة: {service} - المنتج: {product or '؟'} - النسخة: {version or '؟'}")

            cves = []
            cpes_tried = []
            if args.no_nvd:
                print("  تم تخطي NVD بناءً على --no-nvd")
            elif version:
                print(f"  بدور على CVEs لـ {product or service} {version}...")
                cves, cpes_tried = check_cve_nvd(
                    session, port_data, api_key, limiter, args.results_per_page)
                if cves:
                    print(f"  لقيت {len(cves)} CVE - أعلى 5 حسب CVSS:")
                    for c in cves[:5]:
                        score_txt = f"{c['cvss']}" if c["cvss"] is not None else "؟"
                        print(f"    {c['id']} - CVSS {score_txt} ({c['severity'] or 'غير محدد'})")
                else:
                    print("  مفيش CVEs واضحة اتلقت")
            else:
                print("  مفيش نسخة معروفة - هعدي NVD وأدور في Exploit-DB بس")

            exploits = []
            if not args.no_exploitdb:
                print("  بدور على Exploits محلياً في Exploit-DB (searchsploit)...")
                # Generic service labels are not reliable product fingerprints.
                exploits = searchsploit_lookup(product, version) if product else []
                if not product:
                    print("  مفيش product fingerprint موثوق - تم تخطي Searchsploit لتجنب نتائج غير مرتبطة")
                elif exploits:
                    print(f"  لقيت {len(exploits)} exploit محتمل (أول 5):")
                    for e in exploits[:5]:
                        print(f"    EDB-{e['id']} - {e['title']}")
                else:
                    print("  مفيش exploits اتلقت محلياً")

            # Finalize NVD applicability before correlating exploit references with CVEs.
            cves = assess_cves(cves)

            # Use only Nmap OS-match evidence when present; never infer OS from a service banner.
            os_matches = scanner[host].get("osmatch", []) if hasattr(scanner[host], "get") else []
            os_fingerprint = build_host_os_fingerprint(
                os_matches,
                requested=bool(getattr(args, "os_detection", False) or "-O" in shlex.split(args.nmap_args)),
            )
            target_platform = os_fingerprint["platform_family"]
            exploit_intelligence = build_exploit_intelligence(
                exploits, cves, target_platform=target_platform
            )
            if exploit_intelligence:
                print(f"  Exploit intelligence: {len(exploit_intelligence)} مرجع مع إرشادات تحقق آمنة")

            http_assessment = {"status": "not_requested"}
            if args.http_probe:
                http_assessment = probe_http_metadata(host, port, port_data)
                print(f"  HTTP assessment: {http_assessment.get('status')}")
            web_intelligence = {"status": "not_requested"}
            if args.web_intel:
                web_intelligence = probe_web_intelligence(host, port, port_data)
                print(f"  Web intelligence: {web_intelligence.get('status')}")

            # Keep technical risk, operator-supplied asset context, and remediation separate.
            entry = build_report_entry(
                host=host,
                port=port,
                state=state,
                service=service,
                product=product,
                version=version,
                cpes_tested=cpes_tried,
                cves=cves,
                exploits=exploits,
                fingerprint=build_technology_fingerprint(port_data),
                http_assessment=http_assessment,
                web_intelligence=web_intelligence,
                network_exposure=assess_network_exposure(port, service, product),
                exploit_intelligence=exploit_intelligence,
                host_os_fingerprint=os_fingerprint,
            )
            technical_risk = assess_service_risk(cves, exploits)
            asset_context = assess_asset_context(
                technical_risk, args.asset_criticality, args.exposure
            )
            entry["risk_assessment"] = {
                **technical_risk,
                "asset_context": asset_context,
            }
            entry["remediation_guidance"] = build_remediation(
                entry["service"], cves, entry["risk_assessment"]
            )
            results.append(entry)
            if technical_risk["score"] is None:
                print("  Risk priority: Unscored (no applicable CVSS evidence)")
            else:
                print(f"  Risk priority: {technical_risk['level']} ({technical_risk['score']:.1f}/100)")
            contextual_score = asset_context["contextual_priority_score"]
            if contextual_score is None:
                print("  Contextual priority: Unscored")
            else:
                print(f"  Contextual priority: {asset_context['contextual_priority']} ({contextual_score:.1f}/100)")

    completed_at = datetime.now(timezone.utc)
    scan_metadata = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scanner": {"name": "ReconForge", "version": SCANNER_VERSION},
        "requested_target": target,
        "resolved_hosts": hosts,
        "ports": args.ports,
        "nmap_arguments": args.nmap_args,
        "os_detection_requested": bool(getattr(args, "os_detection", False) or "-O" in shlex.split(args.nmap_args)),
        "started_at_utc": started_at.isoformat(timespec="seconds"),
        "completed_at_utc": completed_at.isoformat(timespec="seconds"),
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        "open_services": len(results),
    }
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_UTC")
    safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("._") or "target"
    filename = args.output or f"scan_{safe_target}_{timestamp}.json"
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": scan_metadata,
        "findings": results,
        "summary": {
            "hosts_scanned": len(hosts),
            "open_services": len(results),
            "cve_candidates": sum(len(item["cve_assessment"]) for item in results),
            "exploit_references": sum(len(item["searchsploit_assessment"]) for item in results),
            "exploit_intelligence_references": sum(len(item.get("exploit_intelligence") or []) for item in results),
            "network_exposure_observations": sum(len(item.get("network_exposure") or []) for item in results),
            "risk_scored_services": sum(item.get("risk_assessment", {}).get("score") is not None for item in results),
            "remediation_guidance_services": sum(bool(item.get("remediation_guidance")) for item in results),
        },
    }
    try:
        write_json_report(filename, report)
    except OSError as e:
        print(f"تعذر حفظ التقرير: {e}")
        sys.exit(1)
    print(f"تم حفظ النتائج في {filename}")
    if args.html_output:
        try:
            html_path = write_html_report(results, args.html_output, target=target)
        except OSError as exc:
            print(f"تعذر حفظ تقرير HTML: {exc}")
            sys.exit(1)
        print(f"تم حفظ تقرير HTML في {html_path}")


if __name__ == "__main__":
    main()