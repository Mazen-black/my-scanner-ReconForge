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
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

import requests
import nmap

from assessment import (
    assess_cve_applicability,
    build_report_entry,
    classify_exploit,
    cpe22_to_cpe23,
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
    for uri in port_data.get("cpe") or []:
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
            item["applicability"] = matched
        elif str(item.get("source", "")).startswith("NVD keyword search"):
            item["applicability"] = {
                "status": "candidate_unverified",
                "confidence": "low",
                "evidence": [],
                "limitations": ["This result came from keyword search, not a validated vulnerable CPE/version match.", "Check the vendor advisory and complete NVD version ranges manually."],
            }
        elif assessments:
            item["applicability"] = assessments[0]
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
                "assessment": relevance,
            })
            if len(out) >= limit:
                return out
    return out


def parse_args():
    parser = argparse.ArgumentParser(
        description="بورت سكانر محسّن: nmap + CVEs من NVD + بحث Exploit-DB محلي")
    parser.add_argument("--target", required=True, help="الـ IP أو الدومين المستهدف")
    parser.add_argument("--ports", default="1-1000", help="رينج البورتات (مثال: 1-1000)")
    parser.add_argument("--nvd-api-key", default=None,
                        help="NVD API Key (أو متغير البيئة NVD_API_KEY) - بيرفع الحد لـ 50 طلب/30 ثانية")
    parser.add_argument("--nmap-args", default="-sV", help="أرجومنتس لـ nmap (الافتراضي: -sV)")
    parser.add_argument("--results-per-page", type=int, default=10,
                        help="عدد نتائج NVD لكل استعلام (الافتراضي: 10)")
    parser.add_argument("--no-exploitdb", action="store_true",
                        help="عطّل بحث searchsploit المحلي")
    parser.add_argument("--output", "-o", default=None,
                        help="اسم ملف النتائج JSON (اختياري)")
    return parser.parse_args()


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
    print(f"بدء فحص: {target} على البورتات: {args.ports} (nmap args: {args.nmap_args})")

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, args.ports, arguments=args.nmap_args)
    except Exception as e:
        print(f"حصل خطأ أثناء الفحص: {e}")
        print("تأكد إن التارجت متصل وإنك شغال بصلاحيات sudo")
        sys.exit(1)

    if target not in scanner.all_hosts():
        print("التارجت مش بيرد أو مش موجود - تأكد من الـ IP والاتصال")
        sys.exit(1)

    results = []
    for host in scanner.all_hosts():
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
            if version:
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
                exploits = searchsploit_lookup(product or service, version)
                if exploits:
                    print(f"  لقيت {len(exploits)} exploit محتمل (أول 5):")
                    for e in exploits[:5]:
                        print(f"    EDB-{e['id']} - {e['title']}")
                else:
                    print("  مفيش exploits اتلقت محلياً")

            results.append(build_report_entry(
                host=host,
                port=port,
                state=state,
                service=service,
                product=product,
                version=version,
                cpes_tested=cpes_tried,
                cves=cves,
                exploits=exploits,
            ))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = args.output or f"scan_{target}_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"تم حفظ النتائج في {filename}")


if __name__ == "__main__":
    main()