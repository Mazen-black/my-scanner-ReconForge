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
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import requests
import nmap

from .asset_context import assess_asset_context
from .remediation import build_remediation
from .report import write_html_report
from .summary import summarize_findings
from .risk import assess_cves, assess_service_risk
from .nvd import (
    BACKOFF_BASE,
    HTTP_TIMEOUT,
    MAX_CPE_QUERIES_PER_PORT,
    MAX_CVE_RESULTS,
    MAX_RETRIES,
    NVD_LIMIT_NO_KEY,
    NVD_LIMIT_WITH_KEY,
    NVD_RATE_WINDOW,
    NVD_URL,
    PRODUCT_CPE_MAP,
    SERVICE_FALLBACK_MAP,
    NVDRateLimiter,
    _cpe22_to_cpe23,
    _cpe23,
    _cpe_slug,
    _cvss_of,
    _version_candidates,
    _vendor_product,
    nvd_fetch,
)
from .nvd import check_cve_nvd as _check_cve_nvd
from .exploitdb import (
    EXPLOITDB_EXPLOITS_ROOT,
    EXPLOIT_HEADER_FIELDS,
    normalize_documented_exploit_metadata,
    extract_exploit_metadata,
    searchsploit_lookup as _searchsploit_lookup,
)
from .web_probe import (
    HTTP_PROBE_PORTS,
    WEB_BODY_LIMIT,
    WEB_TEXT_LIMIT,
    bounded_same_origin_get as _web_bounded_same_origin_get,
    probe_http_metadata as _probe_http_metadata,
    probe_web_intelligence as _probe_web_intelligence,
)
from .targeting import (
    build_host_os_fingerprint,
    infer_target_platform,
    normalize_nmap_args,
    scanned_hosts,
    validate_ports,
    validate_target,
)

from .assessment import (
    assess_cve_applicability,
    apply_contextual_cve_constraints,
    build_report_entry,
    classify_exploit,
    cpe22_to_cpe23,
    build_technology_fingerprint,
    assess_network_exposure,
    build_exploit_intelligence,
)

MAX_EXPLOIT_RESULTS = 10
REPORT_SCHEMA_VERSION = "1.15"
SCANNER_VERSION = "0.10.10"

# خريطة أسماء nmap "product" لأسماء CPE الرسمية في NVD
# (nmap بيقول مثلاً "Apache httpd" لكن اسم الـ CPE الرسمي apache:http_server)

# آخر احتياط: لو مفيش product خالص من nmap نرجّع للخريطة القديمة (بالخدمة بس - أقل دقة)








































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











def check_cve_nvd(session, port_data, api_key, limiter, results_per_page):
    """Compatibility seam preserving scanner-level NVD fetch injection."""
    return _check_cve_nvd(
        session, port_data, api_key, limiter, results_per_page, fetcher=nvd_fetch
    )



def searchsploit_lookup(product, version, limit=MAX_EXPLOIT_RESULTS):
    """Compatibility seam preserving scanner-level SearchSploit patch points."""
    return _searchsploit_lookup(
        product, version, limit=limit, runner=subprocess.run, which=shutil.which
    )



def probe_http_metadata(host, port, port_data):
    """Compatibility seam retaining scanner.requests patch support."""
    return _probe_http_metadata(
        host, port, port_data, requests_module=requests, scanner_version=SCANNER_VERSION
    )


def _bounded_same_origin_get(url, limit):
    """Compatibility seam retaining scanner.requests patch support."""
    return _web_bounded_same_origin_get(
        url, limit, requests_module=requests, scanner_version=SCANNER_VERSION
    )


def probe_web_intelligence(host, port, port_data):
    """Compatibility seam retaining scanner-level bounded-fetch patch support."""
    return _probe_web_intelligence(
        host, port, port_data, bounded_get=_bounded_same_origin_get,
        scanner_version=SCANNER_VERSION
    )

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

    os_detection_requested = bool(
        getattr(args, "os_detection", False) or "-O" in shlex.split(args.nmap_args)
    )
    host_os_fingerprints = {}
    for host in hosts:
        host_data = scanner[host]
        os_matches = host_data.get("osmatch", []) if hasattr(host_data, "get") else []
        host_os_fingerprints[host] = build_host_os_fingerprint(
            os_matches, requested=os_detection_requested
        )

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

            # Reuse host-level Nmap evidence; never infer OS from a service banner.
            os_fingerprint = host_os_fingerprints[host]
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
                entry["service"], cves, entry["risk_assessment"],
                finding_context={
                    "host": host,
                    "port": port,
                    "identification_evidence": entry.get("identification_evidence"),
                },
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
        "os_detection_requested": os_detection_requested,
        "host_os_fingerprints": [
            {"host": host, **fingerprint}
            for host, fingerprint in sorted(host_os_fingerprints.items())
        ],
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
        "summary": summarize_findings(results, hosts=hosts),
    }
    try:
        write_json_report(filename, report)
    except OSError as e:
        print(f"تعذر حفظ التقرير: {e}")
        sys.exit(1)
    print(f"تم حفظ النتائج في {filename}")
    if args.html_output:
        try:
            html_path = write_html_report(
                results, args.html_output, target=target,
                host_os_fingerprints=scan_metadata["host_os_fingerprints"],
                hosts=hosts,
            )
        except OSError as exc:
            print(f"تعذر حفظ تقرير HTML: {exc}")
            sys.exit(1)
        print(f"تم حفظ تقرير HTML في {html_path}")


if __name__ == "__main__":
    main()