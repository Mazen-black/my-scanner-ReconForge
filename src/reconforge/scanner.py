#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconForge network reconnaissance and vulnerability assessment.

The scanner combines Nmap service discovery, NVD CVE research, optional
local Exploit-DB lookups, evidence-based assessment, and structured reports.
All scans require an explicit authorization acknowledgement.
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
from .confidence import build_evidence_confidence
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
REPORT_SCHEMA_VERSION = "1.16"
SCANNER_VERSION = "0.10.11"

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
        description="Authorized network reconnaissance and vulnerability assessment using Nmap, NVD, and optional Exploit-DB.")
    parser.add_argument("--target", required=True, help="Target IP address, CIDR network, or hostname.")
    parser.add_argument(
        "--authorized", action="store_true", required=True,
        help="Confirm that you own the target or have explicit permission to scan it."
    )
    parser.add_argument("--ports", default="1-1000", help="TCP ports or ranges (for example: 1-1000 or 22,80,443).")
    parser.add_argument("--nvd-api-key", default=None,
                        help="NVD API key (or NVD_API_KEY environment variable).")
    parser.add_argument("--nmap-args", default="-sV", help="Allowlisted Nmap flags (default: -sV).")
    parser.add_argument("--os-detection", action="store_true",
                        help="Enable Nmap OS detection (-O); may require root/raw-socket privileges.")
    parser.add_argument("--results-per-page", type=int, default=10,
                        help="Maximum NVD results per query (1-2000).")
    parser.add_argument("--http-probe", action="store_true",
                        help="Inspect HTTP headers and cookie attributes with one HEAD request per web service.")
    parser.add_argument("--web-intel", action="store_true",
                        help="Inspect bounded same-host HTML, CMS/JS hints, robots.txt, and sitemap.xml.")
    parser.add_argument("--no-exploitdb", action="store_true",
                        help="Disable local SearchSploit lookups.")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Skip NVD lookups (useful offline or when NVD is unavailable).")
    parser.add_argument("--html-output", default=None,
                        help="Optional standalone HTML report path.")
    parser.add_argument("--asset-criticality", choices=("unknown", "low", "medium", "high", "critical"), default="unknown",
                        help="Operator-supplied asset criticality; never inferred automatically.")
    parser.add_argument("--exposure", choices=("unknown", "internal", "internet"), default="unknown",
                        help="Operator-supplied exposure; never inferred from open ports.")
    parser.add_argument("--output", "-o", default=None,
                        help="Optional JSON report path.")
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
        print("NVD API key detected; rate limit: 50 requests per 30 seconds.")
    else:
        print("No NVD API key detected; rate limit: 5 requests per 30 seconds. Set NVD_API_KEY to increase the limit.")
    limiter = NVDRateLimiter(NVD_LIMIT_WITH_KEY if api_key else NVD_LIMIT_NO_KEY, NVD_RATE_WINDOW)
    session = requests.Session()

    target = args.target
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    print(f"Starting scan: {target} | ports: {args.ports} | Nmap flags: {args.nmap_args}")

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, args.ports, arguments=args.nmap_args)
    except Exception as e:
        print(f"Scan failed: {e}")
        print("Check target reachability and required Nmap privileges.")
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
            print(f"Port {port}: open | service: {service} | product: {product or 'unknown'} | version: {version or 'unknown'}")

            cves = []
            cpes_tried = []
            if args.no_nvd:
                print("  Skipping NVD lookup (--no-nvd).")
            elif version:
                print(f"  Looking up CVEs for {product or service} {version}...")
                cves, cpes_tried = check_cve_nvd(
                    session, port_data, api_key, limiter, args.results_per_page)
                if cves:
                    print(f"  Found {len(cves)} CVE candidates; top 5 by CVSS:")
                    for c in cves[:5]:
                        score_txt = f"{c['cvss']}" if c["cvss"] is not None else "unknown"
                        print(f"    {c['id']} - CVSS {score_txt} ({c['severity'] or 'unspecified'})")
                else:
                    print("  No CVE candidates found.")
            else:
                print("  No version detected; skipping NVD and checking local Exploit-DB only.")

            exploits = []
            if not args.no_exploitdb:
                print("  Searching local Exploit-DB with SearchSploit...")
                # Generic service labels are not reliable product fingerprints.
                exploits = searchsploit_lookup(product, version) if product else []
                if not product:
                    print("  No reliable product fingerprint; skipping SearchSploit to avoid unrelated results.")
                elif exploits:
                    print(f"  Found {len(exploits)} possible references; showing up to 5:")
                    for e in exploits[:5]:
                        print(f"    EDB-{e['id']} - {e['title']}")
                else:
                    print("  No local Exploit-DB references found.")

            # Finalize NVD applicability before correlating exploit references with CVEs.
            cves = assess_cves(cves)

            # Reuse host-level Nmap evidence; never infer OS from a service banner.
            os_fingerprint = host_os_fingerprints[host]
            target_platform = os_fingerprint["platform_family"]
            exploit_intelligence = build_exploit_intelligence(
                exploits, cves, target_platform=target_platform
            )
            if exploit_intelligence:
                print(f"  Exploit intelligence: {len(exploit_intelligence)} references with safe validation guidance.")

            http_assessment = {"status": "not_requested"}
            if args.http_probe:
                http_assessment = probe_http_metadata(host, port, port_data)
                print(f"  HTTP assessment: {http_assessment.get('status')}")
            web_intelligence = {"status": "not_requested"}
            if args.web_intel:
                web_intelligence = probe_web_intelligence(host, port, port_data)
                print(f"  Web intelligence: {web_intelligence.get('status')}")

            # Keep technical risk, operator-supplied asset context, and remediation separate.
            service_fingerprint = build_technology_fingerprint(port_data)
            evidence_confidence = build_evidence_confidence(
                service_fingerprint, cves, exploits, exploit_intelligence
            )
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
                fingerprint=service_fingerprint,
                http_assessment=http_assessment,
                web_intelligence=web_intelligence,
                network_exposure=assess_network_exposure(port, service, product),
                exploit_intelligence=exploit_intelligence,
                host_os_fingerprint=os_fingerprint,
            )
            entry["evidence_confidence"] = evidence_confidence
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
    summary = summarize_findings(results, hosts=hosts)
    print("\nHost-level summary (canonical aggregation):")
    print(
        f"  Hosts: {summary['hosts_scanned']} | Open services: {summary['open_services']} | "
        f"CVE observations: {summary['cve_candidates']} | Unique per-host CVE candidates: {summary['unique_host_cves']}"
    )
    print(
        f"  Cross-service CVEs: {summary['cross_service_cves']} | "
        f"Duplicate observations: {summary['duplicate_cve_observations']} | "
        f"Hosts with CVE candidates: {summary['hosts_with_cves']}"
    )
    for host_summary in summary["host_risk_summary"]:
        score = host_summary["highest_review_priority_score"]
        score_text = f" ({score:.1f}/100)" if score is not None else ""
        print(
            f"  {host_summary['host']}: {host_summary['unique_cve_count']} unique CVE candidates "
            f"across ports {', '.join(host_summary['ports']) or 'none'}; "
            f"highest service review priority: {host_summary['highest_review_priority']}{score_text}"
        )
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": scan_metadata,
        "findings": results,
        "summary": summary,
    }
    try:
        write_json_report(filename, report)
    except OSError as e:
        print(f"Could not write JSON report: {e}")
        sys.exit(1)
    print(f"JSON report saved to {filename}")
    if args.html_output:
        try:
            html_path = write_html_report(
                results, args.html_output, target=target,
                host_os_fingerprints=scan_metadata["host_os_fingerprints"],
                hosts=hosts,
            )
        except OSError as exc:
            print(f"Could not write HTML report: {exc}")
            sys.exit(1)
        print(f"HTML report saved to {html_path}")


if __name__ == "__main__":
    main()