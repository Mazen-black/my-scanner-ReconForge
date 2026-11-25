# Authorized Metasploitable 2 Lab Evidence

This folder contains three complementary evidence sets:

1. A real, bounded, authorized Metasploitable 2 lab scan with NVD disabled, and the HTML dashboard rendered from that exact report.
2. A real, bounded, authorized Metasploitable 2 lab scan with NVD enabled, and the HTML dashboard rendered from that exact report.
3. A clearly labeled synthetic test fixture and dashboard that demonstrate host-level CVE deduplication, cross-service correlation, and preservation of mixed applicability evidence. The synthetic fixture is fabricated test data, not a network scan or a real vulnerability finding.

## Run details

- Target: `192.168.7.128` (private Metasploitable 2 lab host)
- Scan date: 2026-11-25 (UTC)
- Scanner: ReconForge `0.10.11`
- Report schema: `1.16`
- Ports checked: `21,22,23,25,53,80,139,445`
- Nmap arguments: `-sV`
- Optional HTTP review: enabled (`HEAD /` for the detected HTTP service)
- NVD lookup: intentionally disabled for this eight-port evidence run (`--no-nvd`)
- OS fingerprinting: not requested

## Observed results

- 1 host scanned
- 8 open services observed
- 39 local SearchSploit references retained for manual review
- 4 network-exposure observations
- 8 services with remediation guidance
- 0 CVE candidates in this run because NVD lookup was disabled; this is **not** evidence that the host has no vulnerabilities.
- All SearchSploit results are research leads, not confirmed vulnerabilities. No exploit code was downloaded or executed, and no remediation was applied.

### NVD-enabled run (`metasploitable2-nvd-authorized-*`)

- NVD lookups were enabled; no API key was configured, so the default rate limit (5 requests per 30 seconds) was respected. The scan completed in about 75.5 seconds.
- 8 open services observed; 54 service-level CVE observations were aggregated into 44 unique per-host CVE candidates.
- 10 CVEs were observed on more than one service (10 duplicate observations); in this run, those repeated observations are primarily the same Samba candidates on ports 139 and 445.
- Applicability evidence: 20 service-level observations were `version_match` and 34 were `candidate_unverified`. Neither status proves exploitability; `candidate_unverified` explicitly means the available host/service inventory did not establish the complete NVD configuration path.
- Example of a contextual limitation: `CVE-2011-2523` has a vsftpd 2.3.4 CPE version match, but the known backdoor is tied to download/build provenance during a specific date window. The report correctly leaves it `candidate_unverified` until that provenance is independently established.
- The highest service review-priority score was 98/100 for Apache on port 80. This is a review-ordering heuristic based on CVSS and applicability evidence, not a compromise probability or confirmation of exploitability.
- NVD CVEs are candidates and require vendor/package/build verification. No exploit code was downloaded or executed, and no remediation was applied.

## Files

- `metasploitable2-authorized-scan.json` — machine-readable ReconForge output, including service evidence, summary counts, and assessment limitations.
- `metasploitable2-authorized-dashboard.html` — standalone HTML dashboard generated from the same findings using ReconForge's report renderer.
- `metasploitable2-nvd-authorized-scan.json` — second real scan report with NVD lookups enabled (no API key; default rate limit applied).
- `metasploitable2-nvd-authorized-dashboard.html` — standalone HTML dashboard generated from that exact NVD-enabled JSON report.
- `reconforge-host-cve-correlation-demo.json` — fabricated, explicitly labeled test fixture showing 3 service observations, 2 unique per-host CVE candidates, and 1 CVE observed across two services.
- `reconforge-host-cve-correlation-demo.html` — dashboard rendered from that exact synthetic JSON file; it displays the two ports and their different applicability states (`version_match` and `candidate_unverified`).

The synthetic fixture uses the documentation-only address `192.0.2.10` and fabricated CVE identifiers. It exists solely to make the aggregation/reporting behavior visible when the real lab scan has NVD disabled; it is not evidence of an actual vulnerability.

## Reproduce

From the project root, with Nmap and SearchSploit installed and the lab host reachable:

```bash
reconforge --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --no-nvd --http-probe --output evidence/metasploitable2-authorized-scan.json --html-output evidence/metasploitable2-authorized-dashboard.html
```

This is a bounded lab demonstration, not a full-port or comprehensive security assessment. Scan only systems you own or are explicitly authorized to assess.
