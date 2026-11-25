# Authorized Metasploitable 2 Lab Evidence

This folder contains two complementary evidence sets:

1. A real, bounded, authorized Metasploitable 2 lab scan and the HTML dashboard rendered from that exact report.
2. A clearly labeled synthetic test fixture and dashboard that demonstrate host-level CVE deduplication, cross-service correlation, and preservation of mixed applicability evidence. The synthetic fixture is fabricated test data, not a network scan or a real vulnerability finding.

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

## Files

- `metasploitable2-authorized-scan.json` — machine-readable ReconForge output, including service evidence, summary counts, and assessment limitations.
- `metasploitable2-authorized-dashboard.html` — standalone HTML dashboard generated from the same findings using ReconForge's report renderer.
- `reconforge-host-cve-correlation-demo.json` — fabricated, explicitly labeled test fixture showing 3 service observations, 2 unique per-host CVE candidates, and 1 CVE observed across two services.
- `reconforge-host-cve-correlation-demo.html` — dashboard rendered from that exact synthetic JSON file; it displays the two ports and their different applicability states (`version_match` and `candidate_unverified`).

The synthetic fixture uses the documentation-only address `192.0.2.10` and fabricated CVE identifiers. It exists solely to make the aggregation/reporting behavior visible when the real lab scan has NVD disabled; it is not evidence of an actual vulnerability.

## Reproduce

From the project root, with Nmap and SearchSploit installed and the lab host reachable:

```bash
reconforge --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --no-nvd --http-probe --output evidence/metasploitable2-authorized-scan.json --html-output evidence/metasploitable2-authorized-dashboard.html
```

This is a bounded lab demonstration, not a full-port or comprehensive security assessment. Scan only systems you own or are explicitly authorized to assess.
