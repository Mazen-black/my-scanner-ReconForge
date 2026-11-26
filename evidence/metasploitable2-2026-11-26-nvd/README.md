# Authorized Metasploitable 2 Lab Validation — NVD Enrichment

**Result: completed successfully.** This is a second, separate ReconForge run against the same authorized Metasploitable 2 VM and the same bounded TCP port list as the baseline run. NVD enrichment was enabled; no exploit was executed.

## Test environment

- Date: 2026-11-26 (UTC start: `20:02:00`; completion: `20:03:16`)
- Scanner: Kali Linux, Python `3.13`, Nmap `7.99`
- ReconForge: `0.10.11`; report schema: `1.16`
- Target: `192.168.7.128` (private lab VM)
- Scope: TCP ports `21,22,23,25,53,80,139,445` only
- Nmap arguments: `-sV`
- Authorization acknowledgement: `--authorized`
- NVD enrichment: enabled; no API key was configured (NVD unauthenticated rate limit: 5 requests per 30 seconds)
- HTTP header probe: enabled
- Exploit-DB local lookups: enabled

## Reproduction

```bash
reconforge --authorized --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --http-probe --output evidence/lab-scan-nvd.json --html-output evidence/lab-dashboard-nvd.html
```

## Observed results

- Hosts scanned: `1`.
- Open services: `8` (all eight explicitly selected TCP ports).
- Scan duration: approximately `76.45` seconds.
- NVD CVE observations: `54`.
- Unique CVE candidates aggregated for the host: `44`.
- Duplicate cross-service observations: `10`.
- Services with numeric review scores: `6`; Telnet and SMTP remained unscored because no versioned CVE evidence was available.
- Local Exploit-DB references: `39`.
- Network exposure observations: `4`.
- Highest service review priority: HTTP on `80/tcp`, `Critical (98.0/100)`.
- Other scored service priorities: DNS on `53/tcp`, `High (76.0/100)`; FTP on `21/tcp`, `High (74.0/100)`; SSH and SMB services, `Medium (63.7/100)`.
- Exploit execution: none. No changes were made to the target.

## CVE interpretation — important

The `54` observations are not `54` confirmed vulnerabilities. They are NVD matches returned from service/product/version CPE queries; the host-level aggregation deduplicated them to `44` candidate CVEs.

Applicability confidence varies by service:
- SSH and Samba results were marked `candidate_unverified`; for Samba, Nmap reported only `3.X - 4.X`, which is too broad to prove a vulnerable release or required configuration.
- Some version matches still require manual validation of distribution patches, build options, and CVE-specific preconditions.
- A CVSS score describes a vulnerability's severity under its scoring assumptions; it is not proof that this particular service is exploitable.
- ReconForge's service review priority is a triage aid, not CVSS and not a quantified business-loss estimate.
- Exploit-DB title matches are research leads only and do not prove exploitability.

## Comparison with the baseline run

The baseline evidence in the sibling directory was run with `--no-nvd`:
- Baseline: `0` CVE candidates and services remained `Unscored` because no CVE/CVSS evidence was retrieved.
- NVD-enabled run: `54` CVE observations, `44` unique host-level candidates, and `6` services received numeric review scores.
- Both runs used the same target, eight TCP ports, `-sV`, and HTTP header probe. The NVD-enabled run took longer because it queried the external NVD service and observed its unauthenticated rate limit.

## Evidence included

- `dashboard.png` — screenshot of the NVD-enriched HTML dashboard.
- `scan-console.png` — screenshot of the console output from the NVD-enabled run.

Raw JSON, HTML, and console output were retained locally for analysis and are intentionally not committed; they contain detailed target/service data. This repository contains a concise summary and screenshots only.

## Limitations

This was not a full TCP/UDP sweep, authenticated configuration audit, operating-system fingerprint, or exploit validation. NVD CPE matching can produce false positives or incomplete matches when banners are broad or distribution-specific package revisions are unknown. All candidate findings require manual verification before being reported as confirmed vulnerabilities.
