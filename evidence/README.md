# Authorized Lab Test Guide

ReconForge is intended for controlled security testing on systems you own or have explicit written authorization to assess. The published Metasploitable 2 evidence below comes from an isolated, deliberately vulnerable lab VM.

## Reproduce the baseline scan

```bash
reconforge --authorized --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --no-nvd --http-probe --output evidence/lab-scan.json --html-output evidence/lab-dashboard.html
```

## Reproduce the NVD-enriched scan

```bash
reconforge --authorized --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --http-probe --output evidence/lab-scan-nvd.json --html-output evidence/lab-dashboard-nvd.html
```

Both commands use the same bounded TCP port list and service/version detection. The second run enables NVD enrichment. It may take longer because of external NVD API requests and unauthenticated rate limits. An NVD API key can increase the permitted request rate; keep it in an environment variable and never commit it.

## Published validation evidence

Two real runs were performed on 2026-11-26 against the authorized Metasploitable 2 VM:

| Run | NVD enrichment | Open selected ports | CVE observations | Unique host-level candidates | Duration |
|---|---:|---:|---:|---:|---:|
| Baseline | Disabled | 8/8 | 0 (lookup skipped) | 0 | ~17.65 s |
| Enriched | Enabled | 8/8 | 54 | 44 | ~76.45 s |

- [Baseline evidence and findings](metasploitable2-2026-11-26/README.md)
- [NVD-enriched evidence and findings](metasploitable2-2026-11-26-nvd/README.md)

The baseline's zero CVE count means NVD was not queried; it does not mean the host was vulnerability-free. The enriched run returned 54 service-level NVD observations, deduplicated to 44 unique host-level candidate CVEs. These are not confirmed vulnerabilities. Applicability and exploitability require manual verification against exact package builds, distribution backports, configuration, and CVE preconditions.

## Safety controls and scope

The current scanner requires the `--authorized` acknowledgement. This is an operator confirmation, not an independent authorization check. It rejects CIDR networks larger than 256 addresses and accepts only reviewed Nmap arguments documented in the main README. The published runs used only the explicitly selected eight TCP ports and Nmap `-sV`.

No exploit code was downloaded or executed, and no changes were made to the target.

## Evidence handling

Generated JSON and HTML reports and raw console transcripts are intentionally ignored by Git because they can expose target addresses, service banners, software versions, and vulnerability observations. The repository publishes only reviewed summaries and screenshots. Keep full reports in a private location and redact sensitive details before sharing.

## Test coverage

The automated unit and integration suite runs offline and does not scan a live target or make live NVD requests:

```bash
python -m unittest discover -s tests -v
```

The live lab evidence complements these tests; it does not replace them or establish exploitability.