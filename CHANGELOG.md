# Changelog

## 0.10.11 - 2026-11-25

- Add host-level risk summaries with unique CVEs deduplicated per host, cross-service CVE correlation, duplicate-observation counts, affected ports, and highest service review-priority score.
- Extend the HTML dashboard with host-level correlation tables and transparent distinction between raw CVE observations and unique per-host CVEs.
- Treat repeated CVE rows within one service as a single service observation; preserve separate counts when the same CVE affects multiple hosts.
- Harden summary aggregation against malformed findings, CVE records, and invalid/non-finite risk scores.
- Advance the additive report schema to 1.16 and scanner package version to 0.10.11.

## 0.10.10 - 2026-11-25

- Add an explainable evidence-confidence profile separating Nmap service identity, NVD CVE applicability, explicit Exploit-DB/CVE linkage, and exploitability; render the consolidated profile in HTML reports.
- Harden Exploit-DB deduplication so unidentified rows are not merged, merge missing duplicate metadata while retaining conflicting variants, and safely handle malformed nested correlation metadata; expose metadata conflicts in the dashboard.
- Make risk scoring formulas and applicability/context factors explicit; reject non-finite or malformed scores and safely ignore malformed CVE/exploit entries. Dashboard now exposes the factors behind technical and contextual priorities.
- Attach host, port, detected service/product/version, NVD applicability criteria, confidence reasons, and evidence gaps to remediation guidance; render escaped provenance in the HTML dashboard. Unknown applicability states are downgraded to unverified.
- Validate NVD CVSS scores at ingestion; reject booleans, non-finite values, non-numeric values, and scores outside the 0–10 range before risk assessment.
- Validate report schema versions and reject unsupported future major/minor versions while preserving legacy list and unversioned-envelope compatibility.
- Derive displayed CVSS severity from validated 0–10 scores instead of trusting potentially inconsistent labels.
- Handle malformed/unreadable JSON with a concise CLI error and preserve 0–100 risk-priority score rendering.
- Validate CVSS values before rendering; booleans, out-of-range values, NaN, and infinity remain Unknown/N/A.
- Expand GitHub Actions validation across Python 3.10, 3.11, 3.12, and 3.13.
- Compile the scanner, assessment, reporting, risk, asset-context, and remediation modules in CI before running tests.

## 0.10.9 - 2026-11-25

- Require complete CPE 2.3 identifiers before evaluating NVD applicability.
- Keep constrained update, edition, language, target OS, hardware, and other CPE attributes unverified when the service scan has not identified them.
- Stop stripping vendor/distribution suffixes from detected versions because they may encode downstream security backports.
- Add regression tests for malformed CPEs, constrained CPE attributes, and suffixed versions.

## 0.10.8 - 2026-11-25

- Preserve one Nmap OS fingerprint record per resolved host in report metadata, including hosts with no open TCP services.
- Feed host-level OS evidence into standalone HTML reports and keep compatibility with older per-service-only reports.
- Show host-level OS detection status and acceptance details in the dashboard without duplicating hosts.
- Reject out-of-range Nmap OS accuracy values before accepting a platform family.
- Add regression coverage for host-only reports and invalid OS accuracy values.

## 0.10.7

- Expand the HTML report with a dedicated host OS fingerprint section and accepted-match summary.
