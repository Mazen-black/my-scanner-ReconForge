# Changelog

## 0.10.10 - 2026-11-25

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
