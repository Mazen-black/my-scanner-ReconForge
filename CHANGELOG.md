# Changelog

## 0.10.8 - 2026-11-25

- Preserve one Nmap OS fingerprint record per resolved host in report metadata, including hosts with no open TCP services.
- Feed host-level OS evidence into standalone HTML reports and keep compatibility with older per-service-only reports.
- Show host-level OS detection status and acceptance details in the dashboard without duplicating hosts.
- Reject out-of-range Nmap OS accuracy values before accepting a platform family.
- Add regression coverage for host-only reports and invalid OS accuracy values.

## 0.10.7

- Expand the HTML report with a dedicated host OS fingerprint section and accepted-match summary.
