# Authorized Metasploitable 2 Lab Validation

**Result: completed successfully** — ReconForge `0.10.11` performed a bounded live scan of the authorized Metasploitable 2 VM.

## Test environment

- Date: 2026-11-26 (UTC scan start: `19:55:40`; completion: `19:55:57`)
- Scanner: Kali Linux, Python `3.13`, Nmap `7.99`
- Target: `192.168.7.128` (private address of the isolated Metasploitable 2 lab VM)
- ReconForge version: `0.10.11`, report schema `1.16`
- Target scope: TCP ports `21,22,23,25,53,80,139,445` only
- Nmap arguments: `-sV` (service/version detection)
- Authorization acknowledgement: `--authorized`
- CVE enrichment: disabled with `--no-nvd` to keep this validation bounded and avoid external API lookups
- HTTP review: enabled with `--http-probe`

## Reproduction

From the repository root, after installing ReconForge in a virtual environment:

```bash
reconforge --authorized --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --no-nvd --http-probe --output evidence/lab-scan.json --html-output evidence/lab-dashboard.html
```

## Observed results

- Reachability: target replied to ICMP; 2 packets sent, 2 received, 0% loss.
- Scan duration: approximately `17.653` seconds.
- Hosts scanned: `1`.
- Open TCP services: `8` of the 8 explicitly selected ports.
- Service fingerprints:
  - `21/tcp`: FTP — `vsftpd 2.3.4`
  - `22/tcp`: SSH — `OpenSSH 4.7p1 Debian 8ubuntu1`
  - `23/tcp`: Telnet — `Linux telnetd` (version unknown)
  - `25/tcp`: SMTP — `Postfix smtpd` (version unknown)
  - `53/tcp`: DNS — `ISC BIND 9.4.2`
  - `80/tcp`: HTTP — `Apache httpd 2.2.8`; bounded HTTP header probe received a response
  - `139/tcp`: NetBIOS/SMB — `Samba smbd 3.X - 4.X`
  - `445/tcp`: NetBIOS/SMB — `Samba smbd 3.X - 4.X`
- Local Exploit-DB intelligence: `39` candidate references across the scanned services. These are research leads, not confirmation of exploitability.
- Network exposure observations: `4`.
- CVE candidates: `0` because NVD lookup was deliberately disabled; this does **not** mean the host has no vulnerabilities.
- Risk score: `Unscored`, because no CVE/CVSS evidence was retrieved in this run.
- Exploit execution: none. No exploit code was run and no changes were made to the target.

## Evidence included in this repository

- `dashboard.png` — screenshot of the generated ReconForge HTML dashboard.
- `scan-console.png` — screenshot of the captured scan console output.

The full JSON report, HTML report, and raw console transcript were generated locally during the test but are intentionally not committed. They contain detailed target and service data; the repository keeps only this concise summary and screenshots as reproducible portfolio evidence.

## Limitations

This was a deliberately narrow service/version scan of eight selected TCP ports, not a full TCP/UDP port sweep. NVD lookups and OS fingerprinting were not requested. SearchSploit title matches can be noisy and require manual validation. A live scan confirms that the tool ran and collected the displayed observations; it does not establish that every listed service is exploitable.
