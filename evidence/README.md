# Authorized Lab Test Guide

ReconForge should be validated against a deliberately vulnerable lab host such as Metasploitable 2 or an isolated local VM. Do not use public or third-party systems without explicit written authorization.

## Reproduce a bounded scan

The following example uses a private lab address and eight TCP ports. The target must be reachable from the scanner host.

```bash
reconforge --authorized --target 192.168.7.128 --ports 21,22,23,25,53,80,139,445 --no-nvd --http-probe --output evidence/lab-scan.json --html-output evidence/lab-dashboard.html
```

The current scanner requires the `--authorized` acknowledgement. It also rejects CIDR networks larger than 256 addresses and accepts only the reviewed Nmap flags documented in the main README.

## Evidence handling

Generated JSON and HTML reports are intentionally ignored by Git. They may contain target addresses, service banners, software versions, and vulnerability observations. Keep them locally or in a private evidence store, and redact sensitive details before sharing.

The historical Metasploitable 2 evidence was collected before the authorization-flag and Nmap-argument hardening changes. Re-run the command above against the isolated lab after those changes before claiming that the hardened version passed a live lab test.

No exploit code should be downloaded or executed as part of this validation. Confirm only expected scan behavior, output generation, and report consistency.
