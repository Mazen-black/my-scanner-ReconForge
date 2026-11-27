# Security Policy

## Supported versions

ReconForge is a pre-1.0 project under active development. Security fixes are made in the latest release only.

| Version | Supported |
| --- | --- |
| Latest release (see the `Current version` line in the README) | Yes |
| Older releases | No |

## Scope

ReconForge is a reconnaissance and vulnerability assessment tool for systems you own or have explicit written authorization to test. It does not exploit vulnerabilities, and it does not apply changes to targets.

In scope for this policy:

- Defects in ReconForge itself, such as unsafe handling of scan targets or Nmap output, injection into the HTML or JSON reports, unsafe handling of NVD or Exploit-DB data, and vulnerable dependencies.

Out of scope:

- Findings that ReconForge reports about a scanned host. Those belong to the owner of that system.
- Anything that requires scanning a system you are not authorized to test.
- Reports generated from unauthorized scanning. Unauthorized use is not supported.

## Reporting a vulnerability

Report security problems privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (direct link: https://github.com/Mazen-black/my-scanner-ReconForge/security/advisories/new). Please do not open a public issue for a security problem.

A useful report includes the ReconForge version, the report schema version if it is relevant, the steps to reproduce, and the impact you observed.

Do not include real target addresses, credentials, or third-party scan data. Use documentation ranges such as `192.0.2.0/24`, or redact them.

## What to expect

This is a best-effort project maintained by one person, so a reply may take a few days. Valid reports are fixed in the next patch release and noted in `CHANGELOG.md`, and the reporter is credited unless they ask otherwise.

## Responsible use

Use ReconForge only on systems you own or have explicit authorization to test, and follow applicable laws and the target owner's rules of engagement. The author is not responsible for misuse or damage caused by use of this software. See the "Responsible use" section of the README.
