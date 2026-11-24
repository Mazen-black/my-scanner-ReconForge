"""Conservative remediation guidance based on observed service/CVE metadata.

Recommendations are review guidance, not verified vendor fixes. Never invent fixed
versions or run changes against a target from this module.
"""

SERVICE_GUIDANCE = {
    "telnet": {
        "title": "Replace plaintext remote administration",
        "actions": [
            "Confirm whether Telnet is required; if not, disable the service through the host's approved change process.",
            "If remote administration is needed, migrate to SSH with key-based authentication and managed access controls.",
            "Restrict administrative access to approved management networks while migration is planned.",
        ],
        "verification": [
            "Confirm the Telnet daemon is disabled or no longer listening.",
            "Verify approved SSH access works and authentication policy is enforced.",
            "Re-scan from the same authorized network vantage point.",
        ],
        "priority": "high",
        "reason": "Telnet does not protect session contents with transport encryption.",
    },
    "ftp": {
        "title": "Review FTP transport and authentication",
        "actions": [
            "Confirm whether FTP is required; disable it if unused.",
            "Prefer SFTP or FTPS with enforced encryption and managed credentials.",
            "Restrict access to approved clients and review anonymous access and write permissions.",
        ],
        "verification": [
            "Confirm the legacy FTP listener is removed or restricted as intended.",
            "Test encrypted file-transfer access and verify anonymous access is disabled unless explicitly required.",
            "Re-scan and review service configuration.",
        ],
        "priority": "medium",
        "reason": "Traditional FTP does not encrypt credentials or file contents by default.",
    },
    "rsh": {
        "title": "Remove legacy r-services",
        "actions": [
            "Identify dependencies on rsh, rlogin, and rexec before making changes.",
            "Disable unused legacy services and remove trust-based host access where no longer required.",
            "Migrate administration to SSH with key-based authentication and least privilege.",
        ],
        "verification": [
            "Confirm legacy r-service daemons are disabled and ports are no longer listening.",
            "Verify replacement SSH workflows and access logging.",
            "Re-scan the host from the authorized test network.",
        ],
        "priority": "high",
        "reason": "Legacy r-services commonly rely on weak host-based trust and lack modern transport protections.",
    },
    "smb": {
        "title": "Harden SMB file sharing",
        "actions": [
            "Inventory required shares and remove guest or anonymous access unless explicitly approved.",
            "Restrict SMB to trusted network segments and enforce least-privilege share and filesystem permissions.",
            "Disable SMBv1 where compatibility requirements permit and apply supported vendor security updates.",
        ],
        "verification": [
            "Review effective share and filesystem ACLs using an authorized account.",
            "Confirm SMBv1 is disabled where intended and only approved networks can reach SMB.",
            "Re-scan and validate business-critical file-sharing workflows.",
        ],
        "priority": "high",
        "reason": "SMB exposure and legacy protocol/configuration choices can increase attack surface.",
    },
    "ssh": {
        "title": "Harden SSH administration",
        "actions": [
            "Apply supported vendor security updates after compatibility review.",
            "Prefer key-based authentication, disable obsolete algorithms, and restrict administrative access.",
            "Review privileged accounts, authentication logs, and rate-limiting controls.",
        ],
        "verification": [
            "Validate effective SSH configuration and supported cryptographic algorithms.",
            "Test access using approved accounts before closing the change.",
            "Confirm logs capture successful and failed authentication attempts.",
        ],
        "priority": "medium",
        "reason": "SSH is encrypted, but outdated software or permissive configuration can still create risk.",
    },
    "http": {
        "title": "Review web service patching and exposure",
        "actions": [
            "Identify the exact web server build and compare it with the vendor's security advisories.",
            "Apply a vendor-supported fixed release through the normal maintenance process.",
            "Remove unused modules, restrict administrative interfaces, and place the service behind approved network controls.",
        ],
        "verification": [
            "Confirm the deployed build matches the vendor-approved target version.",
            "Run application health checks and review server error/access logs.",
            "Re-scan and validate TLS and exposed endpoints.",
        ],
        "priority": "medium",
        "reason": "Web server version and configuration should be validated against vendor guidance.",
    },
}


def _service_family(service_name):
    name = (service_name or "").lower()
    if "telnet" in name:
        return "telnet"
    if name in {"ftp", "ftps"} or name.startswith("ftp-"):
        return "ftp"
    if name in {"shell", "login", "exec", "rsh", "rlogin", "rexec"}:
        return "rsh"
    if "smb" in name or "microsoft-ds" in name or "netbios-ssn" in name:
        return "smb"
    if "ssh" in name:
        return "ssh"
    if "http" in name or "https" in name:
        return "http"
    return None


def build_remediation(service, cves=None, risk_assessment=None):
    """Build non-invasive, evidence-labelled guidance for one discovered service."""
    service = service or {}
    family = _service_family(service.get("name"))
    service_item = None
    if family:
        template = SERVICE_GUIDANCE[family]
        service_item = {
            "source": "service_family_heuristic",
            "service_family": family,
            "title": template["title"],
            "priority": template["priority"],
            "reason": template["reason"],
            "actions": list(template["actions"]),
            "verification": list(template["verification"]),
            "confidence": "medium",
        }

    cve_items = []
    for cve in cves or []:
        applicability = cve.get("applicability") or {}
        priority = cve.get("risk_priority") or {}
        cve_id = cve.get("id") or "Unidentified CVE"
        status = applicability.get("status", "candidate_unverified")
        if status == "not_matched_by_nvd_cpe":
            continue
        actions = [
            "Retrieve the authoritative vendor advisory for this CVE and confirm the affected product, exact build, platform, and prerequisites.",
            "If the installed build is affected, plan an upgrade to the vendor-documented fixed release; ReconForge does not guess fixed version numbers.",
            "If patching must wait, apply only vendor-documented compensating controls and restrict access to the affected component.",
        ]
        if status == "candidate_unverified":
            actions.insert(0, "Verify the remaining NVD configuration conditions (such as operating system, module, or deployment context) before treating this finding as applicable.")
        cve_items.append({
            "cve_id": cve_id,
            "source": "CVE metadata and NVD applicability status",
            "applicability": status,
            "priority": priority.get("priority", "Unscored"),
            "priority_score": priority.get("priority_score"),
            "confidence": "low" if status == "candidate_unverified" else "medium",
            "title": f"Validate and remediate {cve_id}",
            "actions": actions,
            "verification": [
                "Confirm the vendor-reported fixed build is installed and the affected component is restarted if required.",
                "Re-run version detection and review vendor-specific validation guidance.",
                "Reassess the complete NVD configuration and confirm the finding is no longer applicable.",
            ],
            "limitations": [
                "A CVE reference or CPE match does not prove exploitability.",
                "No fixed version is asserted unless verified from the product vendor.",
                "No remediation command is executed by ReconForge.",
            ],
        })

    return {
        "model": "ReconForge-RM1",
        "mode": "guidance_only",
        "service_guidance": service_item,
        "cve_guidance": cve_items,
        "notes": [
            "Guidance must be reviewed against vendor documentation and the asset owner's change process.",
            "Recommendations are not automatically applied.",
        ],
    }
