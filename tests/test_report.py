import json
import sys
import tempfile
import unittest
from pathlib import Path

from report import main as report_main, render_html_report, write_html_report


class HTMLReportTests(unittest.TestCase):
    def sample(self):
        return [{
            "host": "127.0.0.1",
            "port": 443,
            "state": "open",
            "service": {"name": "https", "product": "Example Server", "version": "1.2.3"},
            "cve_assessment": [{
                "id": "CVE-2099-0001",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "summary": "Example <script>alert(1)</script>",
                "applicability": {"status": "version_match", "confidence": "medium"},
            }],
            "searchsploit_assessment": [{
                "id": "12345",
                "title": "Example Server <img src=x onerror=alert(1)>",
                "platform": "Linux",
                "assessment": {"relevance": "product_and_version_match", "confidence": "medium"},
            }],
            "assessment_limits": ["Banners may be incomplete or spoofed."],
        }]

    def test_report_contains_target_and_summary_metrics(self):
        html = render_html_report(self.sample(), target="lab.local", generated_at="2026-11-13 12:00 UTC")
        self.assertIn("lab.local", html)
        self.assertIn("CVE-2099-0001", html)
        self.assertIn("High / Critical CVEs", html)
        self.assertIn(">1</div>", html)

    def test_report_renders_host_os_fingerprint_and_escapes_it(self):
        findings = self.sample()
        findings[0]["host_os_fingerprint"] = {
            "status": "accepted_high_confidence",
            "platform_family": "linux",
            "nmap_name": "Linux 2.6.9 - 2.6.33 <test>",
            "accuracy": 100,
        }
        html = render_html_report(findings)
        self.assertIn("Host OS fingerprint", html)
        self.assertIn("Linux 2.6.9 - 2.6.33 &lt;test&gt; (100%)", html)
        self.assertNotIn("Linux 2.6.9 - 2.6.33 <test>", html)

    def test_report_renders_risk_and_remediation_guidance(self):
        findings = self.sample()
        findings[0]["risk_assessment"] = {
            "score": 98.0, "level": "Critical", "top_cve": "CVE-2099-0001",
            "exploit_reference_count": 1,
            "asset_context": {
                "contextual_priority_score": 100.0,
                "contextual_priority": "Critical",
                "asset_criticality": "critical",
                "network_exposure": "internet",
            },
        }
        findings[0]["remediation_guidance"] = {
            "mode": "guidance_only",
            "service_guidance": {
                "title": "Harden the service", "priority": "high",
                "confidence": "medium", "reason": "Synthetic test guidance",
                "actions": ["Restrict access to approved networks."],
                "verification": ["Re-scan from the approved test network."],
            },
            "cve_guidance": [],
        }
        html = render_html_report(findings, target="risk-lab")
        self.assertIn("Critical", html)
        self.assertIn("Harden the service", html)
        self.assertIn("Restrict access to approved networks.", html)
        self.assertIn("Re-scan from the approved test network.", html)

    def test_report_renders_explicit_exploit_metadata_values(self):
        findings = [{
            "host": "127.0.0.1", "port": 22,
            "service": {"name": "ssh"},
            "searchsploit_assessment": [{
                "id": "777", "title": "Example", "platform": "Linux",
                "assessment": {"relevance": "product_match_version_unconfirmed", "confidence": "low"},
            }],
            "exploit_intelligence": [{
                "reference": {"id": "777", "title": "Example"},
                "applicability_evidence": {
                    "requirements_assessment": "documented_in_local_metadata",
                    "documented_requirements": {
                        "required_privileges": {"value": "root"}
                    },
                    "architecture_assessment": "target_architecture_documented_in_local_metadata",
                    "target_architecture": {"value": "x86_64"},
                },
            }],
        }]
        html = render_html_report(findings, target="127.0.0.1")
        self.assertIn("required_privileges: root", html)
        self.assertIn("x86_64", html)

    def test_report_renders_normalized_documented_requirements(self):
        findings = [{
            "host": "127.0.0.1", "port": 22,
            "service": {"name": "ssh"},
            "searchsploit_assessment": [{"id": "779", "title": "Example"}],
            "exploit_intelligence": [{
                "reference": {"id": "779"},
                "applicability_evidence": {
                    "requirements_assessment": "documented_in_local_metadata",
                    "normalized_requirements": {
                        "authentication_required": {"status": "yes", "raw_value": "yes"},
                        "required_privileges": {"level": "elevated", "raw_value": "root"},
                        "user_interaction": {"status": "unknown", "raw_value": "maybe"},
                    },
                },
            }],
        }]
        html = render_html_report(findings)
        self.assertIn("authentication_required=yes", html)
        self.assertIn("required_privileges=elevated", html)
        self.assertNotIn("user_interaction=unknown", html)

    def test_report_renders_platform_compatibility_column(self):
        findings = self.sample()
        findings[0]["searchsploit_assessment"] = [{
            "id": "123", "title": "Example exploit", "platform": "windows",
            "assessment": {"relevance": "product_match_version_unconfirmed", "confidence": "low"},
        }]
        findings[0]["exploit_intelligence"] = [{
            "reference": {"id": "123"},
            "platform_compatibility": {"status": "platform_mismatch_candidate"},
            "applicability_evidence": {
                "requirements_assessment": "unknown_not_inferred_from_exploit_title",
                "architecture_assessment": "unknown_not_inferred_from_platform_label",
            },
            "triage": {"status": "manual_cve_correlation_required"},
            "cve_correlation": {"status": "no_explicit_cve_link"},
        }]
        html = render_html_report(findings)
        self.assertIn("Platform compatibility", html)
        self.assertIn("platform_mismatch_candidate", html)
        self.assertIn("Requirements / architecture", html)
        self.assertIn("unknown_not_inferred_from_exploit_title", html)

    def test_report_shows_contextual_cve_constraints_and_exploit_triage(self):
        findings = self.sample()
        findings[0]["cve_assessment"][0]["applicability"] = {
            "status": "candidate_unverified", "confidence": "low",
            "cpe_version_status": "version_match",
            "contextual_constraint": {
                "kind": "build_provenance",
                "condition": "Verify package build provenance before confirming impact.",
            },
        }
        findings[0]["exploit_intelligence"] = [{
            "reference": {"id": "12345"},
            "triage": {"status": "cve_candidate_unverified"},
            "cve_correlation": {
                "status": "explicit_cve_match_applicability_unverified",
                "matched_scanner_cve_ids": ["CVE-2099-0001"],
            },
        }]
        html = render_html_report(findings)
        self.assertIn("build_provenance", html)
        self.assertIn("Verify package build provenance", html)
        self.assertIn("cve_candidate_unverified", html)
        self.assertIn("explicit_cve_match_applicability_unverified", html)

    def test_untrusted_values_are_escaped(self):
        html = render_html_report(self.sample())
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)

    def test_empty_report_has_helpful_placeholders(self):
        html = render_html_report([], target="empty-lab")
        self.assertIn("No open services recorded.", html)
        self.assertIn("No CVE results recorded.", html)
        self.assertIn("No matching Exploit-DB entries recorded.", html)

    def test_cli_renders_versioned_json_report_envelope(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "scan.json"
            output = Path(temp_dir) / "scan.html"
            payload = {
                "schema_version": "1.8",
                "metadata": {"requested_target": "lab-envelope.local"},
                "summary": {"open_services": 1},
                "findings": self.sample(),
            }
            source.write_text(json.dumps(payload), encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source), "--output", str(output)]):
                report_main()
            html = output.read_text(encoding="utf-8")
            self.assertIn("lab-envelope.local", html)
            self.assertIn("CVE-2099-0001", html)

    def test_cli_rejects_non_object_metadata_in_report_envelope(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "invalid.json"
            source.write_text(json.dumps({"metadata": "not-an-object", "findings": []}), encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source)]):
                with self.assertRaises(SystemExit) as raised:
                    report_main()
            self.assertEqual(raised.exception.code, 2)

    def test_cli_keeps_legacy_list_json_compatibility(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "legacy.json"
            output = Path(temp_dir) / "legacy.html"
            source.write_text(json.dumps(self.sample()), encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source), "--output", str(output)]):
                report_main()
            self.assertTrue(output.exists())

    def test_write_html_report_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "reports" / "scan.html"
            written = write_html_report(self.sample(), path, target="127.0.0.1")
            self.assertTrue(written.exists())
            self.assertIn("Network Scan Report", written.read_text(encoding="utf-8"))


    def test_report_renders_explicit_cve_correlation_and_related_references(self):
        findings = self.sample()
        findings[0]["searchsploit_assessment"] = [{
            "id": "100", "title": "Example CVE-2099-0001", "platform": "Linux",
            "assessment": {"relevance": "product_match_version_unconfirmed"},
        }]
        findings[0]["exploit_intelligence"] = [{
            "reference": {"id": "100"},
            "triage": {"status": "manual_review_required", "applicability_confidence": "low",
                       "exploitability_confidence": "unknown"},
            "cve_correlation": {
                "status": "explicit_title_and_scanner_match",
                "matched_scanner_cve_ids": ["CVE-2099-0001"],
                "link_confidence": "high_for_identifier_link_only",
                "related_exploit_db_ids": ["200", "300"],
                "duplicate_observations": [{"title": "alternate title"}],
            },
        }]
        html = render_html_report(findings)
        self.assertIn("Explicit-ID link confidence: high_for_identifier_link_only", html)
        self.assertIn("Related EDB references: 200, 300", html)
        self.assertIn("Duplicate search observations: 1", html)

    def test_report_renders_confidence_reasons_and_evidence_gaps(self):
        findings = self.sample()
        findings[0]["cve_assessment"][0]["applicability"].update({
            "applicability_confidence": "medium",
            "exploitability_confidence": "unknown",
            "evidence_sources": ["NVD CPE data", "Nmap identification"],
            "confidence_reasons": ["Exact CPE version matched."],
            "evidence_gaps": ["Vendor backport status is unknown."],
        })
        findings[0]["searchsploit_assessment"] = [{
            "id": "321", "title": "Example exploit", "platform": "Linux",
            "assessment": {"relevance": "product_and_version_match", "confidence": "low"},
        }]
        findings[0]["exploit_intelligence"] = [{
            "reference": {"id": "321"},
            "triage": {
                "status": "manual_review_required",
                "applicability_confidence": "low",
                "exploitability_confidence": "unknown",
                "evidence_sources": ["Local Exploit-DB metadata"],
                "confidence_reasons": ["Title match is not target validation."],
                "evidence_gaps": ["Build provenance is unknown."],
            },
        }]
        html = render_html_report(findings)
        self.assertIn("Applicability confidence: medium; exploitability: unknown", html)
        self.assertIn("NVD CPE data; Nmap identification", html)
        self.assertIn("Local Exploit-DB metadata", html)
        self.assertIn("Exact CPE version matched.", html)
        self.assertIn("Vendor backport status is unknown.", html)
        self.assertIn("Title match is not target validation.", html)
        self.assertIn("Build provenance is unknown.", html)


if __name__ == "__main__":
    unittest.main()
