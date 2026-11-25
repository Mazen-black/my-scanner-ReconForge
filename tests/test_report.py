import json
import sys
import tempfile
import unittest
import unittest.mock
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
        self.assertIn("Host OS Fingerprint", html)
        self.assertIn("Linux 2.6.9 - 2.6.33 &lt;test&gt; (100%)", html)
        self.assertIn("Linux 2.6.9 - 2.6.33 &lt;test&gt;", html)
        self.assertIn("90%", html)
        self.assertIn("Hosts with accepted OS match", html)
        self.assertNotIn("Linux 2.6.9 - 2.6.33 <test>", html)

    def test_os_fingerprint_table_deduplicates_hosts_and_keeps_unknowns(self):
        findings = self.sample()
        findings[0]["host_os_fingerprint"] = {
            "status": "accepted_high_confidence", "platform_family": "linux",
            "nmap_name": "Linux Server", "accuracy": 98, "minimum_accuracy": 90,
        }
        second_service = dict(findings[0])
        second_service["port"] = 8080
        second_service["host_os_fingerprint"] = dict(findings[0]["host_os_fingerprint"])
        unknown_host = dict(findings[0])
        unknown_host["host"] = "192.0.2.20"
        unknown_host["host_os_fingerprint"] = {
            "status": "no_match", "platform_family": None, "nmap_name": None,
            "accuracy": None, "minimum_accuracy": 90,
        }
        html = render_html_report([findings[0], second_service, unknown_host])
        self.assertEqual(html.count("<td>127.0.0.1</td><td>Linux Server</td>"), 1)
        self.assertIn("<td>192.0.2.20</td><td>No OS match returned</td>", html)
        self.assertIn("accepted_high_confidence", html)
        self.assertIn("no_match", html)

    def test_os_fingerprint_section_has_placeholder_when_not_recorded(self):
        html = render_html_report(self.sample())
        self.assertIn("No host OS fingerprint data recorded.", html)

    def test_report_preserves_risk_scores_on_zero_to_one_hundred_scale(self):
        findings = self.sample()
        findings[0]["risk_assessment"] = {
            "score": 57.2, "level": "Medium", "top_cve": "CVE-2099-0001",
            "asset_context": {"contextual_priority_score": 64.5, "contextual_priority": "Medium"},
        }
        findings[0]["cve_assessment"][0]["risk_priority"] = {
            "priority": "Medium", "priority_score": 57.2,
        }
        html = render_html_report(findings)
        self.assertIn('<td class="numeric">57.2</td>', html)
        self.assertIn('(64.5)', html)

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

    def test_remediation_dashboard_renders_escaped_evidence_provenance(self):
        findings = [{
            "host": "192.0.2.10", "port": 80,
            "service": {"name": "http", "product": "Apache", "version": "2.2.8"},
            "remediation_guidance": {
                "mode": "guidance_only",
                "service_guidance": {
                    "title": "Review web service", "priority": "medium", "confidence": "medium",
                    "reason": "Service-family heuristic", "actions": [], "verification": [],
                    "evidence": {"host": "192.0.2.10", "port": 80, "product": "<Apache>"},
                },
                "cve_guidance": [{
                    "title": "Validate CVE-2099-4", "priority": "High", "applicability": "version_match",
                    "confidence": "medium", "actions": [], "verification": [],
                    "evidence": {"cve_id": "CVE-2099-4", "matched_criteria": ["cpe:2.3:a:vendor:product"]},
                }],
            },
        }]
        html = render_html_report(findings)
        self.assertIn("192.0.2.10", html)
        self.assertIn("CVE-2099-4", html)
        self.assertIn("&lt;Apache&gt;", html)
        self.assertNotIn('"product": "<Apache>"', html)

    def test_dashboard_explains_technical_and_contextual_risk_factors(self):
        findings = [{
            "host": "192.0.2.20", "port": 443,
            "service": {"name": "https", "product": "Example", "version": "1.0"},
            "cve_assessment": [{
                "id": "CVE-2099-9", "cvss": 8.0, "severity": "HIGH",
                "applicability": {"status": "candidate_unverified"},
                "risk_priority": {
                    "priority": "Medium", "priority_score": 52.0,
                    "applicability_factor": 0.65,
                    "factor_explanation": "Discounted factor: applicability remains unverified.",
                },
            }],
            "risk_assessment": {
                "score": 52.0, "level": "Medium", "top_cve": "CVE-2099-9",
                "model": "ReconForge-RP1", "notes": ["Review priority is not proof of exploitability."],
                "asset_context": {
                    "contextual_priority_score": 59.8, "contextual_priority": "Medium",
                    "asset_criticality": "high", "network_exposure": "internet",
                    "criticality_factor": 1.15, "exposure_factor": 1.0,
                },
            },
        }]
        html = render_html_report(findings)
        self.assertIn("Factor: 0.65", html)
        self.assertIn("Discounted factor", html)
        self.assertIn("criticality ×1.15", html)
        self.assertIn("exposure ×1.0", html)
        self.assertIn("Review priority is not proof of exploitability", html)

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

    def test_invalid_cvss_values_are_not_rendered_as_severity_or_scores(self):
        for invalid_score in (True, False, -0.1, 10.1, float("nan"), float("inf"), 10 ** 10000):
            with self.subTest(cvss=invalid_score):
                findings = self.sample()
                findings[0]["cve_assessment"][0]["cvss"] = invalid_score
                findings[0]["cve_assessment"][0].pop("severity", None)
                html = render_html_report(findings)
                self.assertIn('class="severity unknown">Unknown</span>', html)
                self.assertIn('<td class="numeric">N/A</td>', html)
                self.assertIn('<div class="muted">High / Critical CVEs</div><div class="metric">0</div>', html)

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

    def test_cli_renders_host_os_metadata_when_host_has_no_open_services(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "host-only.json"
            output = Path(temp_dir) / "host-only.html"
            payload = {
                "schema_version": "1.16",
                "metadata": {
                    "requested_target": "lab-with-filtered-ports.local",
                    "host_os_fingerprints": [{
                        "host": "192.0.2.30", "status": "accepted_high_confidence",
                        "platform_family": "linux", "nmap_name": "Linux 5.x",
                        "accuracy": 98, "minimum_accuracy": 90,
                        "source": "Nmap OS detection",
                    }],
                },
                "findings": [],
            }
            source.write_text(json.dumps(payload), encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source), "--output", str(output)]):
                report_main()
            html = output.read_text(encoding="utf-8")
            self.assertIn("192.0.2.30", html)
            self.assertIn("Linux 5.x", html)
            self.assertIn("98%", html)
            self.assertIn("Hosts with accepted OS match", html)
            self.assertIn(">1</div>", html)

    def test_report_uses_cvss_score_not_inconsistent_severity_label(self):
        findings = self.sample()
        findings[0]["cve_assessment"][0]["cvss"] = 9.8
        findings[0]["cve_assessment"][0]["severity"] = "LOW"
        html = render_html_report(findings)
        self.assertIn('<span class="severity critical">Critical</span>', html)
        self.assertNotIn('<span class="severity low">Low</span>', html)

    def test_cli_rejects_malformed_or_unsupported_schema_versions(self):
        invalid_versions = ("latest", "1", "2.0", "1.17", "1.x")
        for version in invalid_versions:
            with self.subTest(schema_version=version), tempfile.TemporaryDirectory() as temp_dir:
                source = Path(temp_dir) / "future.json"
                source.write_text(json.dumps({"schema_version": version, "metadata": {}, "findings": []}), encoding="utf-8")
                with unittest.mock.patch.object(sys, "argv", ["report.py", str(source)]):
                    with self.assertRaises(SystemExit) as raised:
                        report_main()
                self.assertEqual(raised.exception.code, 2)

    def test_cli_accepts_legacy_envelope_without_schema_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "legacy-envelope.json"
            output = Path(temp_dir) / "legacy-envelope.html"
            source.write_text(json.dumps({"metadata": {"requested_target": "old.local"}, "findings": []}), encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source), "--output", str(output)]):
                report_main()
            self.assertIn("old.local", output.read_text(encoding="utf-8"))

    def test_cli_reports_malformed_json_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "broken.json"
            source.write_text('{"schema_version":', encoding="utf-8")
            with unittest.mock.patch.object(sys, "argv", ["report.py", str(source)]):
                with self.assertRaises(SystemExit) as raised:
                    report_main()
            self.assertEqual(raised.exception.code, 2)

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
                "duplicate_observations": [{
                    "title": "alternate title",
                    "metadata_variants": {"local_metadata": {"architecture": "x86_64"}},
                }],
            },
        }]
        html = render_html_report(findings)
        self.assertIn("Explicit-ID link confidence: high_for_identifier_link_only", html)
        self.assertIn("Related EDB references: 200, 300", html)
        self.assertIn("Duplicate search observations: 1", html)
        self.assertIn("Conflicting metadata fields: local_metadata", html)

    def test_report_renders_consolidated_evidence_confidence(self):
        findings = self.sample()
        findings[0]["evidence_confidence"] = {
            "service_identity": {"confidence": "high", "nmap_method": "probed", "nmap_confidence": 10,
                                 "reasons": ["Active Nmap probe." ]},
            "cve_applicability": {"confidence": "medium", "counts": {"version_match": 1, "candidate_unverified": 2,
                                     "not_matched_by_nvd_cpe": 0}, "reasons": ["One path matched."]},
            "exploit_reference_linkage": {"confidence": "high_for_identifier_link_only", "explicit_cve_links": 1,
                                          "exploit_references": 2, "reasons": ["Explicit identifier link."]},
            "overall_review_confidence": "medium", "exploitability_confidence": "unknown",
            "overall_reasons": ["Evidence linked."], "overall_evidence_gaps": ["Build provenance unknown."],
        }
        html = render_html_report(findings)
        self.assertIn("Consolidated Evidence Confidence", html)
        self.assertIn("high_for_identifier_link_only", html)
        self.assertIn("Build provenance unknown.", html)
        self.assertIn("Exploitability: unknown", html)

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
