import tempfile
import unittest
from pathlib import Path

from reconforge.report import render_html_report
from reconforge.summary import summarize_findings


class SummaryAggregationTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {
                "host": "192.0.2.10",
                "port": 22,
                "cve_assessment": [{"id": "CVE-2099-0001"}, {"id": "CVE-2099-0002"}],
                "searchsploit_assessment": [{"id": "EDB-1"}],
                "exploit_intelligence": [{"reference": {"id": "EDB-1"}}],
                "network_exposure": [{"type": "database_exposed"}],
                "risk_assessment": {"score": 61.0},
                "remediation_guidance": {"mode": "guidance_only"},
            },
            {
                "host": "192.0.2.10",
                "port": 80,
                "cve_assessment": [],
                "searchsploit_assessment": [],
                "exploit_intelligence": [],
                "network_exposure": [],
                "risk_assessment": {"score": None},
            },
        ]

    def test_summary_counts_services_and_evidence_consistently(self):
        actual = summarize_findings(self.findings, hosts=["192.0.2.10", "192.0.2.11"])
        for host in actual["host_risk_summary"]:
            host.pop("cve_evidence")
        self.assertEqual(actual, {
            "hosts_scanned": 2,
            "open_services": 2,
            "cve_candidates": 2,
            "unique_host_cves": 2,
            "cross_service_cves": 0,
            "duplicate_cve_observations": 0,
            "hosts_with_cves": 1,
            "exploit_references": 1,
            "exploit_intelligence_references": 1,
            "network_exposure_observations": 1,
            "risk_scored_services": 1,
            "remediation_guidance_services": 1,
            "host_risk_summary": [{
                "host": "192.0.2.10", "services": 2, "ports": ["22", "80"],
                "unique_cves": ["CVE-2099-0001", "CVE-2099-0002"],
                "highest_review_priority_score": 61.0, "highest_review_priority": "Unspecified",
                "unique_cve_count": 2, "cross_service_cves": [], "duplicate_cve_observations": 0,
            }, {
                "host": "192.0.2.11", "services": 0, "ports": [], "unique_cves": [],
                "highest_review_priority_score": None, "highest_review_priority": "Unscored",
                "unique_cve_count": 0, "cross_service_cves": [], "duplicate_cve_observations": 0,
            }],
        })

    def test_summary_falls_back_to_unique_hosts_in_legacy_findings(self):
        self.assertEqual(summarize_findings(self.findings)["hosts_scanned"], 1)

    def test_html_dashboard_uses_canonical_summary_counts(self):
        html = render_html_report(self.findings, hosts=["192.0.2.10", "192.0.2.11"])
        for label, value in (
            ("Hosts scanned", 2),
            ("Open services", 2),
            ("CVE observations", 2),
            ("Unique CVE candidates per host", 2),
            ("Candidates on multiple services", 0),
            ("Duplicate candidate observations", 0),
            ("Exploit references", 1),
            ("Exploit intelligence references", 1),
            ("Network exposure observations", 1),
            ("Risk-scored services", 1),
            ("Services with remediation guidance", 1),
        ):
            self.assertIn(f"{label}</div><div class=\"metric\">{value}</div>", html)

    def test_same_cve_on_multiple_services_is_deduplicated_per_host(self):
        findings = [
            {"host": "192.0.2.10", "port": 22, "cve_assessment": [{"id": "CVE-2025-1234"}], "risk_assessment": {"score": 55, "priority": "Medium"}},
            {"host": "192.0.2.10", "port": 80, "cve_assessment": [{"id": "cve-2025-1234"}, {"id": "CVE-2025-5678"}], "risk_assessment": {"score": 82, "priority": "High"}},
            {"host": "192.0.2.11", "port": 443, "cve_assessment": [{"id": "CVE-2025-1234"}], "risk_assessment": {"score": 101, "priority": "Critical"}},
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["cve_candidates"], 4)
        self.assertEqual(summary["unique_host_cves"], 3)
        self.assertEqual(summary["cross_service_cves"], 1)
        self.assertEqual(summary["duplicate_cve_observations"], 1)
        first, second = summary["host_risk_summary"]
        self.assertEqual(first["unique_cves"], ["CVE-2025-1234", "CVE-2025-5678"])
        self.assertEqual(first["cross_service_cves"], ["CVE-2025-1234"])
        self.assertEqual(first["highest_review_priority_score"], 82.0)
        self.assertEqual(second["unique_cve_count"], 1)
        self.assertIsNone(second["highest_review_priority_score"])


    def test_host_cve_evidence_retains_each_service_and_mixed_applicability(self):
        findings = [
            {"host": "192.0.2.10", "port": 21,
             "service": {"name": "ftp", "product": "vsftpd", "version": "2.3.4"},
             "cve_assessment": [{"id": "CVE-2025-1234", "cvss": 9.8,
                                 "applicability": {"status": "version_match"}}],
             "risk_assessment": {"score": 98.0, "level": "Critical"}},
            {"host": "192.0.2.10", "port": 2121,
             "service": {"name": "ftp-alt", "product": "vsftpd", "version": "unknown"},
             "cve_assessment": [{"id": "CVE-2025-1234", "cvss": 9.8,
                                 "applicability": {"status": "candidate_unverified"}}],
             "risk_assessment": {"score": 63.7, "level": "Medium"}},
        ]
        host = summarize_findings(findings)["host_risk_summary"][0]
        self.assertEqual(host["unique_cve_count"], 1)
        self.assertEqual(host["cross_service_cves"], ["CVE-2025-1234"])
        evidence = host["cve_evidence"][0]
        self.assertEqual(evidence["cve_id"], "CVE-2025-1234")
        observations = evidence["service_observations"]
        self.assertEqual([item["port"] for item in observations], ["21", "2121"])
        self.assertEqual(observations[0]["applicability_statuses"], ["version_match"])
        self.assertEqual(observations[1]["applicability_statuses"], ["candidate_unverified"])
        self.assertEqual(observations[0]["cvss_base_scores"], [9.8])
        self.assertEqual(host["highest_review_priority_score"], 98.0)

    def test_dashboard_displays_cross_service_applicability_per_port(self):
        html = render_html_report([
            {"host": "192.0.2.10", "port": 21, "service": {"name": "ftp"},
             "cve_assessment": [{"id": "CVE-2025-1234", "applicability": {"status": "version_match"}}]},
            {"host": "192.0.2.10", "port": 2121, "service": {"name": "ftp-alt"},
             "cve_assessment": [{"id": "CVE-2025-1234", "applicability": {"status": "candidate_unverified"}}]},
        ])
        self.assertIn("port 21 ftp [version_match]", html)
        self.assertIn("port 2121 ftp-alt [candidate_unverified]", html)
        self.assertIn("mixed states are not collapsed", html)

    def test_host_summary_uses_risk_level_when_priority_field_is_absent(self):
        summary = summarize_findings([{
            "host": "192.0.2.10", "port": 21,
            "risk_assessment": {"score": 74.0, "level": "High"},
        }])
        self.assertEqual(summary["host_risk_summary"][0]["highest_review_priority"], "High")

    def test_duplicate_cve_rows_on_one_service_are_not_cross_service(self):
        summary = summarize_findings([{
            "host": "192.0.2.10", "port": 443,
            "cve_assessment": [{"id": "CVE-2025-1234"}, {"id": "CVE-2025-1234"}],
        }])
        self.assertEqual(summary["unique_host_cves"], 1)
        self.assertEqual(summary["cross_service_cves"], 0)
        self.assertEqual(summary["duplicate_cve_observations"], 0)

    def test_malformed_cve_records_and_findings_are_ignored_safely(self):
        summary = summarize_findings([
            None,
            {"host": "192.0.2.10", "port": 80, "cve_assessment": [None, {}, {"id": "not-a-cve"}, {"id": "CVE-2025-1234"}], "risk_assessment": {"score": True}},
        ])
        self.assertEqual(summary["cve_candidates"], 4)
        self.assertEqual(summary["unique_host_cves"], 1)
        self.assertEqual(summary["risk_scored_services"], 0)

    def test_huge_integer_risk_score_is_safely_unscored(self):
        summary = summarize_findings([{
            "host": "192.0.2.10", "port": 443,
            "risk_assessment": {"score": 10 ** 10000, "priority": "Critical"},
        }])
        self.assertEqual(summary["risk_scored_services"], 0)
        self.assertIsNone(summary["host_risk_summary"][0]["highest_review_priority_score"])

    def test_dashboard_renders_host_level_correlation_and_escapes_host(self):
        html = render_html_report([
            {"host": "<script>host</script>", "port": 22, "cve_assessment": [{"id": "CVE-2025-1234"}], "risk_assessment": {"score": 72, "priority": "High"}},
            {"host": "<script>host</script>", "port": 443, "cve_assessment": [{"id": "CVE-2025-1234"}]},
        ])
        self.assertIn("Host-Level Risk & CVE Correlation", html)
        self.assertIn("CVE-2025-1234", html)
        self.assertIn("&lt;script&gt;host&lt;/script&gt;", html)
        self.assertNotIn("<script>host</script>", html)


if __name__ == "__main__":
    unittest.main()
