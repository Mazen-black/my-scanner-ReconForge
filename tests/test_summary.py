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
        self.assertEqual(summarize_findings(self.findings, hosts=["192.0.2.10", "192.0.2.11"]), {
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
