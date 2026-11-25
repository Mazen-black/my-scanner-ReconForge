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
            "exploit_references": 1,
            "exploit_intelligence_references": 1,
            "network_exposure_observations": 1,
            "risk_scored_services": 1,
            "remediation_guidance_services": 1,
        })

    def test_summary_falls_back_to_unique_hosts_in_legacy_findings(self):
        self.assertEqual(summarize_findings(self.findings)["hosts_scanned"], 1)

    def test_html_dashboard_uses_canonical_summary_counts(self):
        html = render_html_report(self.findings, hosts=["192.0.2.10", "192.0.2.11"])
        for label, value in (
            ("Hosts scanned", 2),
            ("Open services", 2),
            ("CVE references", 2),
            ("Exploit references", 1),
            ("Exploit intelligence references", 1),
            ("Network exposure observations", 1),
            ("Risk-scored services", 1),
            ("Services with remediation guidance", 1),
        ):
            self.assertIn(f"{label}</div><div class=\"metric\">{value}</div>", html)


if __name__ == "__main__":
    unittest.main()
