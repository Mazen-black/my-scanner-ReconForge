import tempfile
import unittest
from pathlib import Path

from report import render_html_report, write_html_report


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

    def test_write_html_report_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "reports" / "scan.html"
            written = write_html_report(self.sample(), path, target="127.0.0.1")
            self.assertTrue(written.exists())
            self.assertIn("Network Scan Report", written.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
