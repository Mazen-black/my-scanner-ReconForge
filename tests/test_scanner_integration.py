import unittest
from unittest.mock import patch

import scanner


class InputValidationTests(unittest.TestCase):
    def test_accepts_ip_hostname_and_cidr(self):
        self.assertEqual(scanner.validate_target("192.0.2.10"), "192.0.2.10")
        self.assertEqual(scanner.validate_target("lab.example.org"), "lab.example.org")
        self.assertEqual(scanner.validate_target("192.0.2.0/24"), "192.0.2.0/24")

    def test_rejects_url_shell_and_option_like_targets(self):
        for target in ("https://example.org", "-Pn", "host;id", "host name"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    scanner.validate_target(target)

    def test_validates_port_lists_and_ranges(self):
        self.assertEqual(scanner.validate_ports("22,80,443,8000-8100"), "22,80,443,8000-8100")
        for ports in ("0", "65536", "80-", "90-80", "22;id", "1,,2"):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    scanner.validate_ports(ports)

    def test_nmap_arguments_are_shell_quoted(self):
        normalized = scanner.normalize_nmap_args('-sV --script "safe script"')
        self.assertIn("-sV", normalized)
        self.assertIn("'safe script'", normalized)
        with self.assertRaises(ValueError):
            scanner.normalize_nmap_args('"unterminated')

    def test_scanned_hosts_uses_resolved_hosts_not_input_hostname(self):
        class FakeScanner:
            def all_hosts(self):
                return ["203.0.113.8"]
        self.assertEqual(scanner.scanned_hosts(FakeScanner()), ["203.0.113.8"])

    def test_empty_scan_result_is_reported(self):
        class FakeScanner:
            def all_hosts(self):
                return []
        with self.assertRaises(RuntimeError):
            scanner.scanned_hosts(FakeScanner())


class CheckCVEIntegrationTests(unittest.TestCase):
    @patch("scanner.nvd_fetch")
    def test_nvd_result_is_assessed_against_detected_version(self, mock_fetch):
        mock_fetch.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-12345",
                    "published": "2099-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Synthetic test CVE"}],
                    "metrics": {},
                    "configurations": [{
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*",
                            }],
                        }]
                    }],
                }
            }]
        }
        cves, tried = scanner.check_cve_nvd(
            session=None,
            port_data={"name": "http", "product": "Apache httpd", "version": "2.4.57", "cpe": []},
            api_key=None,
            limiter=None,
            results_per_page=10,
        )
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["applicability"]["status"], "version_match")
        self.assertEqual(cves[0]["applicability"]["evidence"][0]["reason"], "exact_version")
        self.assertNotIn("configurations", cves[0])
        self.assertTrue(tried)
        self.assertEqual(mock_fetch.call_count, 2)


class HTTPProbeTests(unittest.TestCase):
    @patch("scanner.requests.head")
    def test_http_probe_does_not_follow_redirects(self, mock_head):
        class FakeHeaders(dict):
            def getlist(self, name):
                return []
        class FakeResponse:
            status_code = 302
            headers = {"Location": "https://redirect.invalid/"}
            raw = type("Raw", (), {"headers": FakeHeaders()})()
        mock_head.return_value = FakeResponse()
        result = scanner.probe_http_metadata("192.0.2.10", 80, {"name": "http"})
        self.assertEqual(result["status"], "response_received")
        self.assertTrue(result["redirect_location_present"])
        self.assertFalse(mock_head.call_args.kwargs["allow_redirects"])
        self.assertTrue(mock_head.call_args.kwargs["verify"])

    @patch("scanner.requests.head")
    def test_http_probe_skips_non_http_service(self, mock_head):
        result = scanner.probe_http_metadata("192.0.2.10", 22, {"name": "ssh"})
        self.assertEqual(result["status"], "skipped")
        mock_head.assert_not_called()

    @patch("scanner.requests.head")
    def test_http_probe_does_not_disable_tls_verification(self, mock_head):
        import requests
        mock_head.side_effect = requests.exceptions.SSLError()
        result = scanner.probe_http_metadata("192.0.2.10", 443, {"name": "https"})
        self.assertEqual(result["error"], "tls_validation_failed")
        self.assertTrue(mock_head.call_args.kwargs["verify"])


class WebIntelligenceProbeTests(unittest.TestCase):
    @patch("scanner._bounded_same_origin_get")
    def test_web_intel_fetches_only_three_fixed_same_origin_paths(self, mock_get):
        mock_get.side_effect = [
            ('<meta name="generator" content="Joomla 4.2">', None),
            ("User-agent: *\nDisallow: /admin", None),
            ("<urlset><url><loc>https://lab.test/</loc></url></urlset>", None),
        ]
        result = scanner.probe_web_intelligence("192.0.2.20", 8080, {"name": "http"})
        self.assertEqual(result["status"], "response_received")
        self.assertEqual(mock_get.call_args_list[0].args[0], "http://192.0.2.20:8080/")
        self.assertEqual(mock_get.call_args_list[1].args[0], "http://192.0.2.20:8080/robots.txt")
        self.assertEqual(mock_get.call_args_list[2].args[0], "http://192.0.2.20:8080/sitemap.xml")

    @patch("scanner._bounded_same_origin_get")
    def test_web_intel_does_not_continue_after_root_failure(self, mock_get):
        mock_get.return_value = (None, "request_timeout")
        result = scanner.probe_web_intelligence("192.0.2.20", 80, {"name": "http"})
        self.assertEqual(result["status"], "probe_error")
        mock_get.assert_called_once()

    @patch("scanner.requests.get")
    def test_bounded_get_disables_redirects_and_closes_response(self, mock_get):
        class Response:
            status_code = 200
            encoding = "utf-8"
            closed = False
            def iter_content(self, chunk_size):
                yield b"hello"
            def close(self):
                self.closed = True
        response = Response()
        mock_get.return_value = response
        content, error = scanner._bounded_same_origin_get("http://192.0.2.20/", 20)
        self.assertEqual(content, "hello")
        self.assertIsNone(error)
        self.assertFalse(mock_get.call_args.kwargs["allow_redirects"])
        self.assertTrue(mock_get.call_args.kwargs["verify"])
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
