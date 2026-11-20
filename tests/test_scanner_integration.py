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

    def test_os_detection_flag_adds_nmap_os_scan(self):
        args = scanner.parse_args(["--target", "192.0.2.10", "--os-detection"])
        self.assertIn("-O", args.nmap_args.split())
        self.assertTrue(args.os_detection)

    def test_os_detection_flag_does_not_duplicate_existing_nmap_option(self):
        args = scanner.parse_args(["--target", "192.0.2.10", "--nmap-args", "-sV -O", "--os-detection"])
        self.assertEqual(args.nmap_args.split().count("-O"), 1)

    def test_os_fingerprint_requires_high_confidence_match(self):
        self.assertEqual(scanner.infer_target_platform([{"name": "Linux 6.x", "accuracy": "98"}]), "linux")
        self.assertIsNone(scanner.infer_target_platform([{"name": "Linux 6.x", "accuracy": "75"}]))
        self.assertIsNone(scanner.infer_target_platform([{"name": "Linux 6.x"}]))
        self.assertIsNone(scanner.infer_target_platform([]))

    def test_os_fingerprint_report_preserves_match_and_confidence(self):
        evidence = scanner.build_host_os_fingerprint([{"name": "Linux 6.x", "accuracy": "98"}], requested=True)
        self.assertEqual(evidence["status"], "accepted_high_confidence")
        self.assertEqual(evidence["platform_family"], "linux")
        self.assertEqual(evidence["accuracy"], 98)
        low = scanner.build_host_os_fingerprint([{"name": "Linux 6.x", "accuracy": "75"}], requested=True)
        self.assertEqual(low["status"], "unconfirmed_low_confidence_or_unknown_family")
        self.assertIsNone(low["platform_family"])

    def test_os_fingerprint_maps_supported_families(self):
        cases = {
            "Microsoft Windows Server 2022": "windows",
            "FreeBSD 13.x": "unix",
            "Apple macOS 14": "macos",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(scanner.infer_target_platform([{"name": name, "accuracy": "95"}]), expected)

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

    @patch("scanner.nvd_fetch", return_value={"vulnerabilities": []})
    def test_single_string_nmap_cpe_is_used_as_one_cpe_query(self, mock_fetch):
        scanner.check_cve_nvd(
            session=None,
            port_data={
                "name": "ftp", "product": "vsftpd", "version": "2.3.4",
                "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4",
            },
            api_key=None,
            limiter=None,
            results_per_page=10,
        )
        first_query = mock_fetch.call_args_list[0].args[1]["virtualMatchString"]
        self.assertEqual(
            first_query,
            "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*",
        )


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
        self.assertEqual(
            mock_head.call_args.kwargs["headers"]["User-Agent"],
            f"ReconForge/{scanner.SCANNER_VERSION} (authorized security assessment)",
        )

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
        self.assertEqual(
            mock_get.call_args.kwargs["headers"]["User-Agent"],
            f"ReconForge/{scanner.SCANNER_VERSION} (authorized security assessment)",
        )
        self.assertTrue(response.closed)


class SearchsploitLookupTests(unittest.TestCase):
    def test_extracts_only_allowlisted_metadata_from_local_header(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "exploits"
            root.mkdir()
            source = root / "sample.py"
            source.write_text(
                "# Exploit Title: Example\n"
                "# Target Architecture: x86_64\n"
                "# Required Privileges: root\n"
                "# Authentication Required: no\n"
                "# Notes: ignored\n"
                "#!/usr/bin/python3\n"
                "print('not metadata')\n",
                encoding="utf-8",
            )
            result = scanner.extract_exploit_metadata(str(source), str(root))
            self.assertEqual(result["target_architecture"]["value"], "x86_64")
            self.assertEqual(result["required_privileges"]["value"], "root")
            self.assertEqual(result["authentication_required"]["value"], "no")
            self.assertNotIn("notes", result)

    def test_rejects_paths_outside_exploitdb_root(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "exploits"
            outside = Path(temp) / "outside.py"
            root.mkdir()
            outside.write_text("# Target Architecture: x86\n", encoding="utf-8")
            self.assertEqual(scanner.extract_exploit_metadata(str(outside), str(root)), {})

    def test_stops_at_first_source_statement(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "exploits"
            root.mkdir()
            source = root / "sample.py"
            source.write_text(
                "# Exploit Title: Example\n"
                "# Target Architecture: x86\n"
                "import os\n"
                "# Required Privileges: root\n",
                encoding="utf-8",
            )
            result = scanner.extract_exploit_metadata(str(source), str(root))
            self.assertIn("target_architecture", result)
            self.assertNotIn("required_privileges", result)

    @patch("scanner.subprocess.run")
    @patch("scanner.shutil.which", return_value="/usr/bin/searchsploit")
    def test_missing_product_skips_searchsploit_command(self, mock_which, mock_run):
        self.assertEqual(scanner.searchsploit_lookup("", "1.0"), [])
        mock_run.assert_not_called()


class IntegratedAssessmentTests(unittest.TestCase):
    def test_cli_exposes_offline_html_and_asset_context_options(self):
        args = scanner.parse_args([
            "--target", "192.0.2.10", "--no-nvd", "--html-output", "scan.html",
            "--asset-criticality", "critical", "--exposure", "internet",
        ])
        self.assertTrue(args.no_nvd)
        self.assertEqual(args.html_output, "scan.html")
        self.assertEqual(args.asset_criticality, "critical")
        self.assertEqual(args.exposure, "internet")

    @patch("scanner.write_html_report")
    @patch("scanner.write_json_report")
    @patch("scanner.searchsploit_lookup")
    @patch("scanner.check_cve_nvd")
    @patch("scanner.nmap.PortScanner")
    @patch("scanner.requests.Session")
    @patch("scanner.parse_args")
    def test_no_nvd_mode_builds_json_and_html_without_network_lookup(
        self, mock_args, mock_session, mock_port_scanner, mock_cve_lookup,
        mock_searchsploit, mock_write_json, mock_write_html
    ):
        from argparse import Namespace
        mock_args.return_value = Namespace(
            target="127.0.0.1", ports="21", nmap_args="-sV",
            results_per_page=10, nvd_api_key=None, no_exploitdb=True,
            no_nvd=True, http_probe=False, web_intel=False,
            output="offline.json", html_output="offline.html",
            asset_criticality="high", exposure="internal",
        )
        class FakeScanner:
            def scan(self, target, ports, arguments):
                self.scan_args = (target, ports, arguments)
            def all_hosts(self):
                return ["127.0.0.1"]
            def __getitem__(self, host):
                return {"tcp": {21: {
                    "state": "open", "name": "ftp", "product": "vsftpd",
                    "version": "3.0.5", "cpe": [], "extrainfo": "",
                    "tunnel": "", "method": "probed", "conf": "10",
                }}}
        mock_port_scanner.return_value = FakeScanner()
        captured = {}
        mock_write_json.side_effect = lambda filename, payload: captured.update(payload)
        mock_write_html.return_value = "offline.html"

        scanner.main()

        mock_cve_lookup.assert_not_called()
        mock_searchsploit.assert_not_called()
        self.assertEqual(captured["findings"][0]["cve_assessment"], [])
        self.assertIsNone(captured["findings"][0]["risk_assessment"]["score"])
        self.assertEqual(captured["findings"][0]["risk_assessment"]["asset_context"]["asset_criticality"], "high")
        self.assertEqual(captured["findings"][0]["remediation_guidance"]["mode"], "guidance_only")
        mock_write_html.assert_called_once()
        self.assertEqual(mock_write_html.call_args.args[0][0]["port"], 21)



if __name__ == "__main__":
    unittest.main()



class ScannerExploitIntelligenceIntegrationTests(unittest.TestCase):
    @patch("scanner.write_json_report")
    @patch("scanner.searchsploit_lookup")
    @patch("scanner.check_cve_nvd")
    @patch("scanner.nmap.PortScanner")
    @patch("scanner.requests.Session")
    @patch("scanner.parse_args")
    def test_main_includes_exploit_intelligence_in_final_report(
        self, mock_args, mock_session, mock_port_scanner, mock_cve_lookup,
        mock_searchsploit, mock_write_report
    ):
        from argparse import Namespace

        mock_args.return_value = Namespace(
            target="127.0.0.1", ports="22", nmap_args="-sV", os_detection=False,
            results_per_page=10, nvd_api_key=None, no_exploitdb=False,
            http_probe=False, web_intel=False, output="report.json",
            no_nvd=False, asset_criticality="unknown", exposure="unknown",
            html_output=None,
        )
        mock_session.return_value = object()
        mock_cve_lookup.return_value = (
            [{"id": "CVE-2024-12345", "cvss": 8.8, "severity": "HIGH"}], []
        )
        mock_searchsploit.return_value = [{
            "id": "12345",
            "title": "OpenSSH CVE-2024-12345",
            "type": "remote",
            "platform": "linux",
            "assessment": {"relevance": "product_match_version_unconfirmed"},
        }]

        class FakeHost:
            def all_tcp(self):
                return [22]

        class FakeScanner:
            def scan(self, target, ports, arguments):
                self.asserted_scan = (target, ports, arguments)

            def all_hosts(self):
                return ["127.0.0.1"]

            def __getitem__(self, host):
                return {
                    "tcp": {
                        22: {
                            "state": "open", "name": "ssh",
                            "product": "OpenSSH", "version": "9.0",
                            "cpe": [], "extrainfo": "", "tunnel": "",
                            "method": "probed", "conf": "10",
                        }
                    },
                    "osmatch": [{"name": "Linux 5.x", "accuracy": "98"}],
                }

        mock_port_scanner.return_value = FakeScanner()
        captured = {}
        mock_write_report.side_effect = lambda filename, report: captured.update(report)

        scanner.main()

        finding = captured["findings"][0]
        self.assertEqual(
            finding["exploit_intelligence"][0]["reference"]["url"],
            "https://www.exploit-db.com/exploits/12345",
        )
        self.assertEqual(
            finding["exploit_intelligence"][0]["cve_correlation"]["matched_scanner_cve_ids"],
            ["CVE-2024-12345"],
        )
        self.assertEqual(finding["exploit_intelligence"][0]["execution_status"], "not_executed")
        self.assertEqual(finding["exploit_intelligence"][0]["platform_compatibility"]["status"], "platform_family_match")
        self.assertFalse(captured["metadata"]["os_detection_requested"])
        self.assertEqual(finding["host_os_fingerprint"]["platform_family"], "linux")
        self.assertEqual(finding["host_os_fingerprint"]["accuracy"], 98)
        self.assertEqual(finding["risk_assessment"]["score"], 57.2)
        self.assertEqual(finding["risk_assessment"]["asset_context"]["contextual_priority_score"], 57.2)
        self.assertEqual(finding["remediation_guidance"]["mode"], "guidance_only")
        self.assertEqual(captured["summary"]["risk_scored_services"], 1)
        self.assertEqual(captured["summary"]["exploit_intelligence_references"], 1)
