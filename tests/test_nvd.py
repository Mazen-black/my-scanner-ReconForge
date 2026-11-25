import unittest
from unittest.mock import Mock

from reconforge import nvd


class NVDModuleTests(unittest.TestCase):
    def test_vendor_product_mapping_prefers_known_cpe_identity(self):
        self.assertEqual(nvd._vendor_product("Apache httpd"), "apache:http_server")

    def test_version_candidates_preserve_full_version_and_safe_major_minor(self):
        self.assertEqual(nvd._version_candidates("2.4.57"), ["2.4.57", "2.4"])

    def test_service_lookup_ignores_os_cpe_in_nmap_service_inventory(self):
        fetcher = Mock(return_value={"vulnerabilities": []})
        cves, tried = nvd.check_cve_nvd(
            Mock(),
            {
                "name": "http",
                "product": "Apache httpd",
                "version": "2.4.57",
                "cpe": [
                    "cpe:/o:canonical:ubuntu_linux:22.04",
                    "cpe:/a:apache:http_server:2.4.57",
                ],
            },
            None,
            Mock(),
            10,
            fetcher=fetcher,
        )
        self.assertEqual(cves, [])
        self.assertTrue(tried)
        queried = [
            call.args[1]["virtualMatchString"]
            for call in fetcher.call_args_list
            if "virtualMatchString" in call.args[1]
        ]
        self.assertTrue(all(":o:" not in cpe for cpe in queried))
        self.assertTrue(any(":a:apache:http_server:" in cpe for cpe in queried))

    def test_os_cpe_alone_is_not_misused_as_service_version_evidence(self):
        fetcher = Mock(return_value={"vulnerabilities": []})
        cves, tried = nvd.check_cve_nvd(
            Mock(),
            {
                "name": "unknown-service",
                "version": "22.04",
                "cpe": ["cpe:/o:canonical:ubuntu_linux:22.04"],
            },
            None,
            Mock(),
            10,
            fetcher=fetcher,
        )
        self.assertEqual(cves, [])
        self.assertEqual(tried, [])
        fetcher.assert_not_called()

    def test_distribution_suffix_is_preserved_in_query_candidate(self):
        self.assertEqual(
            nvd._version_candidates("2.4.57-ubuntu1"),
            ["2.4.57-ubuntu1", "2.4"],
        )

    def test_cvss_extraction_prefers_cvss_v31(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.8},
                    "baseSeverity": "HIGH",
                }],
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
            }
        }
        self.assertEqual(nvd._cvss_of(cve), (8.8, "HIGH", "cvssMetricV31"))

    def test_cvss_extraction_rejects_boolean_and_out_of_range_scores(self):
        for invalid in (True, False, -0.1, 10.1, float("nan"), float("inf"), float("-inf"), "9.8"):
            with self.subTest(score=invalid):
                cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": invalid}}]}}
                self.assertEqual(nvd._cvss_of(cve), (None, "", "cvssMetricV31"))

    def test_cvss_extraction_keeps_valid_zero_and_ten(self):
        for score in (0, 10, 0.1, 9.8):
            with self.subTest(score=score):
                cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}}
                self.assertEqual(nvd._cvss_of(cve), (score, "", "cvssMetricV31"))

    def test_cve_lookup_accepts_an_explicit_fetcher(self):
        fetcher = Mock(return_value={"vulnerabilities": []})
        cves, tried = nvd.check_cve_nvd(
            Mock(),
            {"product": "Apache httpd", "name": "http", "version": "2.4.57"},
            None,
            Mock(),
            10,
            fetcher=fetcher,
        )
        self.assertEqual(cves, [])
        self.assertTrue(tried)
        self.assertTrue(fetcher.called)


if __name__ == "__main__":
    unittest.main()
