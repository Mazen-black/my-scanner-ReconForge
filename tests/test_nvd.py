import unittest
from unittest.mock import Mock

from reconforge import nvd


class NVDModuleTests(unittest.TestCase):
    def test_vendor_product_mapping_prefers_known_cpe_identity(self):
        self.assertEqual(nvd._vendor_product("Apache httpd"), "apache:http_server")

    def test_version_candidates_preserve_full_version_and_safe_major_minor(self):
        self.assertEqual(nvd._version_candidates("2.4.57"), ["2.4.57", "2.4"])

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
