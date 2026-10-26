import unittest
from unittest.mock import patch

import scanner


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


if __name__ == "__main__":
    unittest.main()
