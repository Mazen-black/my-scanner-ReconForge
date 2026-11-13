import unittest
from assessment import assess_cve_applicability, build_report_entry, classify_exploit, cpe22_to_cpe23


class CPEConversionTests(unittest.TestCase):
    def test_cpe22_pads_to_exactly_eleven_attributes(self):
        result = cpe22_to_cpe23("cpe:/a:openbsd:openssh:7.9p1")
        self.assertEqual(result, "cpe:2.3:a:openbsd:openssh:7.9p1:*:*:*:*:*:*:*")
        self.assertEqual(len(result.split(":")), 13)

    def test_cpe23_full_value_is_preserved(self):
        value = "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"
        self.assertEqual(cpe22_to_cpe23(value), value)

    def test_cpe23_short_value_is_padded(self):
        value = cpe22_to_cpe23("cpe:2.3:a:vendor:product:1.2")
        self.assertEqual(value, "cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*")
        self.assertEqual(len(value.split(":")), 13)

    def test_invalid_cpe_returns_none(self):
        self.assertIsNone(cpe22_to_cpe23(""))
        self.assertIsNone(cpe22_to_cpe23("not-a-cpe"))
        self.assertIsNone(cpe22_to_cpe23("cpe:/x:vendor:product:1.0"))


class CVEApplicabilityTests(unittest.TestCase):
    def _match(self, criteria, vulnerable=True, **bounds):
        match = {"vulnerable": vulnerable, "criteria": criteria}
        match.update(bounds)
        return match

    def _cve(self, *matches, operator="OR"):
        return {"configurations": [{"nodes": [{"operator": operator, "cpeMatch": list(matches)}]}]}

    def test_exact_version_match(self):
        cve = self._cve(self._match("cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"))
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")
        self.assertEqual(result["evidence"][0]["reason"], "version_match")

    def test_exact_version_mismatch_is_not_match(self):
        cve = self._cve(self._match("cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*"))
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "not_matched_by_nvd_cpe")

    def test_inclusive_version_range(self):
        cve = self._cve(self._match(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            versionStartIncluding="2.4.0", versionEndExcluding="2.4.58"
        ))
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")

    def test_outside_version_range_is_not_match(self):
        cve = self._cve(self._match(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            versionStartIncluding="2.4.0", versionEndExcluding="2.4.58"
        ))
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.58")
        self.assertEqual(result["status"], "not_matched_by_nvd_cpe")

    def test_non_vulnerable_cpe_is_not_reported_as_vulnerable(self):
        cve = self._cve(self._match(
            "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*", vulnerable=False
        ))
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "candidate_unverified")

    def test_and_with_unknown_environmental_condition_is_unverified(self):
        target = self._match("cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*")
        os_condition = self._match("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")
        cve = self._cve(target, os_condition, operator="AND")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "candidate_unverified")

    def test_or_with_matching_target_branch_is_a_match(self):
        target = self._match("cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*")
        other = self._match("cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*")
        cve = self._cve(target, other, operator="OR")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")

    def test_and_with_target_version_mismatch_is_not_match(self):
        target = self._match("cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*")
        other = self._match("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")
        cve = self._cve(target, other, operator="AND")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "not_matched_by_nvd_cpe")

    def test_nested_and_or_logic(self):
        cve = {"configurations": [{"nodes": [{
            "operator": "AND",
            "cpeMatch": [self._match("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")],
            "children": [{
                "operator": "OR",
                "cpeMatch": [
                    self._match("cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"),
                    self._match("cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*")
                ]
            }]
        }]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "candidate_unverified")


class SearchsploitTests(unittest.TestCase):
    def test_product_and_version_match(self):
        result = classify_exploit({"Title": "Apache httpd 2.4.57 - Example"}, "Apache httpd", "2.4.57")
        self.assertEqual(result["relevance"], "product_and_version_match")

    def test_unrelated_title_is_weak(self):
        result = classify_exploit({"Title": "WordPress plugin SQL Injection"}, "Apache httpd", "2.4.57")
        self.assertEqual(result["relevance"], "weak_or_unrelated")

    def test_report_has_structured_service_and_limits(self):
        report = build_report_entry("127.0.0.1", 80, "open", "http", "Apache httpd", "2.4.57", [], [], [])
        self.assertEqual(report["service"]["version"], "2.4.57")
        self.assertIn("assessment_limits", report)
        self.assertIn("cve_assessment", report)


if __name__ == "__main__":
    unittest.main()
