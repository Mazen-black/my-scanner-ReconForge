import unittest
from assessment import assess_cve_applicability, build_report_entry, build_technology_fingerprint, classify_exploit, cpe22_to_cpe23


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
    def _cve(self, criteria, **bounds):
        match = {"vulnerable": True, "criteria": criteria}
        match.update(bounds)
        return {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}]}

    def test_exact_version_match(self):
        cve = self._cve("cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")
        self.assertEqual(result["evidence"][0]["reason"], "exact_version")

    def test_exact_version_mismatch_is_not_match(self):
        cve = self._cve("cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertNotEqual(result["status"], "version_match")

    def test_inclusive_version_range(self):
        cve = self._cve("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        versionStartIncluding="2.4.0", versionEndExcluding="2.4.58")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")
        self.assertEqual(result["evidence"][0]["reason"], "version_range_match")

    def test_outside_version_range_is_not_match(self):
        cve = self._cve("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        versionStartIncluding="2.4.0", versionEndExcluding="2.4.58")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.58")
        self.assertNotEqual(result["status"], "version_match")

    def test_non_vulnerable_cpe_match_is_ignored(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": False,
            "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*",
        }]}]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertNotEqual(result["status"], "version_match")


    def test_and_requires_every_environment_component(self):
        cve = {"configurations": [{"nodes": [{"operator": "AND", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"},
        ]}]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "candidate_unverified")
        self.assertEqual(result["evidence"], [])

    def test_or_can_match_one_vulnerable_alternative(self):
        cve = {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*"},
        ]}]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "version_match")
        self.assertEqual(len(result["evidence"]), 1)

    def test_nested_and_child_requirement_is_not_ignored(self):
        cve = {"configurations": [{"nodes": [{"operator": "AND", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"}
        ], "children": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"}
        ]}]}]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "candidate_unverified")

    def test_negated_matching_condition_is_not_positive_evidence(self):
        cve = {"configurations": [{"nodes": [{"operator": "OR", "negate": True, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"}
        ]}]}]}
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertNotEqual(result["status"], "version_match")

    def test_unknown_environment_component_does_not_pass_and(self):
        cve = {"configurations": [{"nodes": [{"operator": "AND", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}
        ]}]}]}
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
        self.assertNotIn("scan_metadata", report)


class TechnologyFingerprintTests(unittest.TestCase):
    def test_extracts_observed_nmap_fields_and_product_hints(self):
        result = build_technology_fingerprint({
            "name": "http", "product": "Apache httpd", "version": "2.4.57",
            "extrainfo": "OpenSSL/3.0.2", "tunnel": "ssl", "method": "probed",
            "conf": "10", "cpe": ["cpe:/a:apache:http_server:2.4.57"],
        })
        self.assertEqual(result["observed"]["version"], "2.4.57")
        categories = {item["category"] for item in result["technology_stack"]}
        self.assertIn("web_server", categories)
        self.assertIn("openssl", categories)
        self.assertIn("encrypted_transport", categories)

    def test_does_not_invent_technology_without_evidence(self):
        result = build_technology_fingerprint({"name": "unknown"})
        self.assertEqual(result["technology_stack"], [])
        self.assertEqual(result["observed"]["product"], None)

    def test_report_entry_includes_fingerprint(self):
        fingerprint = build_technology_fingerprint({"name": "ssh", "product": "OpenSSH"})
        report = build_report_entry("127.0.0.1", 22, "open", "ssh", "OpenSSH", "", [], [], [], fingerprint)
        self.assertIn("technology_fingerprint", report["identification_evidence"])


if __name__ == "__main__":
    unittest.main()
