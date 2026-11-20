import unittest
from assessment import assess_network_exposure, analyze_web_content, analyze_http_security, assess_cve_applicability, build_report_entry, build_technology_fingerprint, classify_exploit, cpe22_to_cpe23


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


class HTTPSecurityAssessmentTests(unittest.TestCase):
    def test_reports_missing_security_headers(self):
        result = analyze_http_security({}, is_https=True)
        ids = {finding["id"] for finding in result["findings"]}
        self.assertIn("missing_content_security_policy", ids)
        self.assertIn("missing_strict_transport_security", ids)
        self.assertEqual(result["status"], "analyzed")

    def test_detects_cookie_flags_without_retaining_cookie_value(self):
        result = analyze_http_security(
            {"Content-Security-Policy": "default-src 'self'"},
            ["sessionid=TOP_SECRET; Path=/; SameSite=Lax"], is_https=True)
        self.assertEqual(result["cookies"][0]["name"], "sessionid")
        self.assertFalse(result["cookies"][0]["secure"])
        self.assertFalse(result["cookies"][0]["httponly"])
        self.assertNotIn("TOP_SECRET", repr(result))

    def test_accepts_secure_cookie_attributes(self):
        result = analyze_http_security(
            {"X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000"},
            ["session=hidden; Secure; HttpOnly; SameSite=Strict"], is_https=True)
        self.assertEqual(result["cookies"][0]["samesite"], "Strict")
        self.assertTrue(result["cookies"][0]["secure"])
        self.assertTrue(result["cookies"][0]["httponly"])

    def test_flags_permissive_csp_directives(self):
        result = analyze_http_security(
            {"Content-Security-Policy": "default-src *; script-src 'unsafe-inline'"})
        self.assertIn("csp_permissive_directives", {item["id"] for item in result["findings"]})

    def test_report_entry_has_optional_http_assessment(self):
        report = build_report_entry("127.0.0.1", 80, "open", "http", "", "", [], [], [],
                                    http_assessment={"status": "not_requested"})
        self.assertEqual(report["http_assessment"]["status"], "not_requested")


class WebContentAnalysisTests(unittest.TestCase):
    def test_detects_cms_and_javascript_libraries_from_html_evidence(self):
        html = """
        <meta name="generator" content="WordPress 6.4.2">
        <script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script>
        <script src="/assets/vue.min.js"></script>
        """
        result = analyze_web_content(html)
        found = {(item["name"], item.get("version")) for item in result["technologies"]}
        self.assertIn(("WordPress", "6.4.2"), found)
        self.assertIn(("jQuery", "3.7.1"), found)
        self.assertIn(("Vue.js", None), found)

    def test_detects_drupal_asset_without_claiming_version(self):
        result = analyze_web_content('<script src="/sites/default/files/js/app.js"></script>')
        self.assertIn("Drupal", {item["name"] for item in result["technologies"]})

    def test_parses_robots_and_sitemap_metadata_without_storing_paths(self):
        result = analyze_web_content(
            "<html></html>",
            "User-agent: *\nDisallow: /admin\nSitemap: https://example.test/sitemap.xml\n",
            "<urlset><url><loc>https://example.test/a</loc></url><url><loc>https://example.test/b</loc></url></urlset>",
        )
        self.assertEqual(result["robots_txt"]["disallow_directives"], 1)
        self.assertEqual(result["robots_txt"]["sitemap_directives"], 1)
        self.assertEqual(result["sitemap_xml"]["url_count"], 2)
        self.assertNotIn("/admin", repr(result))

    def test_empty_content_does_not_invent_technology(self):
        result = analyze_web_content("")
        self.assertEqual(result["technologies"], [])


if __name__ == "__main__":
    unittest.main()


class NetworkExposureAssessmentTests(unittest.TestCase):
    def test_flags_exposed_database_with_remediation(self):
        findings = assess_network_exposure(3306, "mysql", "MySQL")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["status"], "exposed_service_observed")
        self.assertIn("public interfaces", findings[0]["recommendation"])
        self.assertIn("not proof", " ".join(findings[0]["limitations"]))

    def test_flags_unauthenticated_docker_api_as_critical_observation(self):
        finding = assess_network_exposure(2375, "docker", "Docker")[0]
        self.assertEqual(finding["severity"], "critical")
        self.assertIn("Disable", finding["recommendation"])

    def test_does_not_flag_ordinary_or_unknown_ports(self):
        self.assertEqual(assess_network_exposure(443, "https", "nginx"), [])
        self.assertEqual(assess_network_exposure(65000, "unknown", ""), [])
        self.assertEqual(assess_network_exposure("invalid"), [])

    def test_report_entry_contains_network_exposure_field(self):
        finding = assess_network_exposure(3389, "ms-wbt-server", "")
        report = build_report_entry("192.0.2.1", 3389, "open", "ms-wbt-server", "", "", [], [], [],
                                    network_exposure=finding)
        self.assertEqual(report["network_exposure"][0]["id"], "remote_access_exposure")
