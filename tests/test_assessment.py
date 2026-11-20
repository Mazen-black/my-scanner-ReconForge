import unittest
from assessment import assess_network_exposure, analyze_web_content, analyze_http_security, assess_cve_applicability, build_report_entry, build_technology_fingerprint, classify_exploit, cpe22_to_cpe23, build_exploit_intelligence, apply_contextual_cve_constraints, assess_exploit_platform


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
        self.assertEqual(result["evidence"][0]["reason"], "exact_version")

    def test_contextual_build_provenance_downgrades_broad_cpe_match(self):
        base = {"status": "version_match", "confidence": "medium", "evidence": [{"reason": "exact_version"}]}
        result = apply_contextual_cve_constraints("CVE-2011-2523", base)
        self.assertEqual(result["status"], "candidate_unverified")
        self.assertEqual(result["cpe_version_status"], "version_match")
        self.assertEqual(result["contextual_constraint"]["kind"], "build_provenance")
        self.assertTrue(any("build/provenance" in item for item in result["limitations"]))

    def test_contextual_constraint_does_not_change_unrelated_cve(self):
        base = {"status": "version_match", "confidence": "medium", "evidence": []}
        result = apply_contextual_cve_constraints("CVE-2024-12345", base)
        self.assertEqual(result, base)

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

    def test_known_target_version_mismatch_dominates_unknown_environment_in_and(self):
        target = self._match("cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*")
        unknown_os = self._match("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")
        cve = self._cve(target, unknown_os, operator="AND")
        result = assess_cve_applicability(cve, "apache", "http_server", "2.4.57")
        self.assertEqual(result["status"], "not_matched_by_nvd_cpe")

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

    def test_different_version_in_title_is_not_reported_as_version_match(self):
        result = classify_exploit({"Title": "Apache httpd 2.2.8 - Example"}, "Apache httpd", "2.4.57")
        self.assertEqual(result["relevance"], "product_match_different_version_in_title")
        self.assertFalse(result["evidence"]["version_text_match"])

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

    def test_normalizes_single_string_cpe_without_splitting_characters(self):
        cpe = "cpe:/a:apache:http_server:2.2.8"
        result = build_technology_fingerprint({"name": "http", "cpe": cpe})
        self.assertEqual(result["observed"]["cpes"], [cpe])

    def test_preserves_multiple_cpes_as_separate_identifiers(self):
        cpes = ["cpe:/a:apache:http_server:2.2.8", "cpe:/a:openssl:openssl:0.9.8"]
        result = build_technology_fingerprint({"name": "http", "cpe": cpes})
        self.assertEqual(result["observed"]["cpes"], cpes)

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


class ExploitIntelligenceTests(unittest.TestCase):
    def test_platform_is_unknown_when_target_os_is_not_known(self):
        result = assess_exploit_platform("windows", None)
        self.assertEqual(result["status"], "unknown_target_platform")

    def test_platform_mismatch_is_flagged_when_target_os_is_known(self):
        result = assess_exploit_platform("windows", "linux")
        self.assertEqual(result["status"], "platform_mismatch_candidate")
        self.assertEqual(result["confidence"], "medium")

    def test_unix_exploit_platform_is_not_rejected_for_linux_target(self):
        result = assess_exploit_platform("unix", "linux")
        self.assertEqual(result["status"], "platform_family_match")

    def test_platform_mismatch_changes_overall_exploit_triage(self):
        result = build_exploit_intelligence(
            [{
                "id": "123", "title": "Example Product 1.0 exploit",
                "platform": "Windows",
                "assessment": {
                    "relevance": "product_and_version_match",
                    "confidence": "low",
                    "evidence": {"version_text_match": True, "version_candidates_in_title": ["1.0"]},
                },
            }],
            [],
            target_platform="linux",
        )[0]
        self.assertEqual(result["triage"]["status"], "platform_mismatch_review")
        self.assertEqual(result["triage"]["cve_status"], "manual_cve_correlation_required")
        self.assertEqual(
            result["applicability_evidence"]["requirements_assessment"],
            "unknown_not_inferred_from_exploit_title",
        )

    def test_different_version_in_exploit_title_is_not_treated_as_applicable(self):
        result = build_exploit_intelligence(
            [{
                "id": "124", "title": "Example Product 2.0 remote exploit",
                "platform": "Linux",
                "assessment": {
                    "relevance": "product_match_different_version_in_title",
                    "confidence": "low",
                    "evidence": {"version_text_match": False, "version_candidates_in_title": ["2.0"]},
                },
            }],
            [],
            target_platform="linux",
        )[0]
        self.assertEqual(result["triage"]["status"], "different_version_candidate")

    def test_exploit_intelligence_records_platform_compatibility(self):
        result = build_exploit_intelligence(
            [{"id": "123", "title": "Example", "platform": "windows"}],
            [],
            target_platform="linux",
        )[0]
        self.assertEqual(
            result["platform_compatibility"]["status"],
            "platform_mismatch_candidate",
        )

    def test_adds_official_exploit_db_reference_and_cve_correlation(self):
        result = build_exploit_intelligence(
            [{"id": "12345", "title": "Apache httpd CVE-2024-12345", "type": "remote",
              "platform": "linux", "assessment": {"relevance": "product_match_version_unconfirmed"}}],
            [{"id": "CVE-2024-12345"}],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["reference"]["url"],
                         "https://www.exploit-db.com/exploits/12345")
        self.assertEqual(result[0]["cve_correlation"]["matched_scanner_cve_ids"],
                         ["CVE-2024-12345"])
        self.assertEqual(result[0]["execution_status"], "not_executed")

    def test_does_not_invent_cve_correlation(self):
        result = build_exploit_intelligence(
            [{"id": "123", "title": "Example exploit"}],
            [{"id": "CVE-2024-9999"}],
        )[0]
        self.assertEqual(result["cve_correlation"]["status"], "no_explicit_cve_link")
        self.assertEqual(result["cve_correlation"]["matched_scanner_cve_ids"], [])

    def test_cve_correlation_carries_separate_review_priority_evidence(self):
        result = build_exploit_intelligence(
            [{
                "id": "125", "title": "Example CVE-2024-12345",
                "assessment": {"relevance": "product_match_version_unconfirmed"},
            }],
            [{
                "id": "CVE-2024-12345", "cvss": 8.8,
                "applicability": {"status": "candidate_unverified", "confidence": "low"},
                "risk_priority": {"priority": "Medium", "score": 42.0},
            }],
        )[0]
        linked = result["cve_correlation"]["matched_cve_applicability"][0]
        self.assertEqual(linked["applicability_status"], "candidate_unverified")
        self.assertEqual(linked["review_priority"]["score"], 42.0)
        self.assertEqual(linked["review_priority"]["priority"], "Medium")

    def test_cve_correlation_preserves_unverified_applicability(self):
        result = build_exploit_intelligence(
            [{"id": "123", "title": "Example CVE-2011-2523 exploit"}],
            [{"id": "CVE-2011-2523", "cvss": 9.8,
              "applicability": {"status": "candidate_unverified", "confidence": "low",
                                "contextual_constraint": {"kind": "build_provenance"}}}],
        )[0]
        self.assertEqual(result["cve_correlation"]["status"], "explicit_cve_match_applicability_unverified")
        self.assertEqual(result["triage"]["status"], "cve_candidate_unverified")
        self.assertEqual(result["cve_correlation"]["matched_cve_applicability"][0]["contextual_constraint"]["kind"], "build_provenance")

    def test_rejects_non_numeric_exploit_db_identifier_for_url(self):
        result = build_exploit_intelligence(
            [{"id": "../../etc/passwd", "title": "Example"}], []
        )[0]
        self.assertIsNone(result["reference"]["url"])

    def test_report_contains_exploit_intelligence(self):
        report = build_report_entry(
            "127.0.0.1", 22, "open", "ssh", "OpenSSH", "9.0", [], [], [],
            exploit_intelligence=[{"execution_status": "not_executed"}],
        )
        self.assertEqual(report["exploit_intelligence"][0]["execution_status"], "not_executed")


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
