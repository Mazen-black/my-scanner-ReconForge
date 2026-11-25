import unittest

from remediation import build_remediation


class RemediationTests(unittest.TestCase):
    def test_telnet_gets_encrypted_alternative_guidance(self):
        result = build_remediation({"name": "telnet"})
        item = result["service_guidance"]
        self.assertEqual(item["service_family"], "telnet")
        self.assertTrue(any("SSH" in action for action in item["actions"]))
        self.assertEqual(result["mode"], "guidance_only")

    def test_smb_guidance_includes_share_access_review(self):
        result = build_remediation({"name": "microsoft-ds"})
        self.assertTrue(any("guest" in action.lower() or "anonymous" in action.lower() for action in result["service_guidance"]["actions"]))

    def test_candidate_cve_requires_applicability_verification(self):
        cve = {"id": "CVE-2099-1", "applicability": {"status": "candidate_unverified"}, "risk_priority": {"priority": "Medium", "priority_score": 60}}
        result = build_remediation({"name": "http"}, [cve])
        advice = result["cve_guidance"][0]
        self.assertEqual(advice["applicability"], "candidate_unverified")
        self.assertIn("Verify the remaining NVD configuration conditions", advice["actions"][0])

    def test_nvd_non_match_does_not_get_cve_remediation(self):
        cve = {"id": "CVE-2099-2", "applicability": {"status": "not_matched_by_nvd_cpe"}}
        result = build_remediation({"name": "http"}, [cve])
        self.assertEqual(result["cve_guidance"], [])

    def test_unknown_service_has_no_invented_service_fix(self):
        result = build_remediation({"name": "mystery-service"})
        self.assertIsNone(result["service_guidance"])

    def test_guidance_carries_host_service_and_nvd_evidence(self):
        cve = {
            "id": "CVE-2099-4", "cvss": 8.1, "severity": "HIGH", "source": "NVD CPE query",
            "applicability": {
                "status": "version_match",
                "evidence": [{"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": True}],
                "evidence_sources": ["NVD CPE configuration", "Nmap service detection"],
                "confidence_reasons": ["Version range matched."],
                "evidence_gaps": ["Vendor backport status is unknown."],
            },
            "risk_priority": {"priority": "High", "priority_score": 81.0},
        }
        result = build_remediation(
            {"name": "http", "product": "Apache httpd", "version": "2.2.8"},
            [cve], {"score": 81.0, "level": "High"},
            finding_context={"host": "192.0.2.10", "port": 80,
                             "identification_evidence": {"source": "Nmap service detection"}},
        )
        advice = result["cve_guidance"][0]
        self.assertEqual(advice["evidence"]["host"], "192.0.2.10")
        self.assertEqual(advice["evidence"]["port"], 80)
        self.assertEqual(advice["evidence"]["product"], "Apache httpd")
        self.assertEqual(advice["evidence"]["detected_version"], "2.2.8")
        self.assertEqual(advice["evidence"]["cvss_base_score"], 8.1)
        self.assertEqual(advice["evidence"]["matched_criteria"], ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"])
        self.assertEqual(advice["evidence"]["evidence_gaps"], ["Vendor backport status is unknown."])
        self.assertEqual(result["finding_context"]["risk_assessment"]["score"], 81.0)

    def test_unknown_applicability_state_is_downgraded_to_unverified(self):
        result = build_remediation({"name": "http"}, [{
            "id": "CVE-2099-5", "applicability": {"status": "confirmed_exploitable"}
        }])
        advice = result["cve_guidance"][0]
        self.assertEqual(advice["applicability"], "candidate_unverified")
        self.assertEqual(advice["confidence"], "low")
        self.assertIn("Verify the remaining NVD configuration conditions", advice["actions"][0])

    def test_malformed_cve_entries_are_ignored_safely(self):
        result = build_remediation({"name": "http"}, [None, "not-a-cve", {"id": "CVE-2099-6"}])
        self.assertEqual(len(result["cve_guidance"]), 1)
        self.assertEqual(result["cve_guidance"][0]["applicability"], "candidate_unverified")

    def test_no_fixed_version_is_fabricated(self):
        cve = {"id": "CVE-2099-3", "applicability": {"status": "version_match"}}
        result = build_remediation({"name": "http"}, [cve])
        text = " ".join(result["cve_guidance"][0]["actions"])
        self.assertIn("does not guess fixed version numbers", text)


if __name__ == "__main__":
    unittest.main()
