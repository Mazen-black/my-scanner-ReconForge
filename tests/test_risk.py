import unittest

from risk import assess_service_risk, score_cve


class RiskScoringTests(unittest.TestCase):
    def test_exact_version_match_keeps_full_cvss_for_priority(self):
        result = score_cve({
            "id": "CVE-2099-1",
            "cvss": 9.8,
            "applicability": {"status": "version_match", "confidence": "medium"},
        })
        self.assertEqual(result["cvss_base_score"], 9.8)
        self.assertEqual(result["priority_score"], 98.0)
        self.assertEqual(result["priority"], "Critical")

    def test_unverified_candidate_is_discounted_not_discarded(self):
        result = score_cve({
            "cvss": 9.8,
            "applicability": {"status": "candidate_unverified", "confidence": "low"},
        })
        self.assertEqual(result["priority_score"], 63.7)
        self.assertEqual(result["priority"], "Medium")

    def test_nvd_non_match_is_not_actionable_priority(self):
        result = score_cve({
            "cvss": 9.8,
            "applicability": {"status": "not_matched_by_nvd_cpe"},
        })
        self.assertEqual(result["priority_score"], 0.0)
        summary = assess_service_risk([{
            "id": "CVE-2099-2",
            "cvss": 9.8,
            "applicability": {"status": "not_matched_by_nvd_cpe"},
        }], [])
        self.assertIsNone(summary["score"])
        self.assertEqual(summary["level"], "Unscored")

    def test_missing_cvss_stays_unscored(self):
        result = score_cve({"id": "CVE-2099-3", "applicability": {"status": "version_match"}})
        self.assertIsNone(result["priority_score"])
        self.assertEqual(result["priority"], "Unscored")

    def test_exploit_references_do_not_change_numeric_score(self):
        cve = {
            "id": "CVE-2099-4",
            "cvss": 7.5,
            "applicability": {"status": "version_match"},
        }
        without_refs = assess_service_risk([cve], [])
        with_refs = assess_service_risk([cve], [{
            "id": "17491",
            "assessment": {"relevance": "product_and_version_match"},
        }])
        self.assertEqual(without_refs["score"], with_refs["score"])
        self.assertEqual(with_refs["exact_product_version_reference_count"], 1)
        self.assertFalse(with_refs["exploit_references_affect_score"])

    def test_service_uses_highest_applicable_priority(self):
        cves = [
            {"id": "CVE-1", "cvss": 5.0, "applicability": {"status": "version_match"}},
            {"id": "CVE-2", "cvss": 9.0, "applicability": {"status": "candidate_unverified"}},
        ]
        summary = assess_service_risk(cves, [])
        self.assertEqual(summary["top_cve"], "CVE-1")
        self.assertEqual(summary["score"], 50.0)


if __name__ == "__main__":
    unittest.main()
