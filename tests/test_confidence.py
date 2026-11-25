import unittest

from reconforge.confidence import build_evidence_confidence


class EvidenceConfidenceSummaryTests(unittest.TestCase):
    def fingerprint(self, method="probed", score=10, product="Apache httpd", version="2.4.57"):
        return {"observed": {"service": "http", "product": product, "version": version,
                             "method": method, "nmap_confidence": score}}

    def test_strong_nmap_identity_and_cpe_match_yield_medium_review_confidence(self):
        result = build_evidence_confidence(
            self.fingerprint(),
            [{"id": "CVE-2024-12345", "applicability": {"status": "version_match"}}],
            [{"id": "123"}],
            [{"cve_correlation": {"matched_scanner_cve_ids": ["CVE-2024-12345"]}}],
        )
        self.assertEqual(result["service_identity"]["confidence"], "high")
        self.assertEqual(result["cve_applicability"]["confidence"], "medium")
        self.assertEqual(result["exploit_reference_linkage"]["confidence"], "high_for_identifier_link_only")
        self.assertEqual(result["overall_review_confidence"], "medium")
        self.assertEqual(result["exploitability_confidence"], "unknown")

    def test_banner_only_or_unverified_cve_does_not_promote_overall_confidence(self):
        result = build_evidence_confidence(
            self.fingerprint(method="table", score=3),
            [{"id": "CVE-2024-12345", "applicability": {"status": "candidate_unverified"}}],
            [{"id": "123"}], [],
        )
        self.assertEqual(result["service_identity"]["confidence"], "medium")
        self.assertEqual(result["cve_applicability"]["confidence"], "low")
        self.assertEqual(result["exploit_reference_linkage"]["confidence"], "low")
        self.assertEqual(result["overall_review_confidence"], "low")
        self.assertTrue(result["overall_evidence_gaps"])

    def test_missing_service_and_cve_data_remains_unknown(self):
        result = build_evidence_confidence({}, [], [], [])
        self.assertEqual(result["service_identity"]["confidence"], "unknown")
        self.assertEqual(result["cve_applicability"]["confidence"], "unknown")
        self.assertEqual(result["overall_review_confidence"], "unknown")

    def test_invalid_nmap_confidence_is_not_trusted(self):
        result = build_evidence_confidence(self.fingerprint(score=100), [], [], [])
        self.assertIsNone(result["service_identity"]["nmap_confidence"])
        self.assertEqual(result["service_identity"]["confidence"], "medium")

    def test_contextual_unverified_status_keeps_cve_confidence_low(self):
        result = build_evidence_confidence(
            self.fingerprint(),
            [{"id": "CVE-2011-2523", "applicability": {
                "status": "candidate_unverified", "cpe_version_status": "version_match",
                "contextual_constraint": {"kind": "build_provenance"}}}],
            [], [],
        )
        self.assertEqual(result["cve_applicability"]["confidence"], "low")
        self.assertEqual(result["overall_review_confidence"], "low")


if __name__ == "__main__":
    unittest.main()
