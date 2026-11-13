import unittest

from asset_context import assess_asset_context


class AssetContextTests(unittest.TestCase):
    def test_unknown_context_is_neutral_and_explicit(self):
        result = assess_asset_context({"score": 60.0})
        self.assertEqual(result["contextual_priority_score"], 60.0)
        self.assertEqual(result["asset_criticality"], "unknown")
        self.assertEqual(result["network_exposure"], "unknown")
        self.assertFalse(result["is_cvss"])

    def test_critical_internet_asset_gets_higher_contextual_priority(self):
        result = assess_asset_context({"score": 60.0}, "critical", "internet")
        self.assertEqual(result["technical_priority_score"], 60.0)
        self.assertEqual(result["contextual_priority_score"], 89.7)
        self.assertEqual(result["contextual_priority"], "High")

    def test_internal_low_criticality_reduces_contextual_priority(self):
        result = assess_asset_context({"score": 50.0}, "low", "internal")
        self.assertEqual(result["contextual_priority_score"], 36.0)
        self.assertEqual(result["contextual_priority"], "Low")

    def test_contextual_score_is_capped_at_100(self):
        result = assess_asset_context({"score": 90.0}, "critical", "internet")
        self.assertEqual(result["contextual_priority_score"], 100.0)

    def test_missing_technical_score_stays_unscored(self):
        result = assess_asset_context({"score": None}, "critical", "internet")
        self.assertIsNone(result["contextual_priority_score"])
        self.assertEqual(result["contextual_priority"], "Unscored")

    def test_invalid_context_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_asset_context({"score": 50}, "urgent", "internet")
        with self.assertRaises(ValueError):
            assess_asset_context({"score": 50}, "high", "public")


if __name__ == "__main__":
    unittest.main()
