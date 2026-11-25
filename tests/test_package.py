import importlib
import unittest

import reconforge


class PackageTests(unittest.TestCase):
    def test_package_version_matches_current_release(self):
        self.assertEqual(reconforge.__version__, "0.10.10")

    def test_legacy_root_modules_are_package_module_aliases(self):
        for module_name in (
            "scanner",
            "assessment",
            "asset_context",
            "remediation",
            "report",
            "risk",
        ):
            with self.subTest(module=module_name):
                legacy_module = importlib.import_module(module_name)
                package_module = importlib.import_module(f"reconforge.{module_name}")
                self.assertIs(legacy_module, package_module)

    def test_extracted_modules_are_importable(self):
        from reconforge import (
            cpe_assessment, exploit_assessment, exploitdb, nvd, targeting,
            web_assessment, web_probe, summary,
        )

        self.assertTrue(callable(exploitdb.searchsploit_lookup))
        self.assertTrue(callable(nvd.check_cve_nvd))
        self.assertTrue(callable(targeting.validate_target))
        self.assertTrue(callable(web_probe.probe_http_metadata))
        self.assertTrue(callable(cpe_assessment.assess_cve_applicability))
        self.assertTrue(callable(exploit_assessment.build_exploit_intelligence))
        self.assertTrue(callable(web_assessment.analyze_web_content))
        self.assertTrue(callable(summary.summarize_findings))

    def test_assessment_domains_are_split_and_facade_stays_compatible(self):
        from reconforge import assessment, cpe_assessment, exploit_assessment, web_assessment

        self.assertIs(assessment.assess_cve_applicability, cpe_assessment.assess_cve_applicability)
        self.assertIs(assessment.build_exploit_intelligence, exploit_assessment.build_exploit_intelligence)
        self.assertIs(assessment.analyze_http_security, web_assessment.analyze_http_security)
        self.assertTrue(callable(assessment.build_report_entry))

    def test_console_entry_points_are_importable(self):
        from reconforge.report import main as report_main
        from reconforge.scanner import main as scanner_main

        self.assertTrue(callable(scanner_main))
        self.assertTrue(callable(report_main))


if __name__ == "__main__":
    unittest.main()
