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

    def test_console_entry_points_are_importable(self):
        from reconforge.report import main as report_main
        from reconforge.scanner import main as scanner_main

        self.assertTrue(callable(scanner_main))
        self.assertTrue(callable(report_main))


if __name__ == "__main__":
    unittest.main()
