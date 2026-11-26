import unittest

from reconforge import targeting


class TargetingModuleTests(unittest.TestCase):
    def test_target_validation_accepts_ip_cidr_and_hostname(self):
        for value in ("192.0.2.4", "192.0.2.0/24", "lab.example.org"):
            with self.subTest(value=value):
                self.assertEqual(targeting.validate_target(value), value)

    def test_target_validation_rejects_oversized_cidr_ranges(self):
        for value in ("192.0.2.0/23", "2001:db8::/119", "0.0.0.0/0"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "maximum allowed"):
                    targeting.validate_target(value)

    def test_target_validation_accepts_maximum_cidr_size(self):
        self.assertEqual(targeting.validate_target("192.0.2.0/24"), "192.0.2.0/24")
        self.assertEqual(targeting.validate_target("2001:db8::/120"), "2001:db8::/120")

    def test_target_validation_rejects_shell_metacharacters(self):
        for value in ("host;id", "host && id", "-Pn", "https://host"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    targeting.validate_target(value)

    def test_port_validation_rejects_reversed_or_out_of_range_ports(self):
        for value in ("80-22", "0", "65536", "80,,443"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    targeting.validate_ports(value)

    def test_nmap_argument_allowlist_accepts_reviewed_flags(self):
        self.assertEqual(targeting.normalize_nmap_args("-sV -Pn --reason"), "-sV -Pn --reason")

    def test_nmap_argument_allowlist_rejects_unreviewed_flags_and_values(self):
        for value in ("-sV -A", "--script vuln", "--datadir /tmp", "-p 1-65535"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Unsupported Nmap argument"):
                    targeting.normalize_nmap_args(value)

    def test_os_fingerprint_keeps_low_accuracy_unconfirmed(self):
        result = targeting.build_host_os_fingerprint(
            [{"name": "Linux 6.x", "accuracy": "72"}], requested=True
        )
        self.assertEqual(result["status"], "unconfirmed_low_confidence_or_unknown_family")
        self.assertIsNone(result["platform_family"])
        self.assertEqual(result["accuracy"], 72)

    def test_empty_host_results_raise_a_clear_error(self):
        class EmptyScanner:
            @staticmethod
            def all_hosts():
                return []

        with self.assertRaisesRegex(RuntimeError, "did not return any hosts"):
            targeting.scanned_hosts(EmptyScanner())


if __name__ == "__main__":
    unittest.main()
