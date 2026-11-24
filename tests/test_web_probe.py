import unittest
from unittest.mock import Mock

from reconforge import web_probe


class WebProbeModuleTests(unittest.TestCase):
    def test_non_web_service_is_skipped_without_http_request(self):
        requests_module = Mock()
        result = web_probe.probe_http_metadata(
            "192.0.2.5", 22, {"name": "ssh"}, requests_module=requests_module
        )
        self.assertEqual(result["status"], "skipped")
        requests_module.head.assert_not_called()

    def test_http_probe_uses_injected_requests_and_version(self):
        response = Mock(status_code=200, headers={"Server": "test"})
        response.raw.headers = Mock()
        response.raw.headers.getlist.return_value = []
        requests_module = Mock()
        requests_module.head.return_value = response
        result = web_probe.probe_http_metadata(
            "192.0.2.5", 80, {"name": "http"},
            requests_module=requests_module, scanner_version="test-version",
        )
        self.assertEqual(result["status"], "response_received")
        self.assertEqual(
            requests_module.head.call_args.kwargs["headers"]["User-Agent"],
            "ReconForge/test-version (authorized security assessment)",
        )
        self.assertFalse(requests_module.head.call_args.kwargs["allow_redirects"])

    def test_bounded_get_closes_response_after_reading_limit(self):
        response = Mock(status_code=200, encoding="utf-8")
        response.iter_content.return_value = iter([b"abcdefgh", b"ijkl"])
        requests_module = Mock()
        requests_module.get.return_value = response
        content, error = web_probe.bounded_same_origin_get(
            "http://192.0.2.5/", 5, requests_module=requests_module
        )
        self.assertEqual(content, "abcde")
        self.assertIsNone(error)
        response.close.assert_called_once()
        self.assertFalse(requests_module.get.call_args.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
