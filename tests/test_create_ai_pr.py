import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from create_ai_pr import notify_dashboard_pr_opened
from dashboard_callback import post_dashboard_callback, validate_callback_url


class DashboardPrCallbackTests(unittest.TestCase):
    def test_pr_callback_sends_bearer_authentication(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch("dashboard_callback.urllib.request.urlopen", return_value=response) as urlopen:
            notify_dashboard_pr_opened(
                "http://localhost:2001/", 17, {"pr_url": "https://github.test/pr/1"}, "callback-secret",
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://localhost:2001/api/tickets/17/mark-pr-opened")
        self.assertEqual(request.get_header("Authorization"), "Bearer callback-secret")

    def test_pr_callback_fails_closed_without_token(self):
        with patch("dashboard_callback.urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "DASHBOARD_CALLBACK_TOKEN"):
                notify_dashboard_pr_opened("http://localhost:2001", 17, {}, "")
        urlopen.assert_not_called()

    def test_unsafe_callback_destinations_are_rejected_before_network_use(self):
        for destination in (
            "https://localhost:2001",
            "http://attacker.example:2001",
            "http://localhost:2001@attacker.example",
            "http://localhost:2001/path",
            "http://localhost:2001/?next=attacker",
        ):
            with self.subTest(destination=destination), \
                 patch("dashboard_callback.urllib.request.urlopen") as urlopen:
                with self.assertRaises(RuntimeError):
                    post_dashboard_callback(destination, 17, "validation-result", {}, "callback-secret")
                urlopen.assert_not_called()

    def test_callback_destination_is_not_a_jenkins_build_parameter(self):
        pipeline = (ROOT / "Jenkinsfile.single-fix").read_text(encoding="utf-8")
        self.assertNotIn("string(name: 'DASHBOARD_CALLBACK_URL'", pipeline)
        self.assertIn("DASHBOARD_CALLBACK_URL = 'http://localhost:2001'", pipeline)

    def test_default_trusted_destination_is_accepted(self):
        self.assertEqual(validate_callback_url("http://localhost:2001"), "http://localhost:2001")


if __name__ == "__main__":
    unittest.main()
