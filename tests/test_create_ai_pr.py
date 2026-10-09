import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from create_ai_pr import (
    create_or_reuse_pull_request,
    find_ticket_pull_request,
    notify_dashboard_pr_opened,
)
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


class GithubPullRequestRetryTests(unittest.TestCase):
    def test_existing_open_pull_request_is_reused_without_post(self):
        existing = {
            "number": 27, "state": "open", "html_url": "https://github.com/example/repo/pull/27",
            "head": {"ref": "ai-remediation/ticket-17"},
            "base": {"ref": "main"},
        }
        with patch("create_ai_pr.github_api", return_value=[existing]) as github_api:
            result = create_or_reuse_pull_request(
                "example/repo", "ai-remediation/ticket-17", "token", "title", "body",
            )
        self.assertEqual(result, existing)
        github_api.assert_called_once()
        self.assertEqual(github_api.call_args.args[0], "GET")
        self.assertIn("head=example%3Aai-remediation%2Fticket-17", github_api.call_args.args[1])

    def test_closed_pull_request_is_not_silently_duplicated(self):
        closed = {
            "number": 27, "state": "closed",
            "head": {"ref": "ai-remediation/ticket-17"},
            "base": {"ref": "main"},
        }
        with patch("create_ai_pr.github_api", return_value=[closed]) as github_api:
            with self.assertRaisesRegex(RuntimeError, "already exists but is closed"):
                create_or_reuse_pull_request(
                    "example/repo", "ai-remediation/ticket-17", "token", "title", "body",
                )
        github_api.assert_called_once()

    def test_new_pull_request_is_created_after_empty_lookup(self):
        created = {
            "number": 28, "state": "open",
            "html_url": "https://github.com/example/repo/pull/28",
        }
        with patch("create_ai_pr.github_api", side_effect=[[], created]) as github_api:
            result = create_or_reuse_pull_request(
                "example/repo", "ai-remediation/ticket-17", "token", "title", "body",
            )
        self.assertEqual(result, created)
        self.assertEqual([call.args[0] for call in github_api.call_args_list], ["GET", "POST"])

    def test_create_error_requeries_for_a_pull_request_created_by_a_retry(self):
        created_by_retry = {
            "number": 29, "state": "open",
            "head": {"ref": "ai-remediation/ticket-17"},
            "base": {"ref": "main"},
        }
        with patch(
            "create_ai_pr.github_api",
            side_effect=[[], RuntimeError("ambiguous create response"), [created_by_retry]],
        ) as github_api:
            result = create_or_reuse_pull_request(
                "example/repo", "ai-remediation/ticket-17", "token", "title", "body",
            )
        self.assertEqual(result, created_by_retry)
        self.assertEqual([call.args[0] for call in github_api.call_args_list], ["GET", "POST", "GET"])


if __name__ == "__main__":
    unittest.main()
