import json
import os
import unittest
import urllib.error
from unittest.mock import Mock, patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from groq_client import GroqRequestError, request_remediation


class GroqClientTests(unittest.TestCase):
    def test_returns_structured_json_from_groq(self):
        proposal = {"vulnerability_id": "CVE-1", "severity": "LOW"}
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({"choices": [{"message": {"content": json.dumps(proposal)}}]}).encode()
        retry_prompt = json.dumps({"patch_validation_feedback": "Previous diff had no valid hunk; return a numeric unified-diff hunk."})
        with patch("groq_client.urllib.request.urlopen", return_value=response) as request:
            with patch.dict(os.environ, {"GROQ_MODEL": "test-model"}):
                result, model = request_remediation(retry_prompt, api_key="test-secret")
        self.assertEqual(result, proposal)
        self.assertEqual(model, "test-model")
        sent_request = request.call_args.args[0]
        self.assertEqual(sent_request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertNotIn("test-secret", sent_request.data.decode())
        sent_body = json.loads(sent_request.data.decode())
        self.assertEqual(sent_body["response_format"], {"type": "json_object"})
        self.assertEqual(sent_body["messages"][1]["content"], retry_prompt)
        self.assertIn("numeric @@", sent_body["messages"][0]["content"])

    def test_rate_limit_is_reported_without_exposing_key(self):
        response = Mock()
        response.read.return_value = b'{"error":"rate limited"}'
        error = urllib.error.HTTPError("https://api.groq.com", 429, "limited", {}, response)
        with patch("groq_client.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(GroqRequestError, "rate limited"):
                request_remediation("prompt", api_key="secret-value")

    def test_rate_limit_retries_once_after_retry_after(self):
        proposal = {"patch": "diff"}
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({"choices": [{"message": {"content": json.dumps(proposal)}}]}).encode()
        rate_limit = urllib.error.HTTPError(
            "https://api.groq.com", 429, "limited", {"Retry-After": "0"}, Mock()
        )
        with patch("groq_client.urllib.request.urlopen", side_effect=[rate_limit, response]) as request:
            with patch("groq_client.time.sleep") as sleep:
                result, _ = request_remediation("prompt", api_key="secret-value")
        self.assertEqual(result, proposal)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.0)

    def test_missing_key_and_malformed_response_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GroqRequestError, "GROQ_API_KEY"):
                request_remediation("prompt")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"choices":[]}'
        with patch("groq_client.urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(GroqRequestError, "no choices"):
                request_remediation("prompt", api_key="test-secret")


if __name__ == "__main__":
    unittest.main()
