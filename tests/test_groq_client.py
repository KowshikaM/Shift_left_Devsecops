import json
import os
import sys
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from groq_client import GroqRequestError, request_remediation, retry_after_seconds


SCHEMA = {
    "type": "object",
    "properties": {"file": {"type": "string"}, "find": {"type": "string"}},
    "required": ["file", "find"],
    "additionalProperties": False,
}


def response_for(content, *, finish_reason="stop", refusal=None):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    message = {"content": content}
    if refusal:
        message["refusal"] = refusal
    response.read.return_value = json.dumps({"choices": [{"message": message, "finish_reason": finish_reason}]}).encode()
    return response


class GroqClientTests(unittest.TestCase):
    def test_uses_strict_schema_and_completion_token_parameter(self):
        proposal = {"file": "app/index.js", "find": "res.send(x)"}
        response = response_for(json.dumps(proposal))
        prompt = json.dumps({"task": "return a structured edit"})
        with patch("groq_client.urllib.request.urlopen", return_value=response) as request:
            with patch.dict(os.environ, {"GROQ_MODEL": "openai/gpt-oss-20b"}):
                result, model = request_remediation(prompt, response_schema=SCHEMA, api_key="test-secret")
        self.assertEqual(result, proposal)
        self.assertEqual(model, "openai/gpt-oss-20b")
        sent_request = request.call_args.args[0]
        self.assertEqual(sent_request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertNotIn("test-secret", sent_request.data.decode())
        sent_body = json.loads(sent_request.data.decode())
        self.assertEqual(sent_body["response_format"]["type"], "json_schema")
        self.assertTrue(sent_body["response_format"]["json_schema"]["strict"])
        self.assertEqual(sent_body["response_format"]["json_schema"]["schema"], SCHEMA)
        self.assertEqual(sent_body["messages"][1]["content"], prompt)
        self.assertEqual(sent_body["max_completion_tokens"], 6000)
        self.assertNotIn("max_tokens", sent_body)

    def test_http_400_detail_is_helpful_and_redacts_secrets(self):
        response = Mock()
        response.read.return_value = json.dumps({"error": {
            "type": "invalid_request_error", "code": "schema_error",
            "message": "Invalid request; Authorization: Bearer secret-value",
            "failed_generation": {"reason": "Schema field mismatch", "attempted_arguments": "secret-value"},
        }}).encode()
        error = urllib.error.HTTPError("https://api.groq.com", 400, "bad request", {}, response)
        with patch("groq_client.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(GroqRequestError, "HTTP 400.*Schema field mismatch") as raised:
                request_remediation("prompt", response_schema=SCHEMA, api_key="secret-value")
        self.assertNotIn("secret-value", str(raised.exception))
        self.assertNotIn("attempted_arguments", str(raised.exception))

    def test_429_retries_once_for_delta_or_http_date_below_cap(self):
        proposal = {"file": "app/index.js", "find": "x"}
        rate_limit = urllib.error.HTTPError(
            "https://api.groq.com", 429, "limited", {"Retry-After": "0"}, Mock()
        )
        with patch("groq_client.urllib.request.urlopen", side_effect=[rate_limit, response_for(json.dumps(proposal))]) as request:
            with patch("groq_client.time.sleep") as sleep:
                result, _ = request_remediation("prompt", response_schema=SCHEMA, api_key="secret-value")
        self.assertEqual(result, proposal)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.0)
        self.assertEqual(retry_after_seconds("61"), None)
        self.assertEqual(retry_after_seconds("not-a-date"), None)
        retry_date = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=10), usegmt=True)
        self.assertGreater(retry_after_seconds(retry_date), 0)
        self.assertLessEqual(retry_after_seconds(retry_date), 10)

    def test_429_without_usable_retry_after_is_not_retried(self):
        rate_limit = urllib.error.HTTPError(
            "https://api.groq.com", 429, "limited", {}, Mock()
        )
        with patch("groq_client.urllib.request.urlopen", side_effect=rate_limit) as request:
            with self.assertRaisesRegex(GroqRequestError, "rate limited"):
                request_remediation("prompt", response_schema=SCHEMA, api_key="secret-value")
        self.assertEqual(request.call_count, 1)

    def test_malformed_json_refusal_and_truncation_fail_explicitly(self):
        for response, expected in (
            (response_for("not json"), "not valid JSON"),
            (response_for("{}", refusal="unsafe"), "refused"),
            (response_for("{}", finish_reason="content_filter"), "refused or filtered"),
            (response_for("{}", finish_reason="length"), "truncated"),
        ):
            with self.subTest(expected=expected), patch("groq_client.urllib.request.urlopen", return_value=response):
                with self.assertRaisesRegex(GroqRequestError, expected):
                    request_remediation("prompt", response_schema=SCHEMA, api_key="secret-value")

    def test_missing_key_invalid_envelope_and_empty_content_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GroqRequestError, "GROQ_API_KEY"):
                request_remediation("prompt", response_schema=SCHEMA)
        for body, expected in ((b'{"choices":[]}', "no choices"),
                               (b'{"choices":[{"message":{"content":""}}]}', "empty")):
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = body
            with patch("groq_client.urllib.request.urlopen", return_value=response):
                with self.assertRaisesRegex(GroqRequestError, expected):
                    request_remediation("prompt", response_schema=SCHEMA, api_key="test-secret")

    def test_model_without_strict_schema_support_is_rejected_before_network_call(self):
        with patch.dict(os.environ, {"GROQ_MODEL": "unverified/model"}), \
             patch("groq_client.urllib.request.urlopen") as request:
            with self.assertRaisesRegex(GroqRequestError, "not enabled for strict JSON Schema"):
                request_remediation("prompt", response_schema=SCHEMA, api_key="test-secret")
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
