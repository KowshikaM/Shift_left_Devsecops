#!/usr/bin/env python3
"""Minimal Groq Chat Completions client; it returns proposals, never executes tools."""

import json
import os
import re
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import urllib.error
import urllib.request

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"
STRICT_JSON_MODELS = {DEFAULT_MODEL}
REQUEST_TIMEOUT_SECONDS = 60
MAX_RATE_LIMIT_RETRY_SECONDS = 60


class GroqRequestError(RuntimeError):
    """A safe, key-free description of a failed Groq request or response."""


def safe_http_error_detail(error, api_key):
    try:
        body = error.read(4096).decode("utf-8", errors="replace")
        payload = json.loads(body)
        detail = payload.get("error", payload) if isinstance(payload, dict) else payload
        if isinstance(detail, dict):
            fields = [detail.get(key) for key in ("type", "code", "message")]
            failed = detail.get("failed_generation")
            if isinstance(failed, dict):
                fields.append(failed.get("reason"))
            detail = "; ".join(str(value) for value in fields if value)
        else:
            detail = str(detail)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError):
        return ""
    if api_key:
        detail = detail.replace(api_key, "[REDACTED]")
    detail = re.sub(r"(?i)bearer\s+\S+", "Bearer [REDACTED]", detail)
    detail = re.sub(r"\b(?:gsk|sk|ghp|github_pat)_[A-Za-z0-9_-]{8,}\b", "[REDACTED]", detail)
    detail = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED]", detail)
    detail = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[REDACTED]", detail)
    detail = re.sub(r"AIza[0-9A-Za-z_-]{30,}", "[REDACTED]", detail)
    detail = re.sub(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", detail)
    detail = "".join(char for char in detail if char.isprintable()).strip()
    return detail[:500]


def retry_after_seconds(value):
    """Parse Retry-After delta-seconds or HTTP-date without exceeding our cap."""
    if not value:
        return None
    try:
        delay = float(value)
    except (TypeError, ValueError):
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if delay < 0 or delay > MAX_RATE_LIMIT_RETRY_SECONDS:
        return None
    return delay


def request_remediation(prompt, response_schema, api_key=None):
    api_key = api_key or os.environ.get("GROQ_API_KEY")
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
    if not api_key:
        raise GroqRequestError("GROQ_API_KEY is not configured")
    if not model.strip():
        raise GroqRequestError("GROQ_MODEL must not be empty")
    if model not in STRICT_JSON_MODELS:
        raise GroqRequestError("GROQ_MODEL is not enabled for strict JSON Schema responses")

    request_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return exactly one JSON object matching the supplied schema. Propose one minimal exact-text edit to the single supplied file. Do not return a patch, Markdown, commands, credentials, or extra properties."},
            {"role": "user", "content": prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "single_file_remediation_edit",
                "strict": True,
                "schema": response_schema,
            },
        },
        "temperature": 0.1,
        "max_completion_tokens": 6000,
    }
    request = urllib.request.Request(
        GROQ_URL,
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ShiftLeftDevSecOps/1.0",
        },
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                data = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as error:
            if error.code == 429:
                retry_after = error.headers.get("Retry-After") if error.headers else None
                delay = retry_after_seconds(retry_after)
                if attempt == 0 and delay is not None and 0 <= delay <= MAX_RATE_LIMIT_RETRY_SECONDS:
                    error.close()
                    time.sleep(delay)
                    continue
                if delay is None:
                    detail = "rate limited; Retry-After was missing, invalid, expired, or exceeded 60 seconds"
                else:
                    detail = "rate limited after one retry"
            elif error.code in (401, 403):
                detail = "authentication or access denied"
            else:
                detail = f"HTTP {error.code}"
            provider_detail = safe_http_error_detail(error, api_key)
            if provider_detail:
                detail = f"{detail}: {provider_detail}"
            raise GroqRequestError(f"Groq request failed ({detail})") from error
        except urllib.error.URLError as error:
            raise GroqRequestError(f"Groq network error: {error.reason}") from error
        except TimeoutError as error:
            raise GroqRequestError("Groq request timed out") from error
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise GroqRequestError("Groq returned an invalid response body") from error
    else:
        raise GroqRequestError("Groq request failed (rate limited after one retry)")

    choices = data.get("choices") if isinstance(data, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise GroqRequestError("Groq response contained no choices")
    if choices[0].get("finish_reason") == "length":
        raise GroqRequestError("Groq response was truncated before completion")
    if choices[0].get("finish_reason") == "content_filter":
        raise GroqRequestError("Groq response was refused or filtered")
    message = choices[0].get("message", {})
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(message, dict) and message.get("refusal"):
        raise GroqRequestError("Groq refused the remediation request")
    if not isinstance(content, str) or not content.strip():
        raise GroqRequestError("Groq response was empty")
    try:
        proposal = json.loads(content)
    except json.JSONDecodeError as error:
        raise GroqRequestError("Groq proposal was not valid JSON") from error
    if not isinstance(proposal, dict):
        raise GroqRequestError("Groq proposal must be a JSON object")
    return proposal, model
