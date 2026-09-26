#!/usr/bin/env python3
"""Minimal Groq Chat Completions client; it returns proposals, never executes tools."""

import json
import os
import urllib.error
import urllib.request

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"
REQUEST_TIMEOUT_SECONDS = 60


class GroqRequestError(RuntimeError):
    """A safe, key-free description of a failed Groq request or response."""


def request_remediation(prompt, api_key=None):
    api_key = api_key or os.environ.get("GROQ_API_KEY")
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
    if not api_key:
        raise GroqRequestError("GROQ_API_KEY is not configured")
    if not model.strip():
        raise GroqRequestError("GROQ_MODEL must not be empty")

    request_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return one JSON object only. Propose a minimal unified diff for the supplied single file. Never request or execute commands."},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
        "max_tokens": 6000,
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
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 429:
            detail = "rate limited"
        elif error.code in (401, 403):
            detail = "authentication or access denied"
        else:
            detail = f"HTTP {error.code}"
        raise GroqRequestError(f"Groq request failed ({detail})") from error
    except urllib.error.URLError as error:
        raise GroqRequestError(f"Groq network error: {error.reason}") from error
    except TimeoutError as error:
        raise GroqRequestError("Groq request timed out") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GroqRequestError("Groq returned an invalid response body") from error

    choices = data.get("choices") if isinstance(data, dict) else None
    if not choices or not isinstance(choices[0], dict):
        raise GroqRequestError("Groq response contained no choices")
    message = choices[0].get("message", {})
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise GroqRequestError("Groq response was empty")
    try:
        proposal = json.loads(content)
    except json.JSONDecodeError as error:
        raise GroqRequestError("Groq proposal was not valid JSON") from error
    if not isinstance(proposal, dict):
        raise GroqRequestError("Groq proposal must be a JSON object")
    return proposal, model
