#!/usr/bin/env python3
"""
AI remediation helper with OpenAI-primary / Groq-fallback provider adapter.

Security rules:
- API keys are read only from environment variables.
- Gitleaks/secret findings are never sent to an external AI provider.
- AI remediation is restricted to:
    - Dockerfile
    - app/
    - k8s/
- Only the requested file may be modified.
- AI must return structured JSON containing the complete corrected file.
- Groq requests use an explicit User-Agent to avoid HTTP 403 / error 1010
  caused by client/network filtering.

Provider transport:
- Both OpenAI and Groq are called through the plain Chat Completions API
  (POST /v1/chat/completions), NOT the Responses API.

  The Responses API returns the model's answer inside a variable, nested
  "output" array that can contain reasoning blocks, tool-call blocks, and
  message blocks in any order. Reliably picking the right nested field out
  of that array is what caused the repeated "no usable text output" /
  "invalid JSON" failures. Chat Completions always puts the answer in
  exactly one place: choices[0].message.content.

- Structured Outputs (response_format: json_schema, strict mode) is used
  so the provider is constrained to return ONLY a JSON object matching
  our schema -- no markdown fences, no explanatory prose, no reasoning
  text mixed into the answer. This is supported by both OpenAI and Groq
  (Groq: openai/gpt-oss-20b and openai/gpt-oss-120b support strict mode).

- parse_ai_json() is kept as a defensive fallback for any provider/model
  that does not honor response_format, so the script degrades gracefully
  instead of hard-failing.
"""

import argparse
import json
import os
import re
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# API configuration
# ---------------------------------------------------------------------------

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

REQUEST_TIMEOUT = 90

# Generous enough for a full Dockerfile / k8s manifest / app source file,
# without setting it so high that a stalled generation ties up the build.
MAX_OUTPUT_TOKENS = 8000

USER_AGENT = "ShiftLeftDevSecOps/1.0"

SYSTEM_PROMPT = (
    "You are a precise security remediation engine. You always respond "
    "with a single JSON object that matches the provided schema exactly. "
    "You never include markdown, code fences, or any text outside the "
    "JSON object."
)

# JSON Schema the model's answer must conform to. Used with Structured
# Outputs (strict mode where the provider supports it).
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {
            "type": "string",
            "description": "2-3 concise sentences explaining the security fix.",
        },
        "fixed_file_content": {
            "type": "string",
            "description": "The FULL corrected file content, nothing omitted.",
        },
    },
    "required": ["explanation", "fixed_file_content"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Path handling
# ---------------------------------------------------------------------------

def normalize_path(path):
    """
    Convert scanner/container paths into repository-relative paths.

    Examples:
        /repo/app/index.js     -> app/index.js
        /src/app/index.js      -> app/index.js
        /project/k8s/foo.yaml  -> k8s/foo.yaml
        ./app/index.js         -> app/index.js
    """

    if not isinstance(path, str):
        raise RuntimeError("File path must be a string")

    p = path.replace("\\", "/").strip()

    # Remove known scanner/container mount prefixes.
    prefixes = (
        "/src/",
        "/project/",
        "/repo/",
    )

    for prefix in prefixes:
        if p.startswith(prefix):
            p = p[len(prefix):]
            break

    # Remove leading ./ and / characters.
    p = p.lstrip("./")

    return p


def safe_path(path):
    """
    Allow AI remediation only for approved repository paths.
    """

    p = normalize_path(path)

    return (
        p == "Dockerfile"
        or p.startswith("app/")
        or p.startswith("k8s/")
    )


# ---------------------------------------------------------------------------
# AI response handling
# ---------------------------------------------------------------------------

def clean_json_response(text):
    """
    Remove accidental Markdown JSON code fences and surrounding whitespace.
    Only used as a fallback when structured output wasn't honored.
    """

    if not isinstance(text, str):
        raise RuntimeError("AI response is not text")

    text = text.strip()

    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    return text.strip()


def parse_ai_json(text):
    """
    Parse and validate the AI's JSON response.

    With Structured Outputs this should already be pure JSON. This
    function is a defensive fallback for providers/models that don't
    honor response_format and wrap the JSON in prose or code fences:

    - Pure JSON
    - JSON wrapped in Markdown fences
    - Explanatory text before/after the JSON object
    """

    if not isinstance(text, str):
        raise RuntimeError("AI response is not text")

    text = text.strip()

    if not text:
        raise RuntimeError(
            "AI provider returned an empty response body"
        )

    # ---------------------------------------------------------------
    # 1. Try the response exactly as returned
    # ---------------------------------------------------------------

    try:
        result = json.loads(text)

        if isinstance(result, dict):
            return result

    except json.JSONDecodeError:
        pass

    # ---------------------------------------------------------------
    # 2. Remove Markdown code fences
    # ---------------------------------------------------------------

    cleaned = clean_json_response(text)

    try:
        result = json.loads(cleaned)

        if isinstance(result, dict):
            return result

    except json.JSONDecodeError:
        pass

    # ---------------------------------------------------------------
    # 3. Find a JSON object inside surrounding text
    # ---------------------------------------------------------------

    decoder = json.JSONDecoder()

    for index, character in enumerate(cleaned):
        if character != "{":
            continue

        try:
            result, _ = decoder.raw_decode(cleaned[index:])

            if isinstance(result, dict):
                return result

        except json.JSONDecodeError:
            continue

    # ---------------------------------------------------------------
    # 4. Nothing valid was found
    # ---------------------------------------------------------------

    preview = cleaned[:500].replace("\n", "\\n")

    raise RuntimeError(
        "AI returned invalid JSON. "
        f"Response preview: {preview}"
    )


# ---------------------------------------------------------------------------
# Provider communication
# ---------------------------------------------------------------------------

def call_provider(url, key, model, prompt):
    """
    Call an OpenAI-compatible Chat Completions provider with Structured
    Outputs enabled, so the reply is constrained to our JSON schema.
    """

    if not key:
        raise RuntimeError(
            f"No API key configured for provider endpoint: {url}"
        )

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "security_remediation",
                "strict": True,
                "schema": RESPONSE_SCHEMA,
            },
        },
        "max_completion_tokens": MAX_OUTPUT_TOKENS,
    }

    request_data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=request_data,
        method="POST",
    )

    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {key}")

    # Explicit client identity. Important for Groq: some network
    # filtering can reject Python urllib's default client signature
    # with HTTP 403 / error code 1010.
    request.add_header("User-Agent", USER_AGENT)

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:

            raw_response = response.read().decode(
                "utf-8",
                errors="replace",
            )

            data = json.loads(raw_response)

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")

        # A 400 on a strict json_schema request usually means the model
        # doesn't support Structured Outputs. Retry once without it so
        # we still get a usable (unstructured) answer instead of failing
        # outright.
        if exc.code == 400 and "response_format" not in error_body:
            return _call_provider_unstructured(
                url, key, model, prompt
            )

        if exc.code == 400 and (
            "json_schema" in error_body or "response_format" in error_body
        ):
            return _call_provider_unstructured(
                url, key, model, prompt
            )

        # Do not expose API keys.
        raise RuntimeError(f"HTTP {exc.code}: {error_body}") from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    except TimeoutError as exc:
        raise RuntimeError("AI provider request timed out") from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError("AI provider returned invalid JSON") from exc

    return _parse_chat_completion(data)


def _call_provider_unstructured(url, key, model, prompt):
    """
    Fallback for providers/models that reject the strict json_schema
    response_format outright (HTTP 400). Falls back to best-effort
    json_object mode, which is far more broadly supported, and relies
    on parse_ai_json()'s defensive parsing.
    """

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "max_completion_tokens": MAX_OUTPUT_TOKENS,
    }

    request_data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(url, data=request_data, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {key}")
    request.add_header("User-Agent", USER_AGENT)

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:

            raw_response = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw_response)

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {error_body}") from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    except TimeoutError as exc:
        raise RuntimeError("AI provider request timed out") from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError("AI provider returned invalid JSON") from exc

    return _parse_chat_completion(data)


def _parse_chat_completion(data):
    """
    Extract and parse the JSON answer out of a Chat Completions response.

    Chat Completions always puts the answer in exactly one place:
        data["choices"][0]["message"]["content"]
    so there is no nested-structure guessing here, unlike the Responses
    API's "output" array.
    """

    if not isinstance(data, dict):
        raise RuntimeError("AI provider returned an invalid response object")

    choices = data.get("choices")

    if not isinstance(choices, list) or not choices:
        error = data.get("error")

        if isinstance(error, dict) and error.get("message"):
            raise RuntimeError(f"AI provider error: {error['message']}")

        raise RuntimeError(
            "AI provider returned no choices in the response"
        )

    message = choices[0].get("message") if isinstance(choices[0], dict) else None

    if not isinstance(message, dict):
        raise RuntimeError("AI provider response is missing a message")

    # A structured-output refusal surfaces here instead of content.
    refusal = message.get("refusal")

    if isinstance(refusal, str) and refusal.strip():
        raise RuntimeError(f"AI provider refused the request: {refusal}")

    content = message.get("content")

    if not isinstance(content, str) or not content.strip():
        finish_reason = choices[0].get("finish_reason", "unknown")

        raise RuntimeError(
            "AI provider returned no usable text output "
            f"(finish_reason={finish_reason})"
        )

    return parse_ai_json(content)


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------

def call_ai(prompt):
    """
    Use OpenAI first and Groq as fallback.

    OpenAI:
        Primary provider.

    Groq:
        Fallback provider.

    If OpenAI is unavailable because of quota/rate limits, the script
    automatically attempts Groq.
    """

    errors = []

    openai_key = os.environ.get("OPENAI_API_KEY")
    groq_key = os.environ.get("GROQ_API_KEY")

    # ---------------------------------------------------------------
    # OpenAI
    # ---------------------------------------------------------------

    if openai_key:
        try:
            result = call_provider(
                OPENAI_URL,
                openai_key,
                OPENAI_MODEL,
                prompt,
            )

            return result, "OpenAI"

        except Exception as exc:
            error_text = str(exc)

            if "credit_balance_exhausted" in error_text or (
                "HTTP 429" in error_text and "quota" in error_text.lower()
            ):
                errors.append(
                    "OpenAI: quota exhausted; using Groq fallback"
                )
            else:
                errors.append(f"OpenAI: {error_text}")

    # ---------------------------------------------------------------
    # Groq fallback
    # ---------------------------------------------------------------

    if groq_key:
        try:
            result = call_provider(
                GROQ_URL,
                groq_key,
                GROQ_MODEL,
                prompt,
            )

            return result, "Groq"

        except Exception as exc:
            errors.append(f"Groq: {exc}")

    # ---------------------------------------------------------------
    # No provider succeeded
    # ---------------------------------------------------------------

    if errors:
        raise RuntimeError(" | ".join(errors))

    raise RuntimeError("No AI provider credential configured")


# ---------------------------------------------------------------------------
# Single-file remediation
# ---------------------------------------------------------------------------

def fix_one(file_path, rule, message):
    """
    Generate one remediation for one approved file.
    """

    # Normalize scanner/container paths.
    file_path = normalize_path(file_path)

    # ---------------------------------------------------------------
    # Security boundary
    # ---------------------------------------------------------------

    if not safe_path(file_path):
        raise RuntimeError(
            "AI remediation is restricted to "
            "app/, k8s/, or Dockerfile: "
            f"{file_path}"
        )

    # ---------------------------------------------------------------
    # Secret protection
    # ---------------------------------------------------------------

    rule_lower = str(rule).lower()
    message_lower = str(message).lower()

    secret_indicators = (
        "gitleaks",
        "secret",
        "credential",
        "password",
        "private-key",
        "private_key",
        "api-key",
        "api_key",
    )

    if (
        any(indicator in rule_lower for indicator in secret_indicators)
        or any(indicator in message_lower for indicator in secret_indicators)
    ):
        raise RuntimeError(
            "Secret or credential findings are manual-only; "
            "their contents are never sent to an AI provider."
        )

    # ---------------------------------------------------------------
    # File existence
    # ---------------------------------------------------------------

    if not os.path.isfile(file_path):
        raise RuntimeError(f"File not found: {file_path}")

    # ---------------------------------------------------------------
    # Read source file
    # ---------------------------------------------------------------

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            original = file.read()

    except OSError as exc:
        raise RuntimeError(f"Unable to read file {file_path}: {exc}") from exc

    # ---------------------------------------------------------------
    # AI prompt
    # ---------------------------------------------------------------

    prompt = f"""
You are a security engineer proposing ONE safe remediation
for a CI security finding.

Security requirements:

1. Modify ONLY the supplied file.
2. Do not modify unrelated functionality.
3. Do not invent credentials.
4. Do not invent API keys.
5. Do not invent passwords.
6. Do not invent tokens.
7. Do not invent secrets.
8. Do not invent URLs.
9. Do not introduce dependencies unless absolutely required
   for the security fix.
10. Preserve the existing application's intended behavior.
11. Make the smallest reasonable security-focused change.
12. Return the COMPLETE corrected file content in "fixed_file_content".
13. Put a 2-3 sentence explanation of the fix in "explanation".

Finding:
file={file_path}
rule={rule}
message={message}

Current file:
<<<
{original}
>>>
"""

    # ---------------------------------------------------------------
    # Call AI
    # ---------------------------------------------------------------

    result, provider = call_ai(prompt)

    # ---------------------------------------------------------------
    # Validate response
    # ---------------------------------------------------------------

    fixed = result.get("fixed_file_content")
    explanation = result.get("explanation", "")

    if not isinstance(fixed, str):
        raise RuntimeError("AI returned an invalid fixed_file_content value")

    if not fixed.strip():
        raise RuntimeError("AI returned an empty fixed_file_content")

    if not isinstance(explanation, str):
        explanation = str(explanation)

    explanation = explanation.strip()

    if not explanation:
        explanation = (
            "AI generated a security-focused remediation "
            "for the reported finding."
        )

    return fixed, explanation, provider


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a single AI-assisted security remediation."
    )

    parser.add_argument("--file", required=True, help="Finding file path")
    parser.add_argument("--rule", required=True, help="Scanner rule or finding ID")
    parser.add_argument("--message", required=True, help="Finding message")
    parser.add_argument("--ticket-id", required=True, help="Dashboard ticket ID")

    args = parser.parse_args()

    # Some scanner outputs may append line/column information.
    file_path = normalize_path(args.file.split(":")[0])

    # ---------------------------------------------------------------
    # Generate remediation
    # ---------------------------------------------------------------

    fixed, explanation, provider = fix_one(
        file_path,
        args.rule,
        args.message,
    )

    # ---------------------------------------------------------------
    # Write corrected file
    # ---------------------------------------------------------------

    try:
        with open(file_path, "w", encoding="utf-8", newline="") as file:
            file.write(fixed)

    except OSError as exc:
        raise RuntimeError(
            f"Unable to write remediated file {file_path}: {exc}"
        ) from exc

    # ---------------------------------------------------------------
    # Save AI result for Jenkins PR stage
    # ---------------------------------------------------------------

    result_file = ".ai-fix-result.json"

    try:
        with open(result_file, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "provider": provider,
                    "explanation": explanation,
                    "file": file_path,
                    "ticket_id": args.ticket_id,
                },
                file,
                indent=2,
            )

    except OSError as exc:
        raise RuntimeError(f"Unable to write {result_file}: {exc}") from exc

    # ---------------------------------------------------------------
    # Console output
    # ---------------------------------------------------------------

    print(f"[ai-fix] Provider used: {provider}")
    print(f"[ai-fix] Applied proposed change to workspace: {file_path}")
    print(f"[ai-fix] Explanation: {explanation}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())