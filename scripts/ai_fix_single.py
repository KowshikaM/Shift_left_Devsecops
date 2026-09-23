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

OPENAI_URL = "https://api.openai.com/v1/responses"
GROQ_URL = "https://api.groq.com/openai/v1/responses"

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

REQUEST_TIMEOUT = 90

USER_AGENT = "ShiftLeftDevSecOps/1.0"


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

def extract_output(data):
    """
    Extract text from an OpenAI-compatible Responses API response.

    Supports:
    - output_text
    - output[].content[].text
    - output[].content[].output_text
    """

    if not isinstance(data, dict):
        raise RuntimeError("AI provider returned an invalid response object")

    # Standard Responses API convenience field.
    output_text = data.get("output_text")

    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    parts = []

    for item in data.get("output", []) or []:
        if not isinstance(item, dict):
            continue

        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue

            content_type = content.get("type")

            if content_type in ("output_text", "text"):
                text = content.get("text", "")

                if isinstance(text, str):
                    parts.append(text)

    result = "".join(parts).strip()

    if not result:
        raise RuntimeError(
            "AI provider returned no usable text output"
        )

    return result


def clean_json_response(text):
    """
    Remove accidental Markdown JSON code fences and surrounding whitespace.
    """

    if not isinstance(text, str):
        raise RuntimeError("AI response is not text")

    text = text.strip()

    # Remove ```json ... ```
    text = re.sub(
        r"^```json\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )

    # Remove ``` ... ```
    text = re.sub(
        r"^```\s*",
        "",
        text,
    )

    text = re.sub(
        r"\s*```$",
        "",
        text,
    )

    return text.strip()


def parse_ai_json(text):
    """
    Parse and validate the AI's JSON response.
    """

    cleaned = clean_json_response(text)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"AI returned invalid JSON: {exc}"
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError(
            "AI response must be a JSON object"
        )

    return result


# ---------------------------------------------------------------------------
# Provider communication
# ---------------------------------------------------------------------------

def call_provider(url, key, model, prompt):
    """
    Call an OpenAI-compatible Responses API provider.

    The explicit User-Agent is important for Groq because some network
    filtering can reject Python urllib's default client signature with
    HTTP 403 / error code 1010.
    """

    if not key:
        raise RuntimeError(
            f"No API key configured for provider endpoint: {url}"
        )

    body = {
        "model": model,
        "input": prompt,
        "store": False,
    }

    request_data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=request_data,
        method="POST",
    )

    request.add_header(
        "Content-Type",
        "application/json",
    )

    request.add_header(
        "Authorization",
        f"Bearer {key}",
    )

    # Explicit client identity.
    request.add_header(
        "User-Agent",
        USER_AGENT,
    )

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
        error_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        # Do not expose API keys.
        raise RuntimeError(
            f"HTTP {exc.code}: {error_body}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Network error: {exc.reason}"
        ) from exc

    except TimeoutError as exc:
        raise RuntimeError(
            "AI provider request timed out"
        ) from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "AI provider returned invalid JSON"
        ) from exc

    text = extract_output(data)

    return parse_ai_json(text)


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
            errors.append(
                f"OpenAI: {exc}"
            )

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
            errors.append(
                f"Groq: {exc}"
            )

    # ---------------------------------------------------------------
    # No provider succeeded
    # ---------------------------------------------------------------

    if errors:
        raise RuntimeError(
            " | ".join(errors)
        )

    raise RuntimeError(
        "No AI provider credential configured"
    )


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
        raise RuntimeError(
            f"File not found: {file_path}"
        )

    # ---------------------------------------------------------------
    # Read source file
    # ---------------------------------------------------------------

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
        ) as file:

            original = file.read()

    except OSError as exc:
        raise RuntimeError(
            f"Unable to read file {file_path}: {exc}"
        ) from exc

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
12. Return the COMPLETE corrected file content.
13. Do not return Markdown.
14. Return valid JSON only.

Required JSON structure:

{{
    "explanation": "2-3 concise sentences explaining the security fix",
    "fixed_file_content": "FULL corrected file content"
}}

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
        raise RuntimeError(
            "AI returned an invalid fixed_file_content value"
        )

    if not fixed.strip():
        raise RuntimeError(
            "AI returned an empty fixed_file_content"
        )

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

    parser.add_argument(
        "--file",
        required=True,
        help="Finding file path",
    )

    parser.add_argument(
        "--rule",
        required=True,
        help="Scanner rule or finding ID",
    )

    parser.add_argument(
        "--message",
        required=True,
        help="Finding message",
    )

    parser.add_argument(
        "--ticket-id",
        required=True,
        help="Dashboard ticket ID",
    )

    args = parser.parse_args()

    # Some scanner outputs may append line/column information.
    file_path = args.file.split(":")[0]

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
        with open(
            file_path,
            "w",
            encoding="utf-8",
            newline="",
        ) as file:

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
        with open(
            result_file,
            "w",
            encoding="utf-8",
        ) as file:

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
        raise RuntimeError(
            f"Unable to write {result_file}: {exc}"
        ) from exc

    # ---------------------------------------------------------------
    # Console output
    # ---------------------------------------------------------------

    print(
        f"[ai-fix] Provider used: {provider}"
    )

    print(
        f"[ai-fix] Applied proposed change to workspace: {file_path}"
    )

    print(
        f"[ai-fix] Explanation: {explanation}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())