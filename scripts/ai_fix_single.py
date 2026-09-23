#!/usr/bin/env python3
"""AI remediation helper with OpenAI-primary / Groq-fallback provider adapter.

Secrets are read only from environment variables. Gitleaks findings are never
sent to an external model because their file content may contain credentials.
"""

import argparse
import json
import os
import re
import urllib.request
import urllib.error


OPENAI_URL = "https://api.openai.com/v1/responses"
GROQ_URL = "https://api.groq.com/openai/v1/responses"

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")


def normalize_path(path):
    """Convert scanner/container paths into repository-relative paths."""
    p = path.replace("\\", "/").strip()

    # Scanner/container mount prefixes.
    for prefix in ("/src/", "/project/", "/repo/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break

    # Normalize leading ./ or / characters.
    p = p.lstrip("./")

    return p


def safe_path(path):
    """Allow AI remediation only for approved repository paths."""
    p = normalize_path(path)

    return p == "Dockerfile" or p.startswith(("app/", "k8s/"))


def extract_output(data):
    """Extract text from the OpenAI-compatible Responses API response."""
    if data.get("output_text"):
        return data["output_text"]

    parts = []

    for item in data.get("output", []):
        for content in item.get("content", []) or []:
            if content.get("type") in ("output_text", "text"):
                parts.append(content.get("text", ""))

    return "".join(parts)


def call_provider(url, key, model, prompt):
    """Call an OpenAI-compatible AI provider."""
    body = {
        "model": model,
        "input": prompt,
        "store": False,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
    )

    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {key}")

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {e.code}: {body}"
        ) from e

    text = extract_output(data).strip()

    # Remove accidental Markdown JSON fences.
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    return json.loads(text)


def call_ai(prompt):
    """Use OpenAI first and Groq as fallback."""
    errors = []

    if os.environ.get("OPENAI_API_KEY"):
        try:
            return (
                call_provider(
                    OPENAI_URL,
                    os.environ["OPENAI_API_KEY"],
                    OPENAI_MODEL,
                    prompt,
                ),
                "OpenAI",
            )
        except Exception as e:
            errors.append(f"OpenAI: {e}")

    if os.environ.get("GROQ_API_KEY"):
        try:
            return (
                call_provider(
                    GROQ_URL,
                    os.environ["GROQ_API_KEY"],
                    GROQ_MODEL,
                    prompt,
                ),
                "Groq",
            )
        except Exception as e:
            errors.append(f"Groq: {e}")

    if errors:
        raise RuntimeError(" | ".join(errors))

    raise RuntimeError("No AI provider credential configured")


def fix_one(file_path, rule, message):
    """Generate one remediation for one approved file."""

    # Normalize paths coming from scanners such as /src/app/index.js.
    file_path = normalize_path(file_path)

    # Keep the AI remediation boundary.
    if not safe_path(file_path):
        raise RuntimeError(
            "AI remediation is restricted to app/, k8s/, or Dockerfile: "
            f"{file_path}"
        )

    # Secrets must never be sent to an external AI provider.
    if rule.lower().startswith("gitleaks") or "secret" in rule.lower():
        raise RuntimeError(
            "Secret findings are manual-only; their contents are never "
            "sent to an AI provider."
        )

    if not os.path.exists(file_path):
        raise RuntimeError(f"File not found: {file_path}")

    with open(file_path, encoding="utf-8") as f:
        original = f.read()

    prompt = f"""You are a security engineer proposing ONE safe remediation for a CI finding.

Never invent credentials, tokens, secrets, URLs, or unrelated changes.
Do not modify files other than the supplied file.

Return only JSON with:
{{"explanation":"2-3 concise sentences","fixed_file_content":"FULL corrected file content"}}

Finding:
file={file_path}
rule={rule}
message={message}

Current file:
<<<
{original}
>>>
"""

    result, provider = call_ai(prompt)

    fixed = result.get("fixed_file_content")
    explanation = result.get("explanation", "")

    if not isinstance(fixed, str) or not fixed.strip():
        raise RuntimeError("AI returned no usable fixed_file_content")

    return fixed, explanation, provider


def main():
    parser = argparse.ArgumentParser()

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

    # Some scanner outputs may append a line/column suffix.
    file_path = args.file.split(":")[0]

    fixed, explanation, provider = fix_one(
        file_path,
        args.rule,
        args.message,
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed)

    with open(".ai-fix-result.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "provider": provider,
                "explanation": explanation,
                "file": file_path,
            },
            f,
        )

    print(f"[ai-fix] Provider used: {provider}")
    print(f"[ai-fix] Applied proposed change to workspace: {file_path}")
    print(f"[ai-fix] Explanation: {explanation}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())