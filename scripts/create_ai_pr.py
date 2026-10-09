#!/usr/bin/env python3
"""Create or reuse the validated remediation PR for one dashboard ticket."""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from dashboard_callback import post_dashboard_callback

GITHUB_API = "https://api.github.com"
GITHUB_TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 1_000_000


def github_api(method, path, token, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(f"{GITHUB_API}{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=GITHUB_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"GitHub API {method} {path} could not be reached: {error.reason}") from error

    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError(f"GitHub API {method} {path} returned an oversized response")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"GitHub API {method} {path} returned invalid JSON") from error


def find_ticket_pull_request(repo, branch, token):
    owner = repo.split("/", 1)[0]
    query = urllib.parse.urlencode({
        "head": f"{owner}:{branch}",
        "base": "main",
        "state": "all",
        "per_page": "100",
    })
    matches = github_api("GET", f"/repos/{repo}/pulls?{query}", token)
    if not isinstance(matches, list):
        raise RuntimeError("GitHub returned an invalid pull-request list")
    return next((
        pull for pull in matches
        if pull.get("head", {}).get("ref") == branch
        and pull.get("base", {}).get("ref") == "main"
    ), None)


def notify_dashboard_pr_opened(callback, ticket, payload, callback_token):
    post_dashboard_callback(callback, ticket, "mark-pr-opened", payload, callback_token)


def create_or_reuse_pull_request(repo, branch, token, title, body):
    existing = find_ticket_pull_request(repo, branch, token)
    if existing:
        if existing.get("state") != "open":
            raise RuntimeError(
                f"Pull request #{existing.get('number')} already exists but is "
                f"{existing.get('state')}; refusing to create a duplicate"
            )
        print(f"[ai-pr] Reusing existing pull request #{existing.get('number')}", flush=True)
        return existing

    print("[ai-pr] No pull request exists for this ticket branch; creating one", flush=True)
    try:
        return github_api("POST", f"/repos/{repo}/pulls", token, {
            "title": title, "head": branch, "base": "main", "body": body,
        })
    except RuntimeError as error:
        # A concurrent retry or a lost POST response can create the PR before
        # the caller sees success. Re-query before reporting a failure.
        existing = find_ticket_pull_request(repo, branch, token)
        if existing and existing.get("state") == "open":
            print(f"[ai-pr] Found pull request #{existing.get('number')} after create response failure", flush=True)
            return existing
        raise error


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    branch = os.environ.get("AI_BRANCH", "")
    ticket = os.environ.get("TICKET_ID", "")
    rule = os.environ.get("RULE_ID", "")
    callback = os.environ.get("DASHBOARD_CALLBACK_URL", "")
    callback_token = os.environ.get("DASHBOARD_CALLBACK_TOKEN", "")

    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    if not re.fullmatch(r"[^/]+/[^/]+", repo):
        raise RuntimeError("GITHUB_REPOSITORY must be an owner/repository pair")
    if not ticket.isdigit() or branch != f"ai-remediation/ticket-{ticket}":
        raise RuntimeError("Ticket ID or isolated remediation branch is invalid")

    with open(".ai-fix-result.json", encoding="utf-8") as result_file:
        result = json.load(result_file)
    if (
        result.get("status") != "PASS"
        or result.get("test_status") != "PASS"
        or result.get("rescan_status") != "PASS"
        or str(result.get("ticket_id", "")) != ticket
        or result.get("branch") != branch
    ):
        raise RuntimeError("Validated test/rescan evidence and matching ticket branch are required before PR creation")

    explanation = result.get("analysis", "")
    remediation = result.get("proposed_remediation", "")
    title = f"Security fix: {rule} (ticket #{ticket})"
    body = f"""## AI-Suggested Security Fix

- Ticket: #{ticket}
- Rule: `{rule}`
- Vulnerability: `{result.get('vulnerability_id', rule)}` ({result.get('severity', 'UNKNOWN')})
- Validation: tests passed; target finding absent after rescanning; no new findings detected
- Provider/model: Groq / `{result.get('model', os.environ.get('GROQ_MODEL', 'configured Groq model'))}`
- Files changed: {', '.join(result.get('files_changed', []))}

**Analysis:** {explanation}

**Proposed remediation:** {remediation}

**Human review and merge are required. No automatic merge or deployment is performed.**
"""

    print(f"[ai-pr] Checking for an existing PR for {branch}", flush=True)
    pr = create_or_reuse_pull_request(repo, branch, token, title, body)
    url = pr.get("html_url", "")
    if not url:
        raise RuntimeError("GitHub returned a pull request without a URL")
    print(f"[ai-pr] PR ready for human review: {url}", flush=True)

    callback_payload = {
        "explanation": explanation,
        "remediation": remediation,
        "pr_url": url,
        "provider": "Groq",
    }
    with open(".ai-pr-result.json", "w", encoding="utf-8") as result_file:
        json.dump(callback_payload, result_file)

    print("[ai-pr] Updating authenticated dashboard callback", flush=True)
    notify_dashboard_pr_opened(callback, ticket, callback_payload, callback_token)


if __name__ == "__main__":
    main()
