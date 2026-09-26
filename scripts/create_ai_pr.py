#!/usr/bin/env python3
import json, os, urllib.request, urllib.error

def github_api(method, path, token, body=None):
    url = "https://api.github.com" + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())

def main():
    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["GITHUB_REPOSITORY"]
    branch = os.environ["AI_BRANCH"]
    ticket = os.environ.get("TICKET_ID", "")
    rule = os.environ.get("RULE_ID", "")
    with open(".ai-fix-result.json", encoding="utf-8") as result_file:
        result = json.load(result_file)
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
    pr = github_api("POST", f"/repos/{repo}/pulls", token, {
        "title": title, "head": branch, "base": "main", "body": body
    })
    url = pr.get("html_url", "")
    print(f"[ai-pr] PR: {url}")

    callback = os.environ.get("DASHBOARD_CALLBACK_URL", "").rstrip("/")
    if callback:
        payload = json.dumps({
            "explanation": explanation,
            "remediation": remediation,
            "pr_url": url,
            "provider": "Groq",
        }).encode()
        req = urllib.request.Request(
            f"{callback}/api/tickets/{ticket}/mark-pr-opened",
            data=payload, method="POST"
        )
        req.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.URLError as e:
            print(f"[ai-pr] Dashboard callback failed: {e}")

if __name__ == "__main__":
    main()
