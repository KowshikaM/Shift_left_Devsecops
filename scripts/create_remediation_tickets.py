#!/usr/bin/env python3
"""
Creates a GitHub Issue for each CRITICAL/HIGH finding that doesn't already
have an open issue (matched via a hidden marker in the issue body, so
re-runs of the pipeline don't spam duplicates).

Requires env vars (set as Jenkins credentials / pipeline env):
  GITHUB_TOKEN       - a GitHub Personal Access Token with 'repo' scope
  GITHUB_REPOSITORY  - "owner/repo"
"""

import json
import os
import urllib.request
import urllib.error

GENERIC_HINTS = {
    "trivy": "Upgrade the affected package to the patched version shown in the CVE advisory, or move to an updated/minimal base image.",
    "semgrep": "Review the flagged code path; typically requires input validation, parameterized queries, or removing the unsafe pattern.",
    "gitleaks": "Revoke/rotate the exposed credential immediately, remove it from the code, and load it from a secrets manager or environment variable instead.",
    "opa-policy": "Update the Dockerfile or Kubernetes manifest to comply with the policy (e.g. add a non-root user, set resource limits).",
}


def classify_finding(source, rule_id, file_name, message):
    return {
        "classification": "MANUAL",
        "why": "This ticket is HIGH/CRITICAL and is never eligible for automatic AI remediation.",
        "plan": [
            "Investigate the finding and affected file manually.",
            "Rotate any exposed secret immediately and remove it from source control.",
            "Create a focused fix with appropriate regression coverage.",
            "Re-run the required scanners and tests, then submit the change for human review."
        ],
    }


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default if default is not None else {}


def gather_findings():
    findings = []

    trivy = load_json("trivy-results.json", default={})
    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            if vuln.get("Severity") in ("CRITICAL", "HIGH"):
                pkg = vuln.get("PkgName", "")
                classification = classify_finding("trivy", vuln.get("VulnerabilityID", ""), pkg, vuln.get("Title", ""))
                findings.append({
                    "marker": f"trivy:{vuln.get('VulnerabilityID')}:{pkg}",
                    "title": f"[Security] {vuln.get('VulnerabilityID')} in {pkg} ({vuln.get('Severity')})",
                    "body": (
                        f"**Source:** Trivy container scan\n"
                        f"**Package:** {pkg} {vuln.get('InstalledVersion','')}\n"
                        f"**Fixed in:** {vuln.get('FixedVersion','N/A')}\n"
                        f"**Severity:** {vuln.get('Severity')}\n"
                        f"**Classification:** {classification['classification']}\n"
                        f"**Why this happened:** {classification['why']}\n\n"
                        f"**Remediation steps:**\n"
                        + "\n".join(f"{i+1}. {step}" for i, step in enumerate(classification['plan'])) + "\n\n"
                        f"**Suggested remediation:** {GENERIC_HINTS['trivy']}\n"
                    ),
                })

    semgrep = load_json("semgrep-results.json", default={})
    for res in semgrep.get("results", []):
        if res.get("extra", {}).get("severity", "").upper() == "ERROR":
            classification = classify_finding("semgrep", res.get("check_id", ""), res.get("path", ""), res.get("extra", {}).get("message", ""))
            findings.append({
                "marker": f"semgrep:{res.get('check_id')}:{res.get('path')}:{res.get('start',{}).get('line')}",
                "title": f"[Security] SAST finding: {res.get('check_id')}",
                "body": (
                    f"**Source:** Semgrep SAST\n"
                    f"**File:** {res.get('path')}:{res.get('start', {}).get('line')}\n\n"
                    f"{res.get('extra', {}).get('message', '')}\n"
                    f"**Classification:** {classification['classification']}\n"
                    f"**Why this happened:** {classification['why']}\n\n"
                    f"**Remediation steps:**\n"
                    + "\n".join(f"{i+1}. {step}" for i, step in enumerate(classification['plan'])) + "\n\n"
                    f"**Suggested remediation:** {GENERIC_HINTS['semgrep']}\n"
                ),
            })

    gitleaks = load_json("gitleaks-results.json", default=[])
    for leak in (gitleaks if isinstance(gitleaks, list) else []):
        classification = classify_finding("gitleaks", leak.get("RuleID", ""), leak.get("File", ""), leak.get("Description", ""))
        findings.append({
            "marker": f"gitleaks:{leak.get('File')}:{leak.get('RuleID')}",
            "title": f"[Security] Hardcoded secret detected in {leak.get('File')}",
            "body": (
                f"**Source:** Gitleaks secret scan\n"
                f"**File:** {leak.get('File')}\n"
                f"**Rule:** {leak.get('RuleID')}\n"
                f"**Classification:** {classification['classification']}\n"
                f"**Why this happened:** {classification['why']}\n\n"
                f"**Remediation steps:**\n"
                + "\n".join(f"{i+1}. {step}" for i, step in enumerate(classification['plan'])) + "\n\n"
                f"**Suggested remediation:** {GENERIC_HINTS['gitleaks']}\n"
            ),
        })

    for path, label in [("dockerfile-policy-results.json", "Dockerfile"),
                         ("k8s-policy-results.json", "Kubernetes")]:
        policy = load_json(path, default=[])
        entries = policy if isinstance(policy, list) else [policy]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                msg = str(failure.get("msg", failure))
                classification = classify_finding(label, msg, entry.get("filename", label), msg)
                findings.append({
                    "marker": f"policy:{label}:{msg[:60]}",
                    "title": f"[Security] {label} policy violation",
                    "body": (
                        f"**Source:** OPA/Conftest ({label})\n"
                        f"**File:** {entry.get('filename', label)}\n\n"
                        f"{msg}\n"
                        f"**Classification:** {classification['classification']}\n"
                        f"**Why this happened:** {classification['why']}\n\n"
                        f"**Remediation steps:**\n"
                        + "\n".join(f"{i+1}. {step}" for i, step in enumerate(classification['plan'])) + "\n\n"
                        f"**Suggested remediation:** {GENERIC_HINTS['opa-policy']}\n"
                    ),
                })

    return findings


def github_api(method, path, token, body=None):
    url = f"https://api.github.com{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[tickets] GitHub API error {e.code}: {e.read().decode()}")
        return None


def existing_markers(token, repo):
    issues = github_api("GET", f"/repos/{repo}/issues?state=open&labels=auto-security&per_page=100", token) or []
    markers = set()
    for issue in issues:
        for line in (issue.get("body", "") or "").splitlines():
            if line.startswith("<!-- marker:"):
                markers.add(line.replace("<!-- marker:", "").replace("-->", "").strip())
    return markers


def main():
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")

    findings = gather_findings()
    if not findings:
        print("[tickets] No CRITICAL/HIGH findings - no tickets needed.")
        return

    if not token or not repo:
        print("[tickets] DRY RUN (GITHUB_TOKEN / GITHUB_REPOSITORY not set). Would create:")
        for f in findings:
            print(f"  - {f['title']}")
        return

    already_open = existing_markers(token, repo)
    created = 0

    for f in findings:
        if f["marker"] in already_open:
            continue
        body = f["body"] + f"\n<!-- marker: {f['marker']} -->"
        result = github_api("POST", f"/repos/{repo}/issues", token, {
            "title": f["title"], "body": body, "labels": ["auto-security", "security"],
        })
        if result:
            created += 1
            print(f"[tickets] Created issue #{result.get('number')}: {f['title']}")

    print(f"[tickets] Done. {created} new issue(s) created, {len(findings) - created} already existed.")


if __name__ == "__main__":
    main()
