#!/usr/bin/env python3
"""Publish the current Jenkins pipeline state and, when requested, findings."""
import json
import os
import urllib.request
import urllib.error
from remediation_policy import load_scanner_findings

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:2001")
SCANNER_SOURCES = {"semgrep", "gitleaks", "trivy", "opa-policy"}


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default if default is not None else {}


def remediation_profile(finding):
    eligible = finding.get("ai_eligible", False)
    if finding["source"] == "gitleaks":
        reason = "This finding may expose secret material. Rotate it and remove it from source control; never send its value to AI."
        guide = (
            "Why this happened: a credential or private secret was committed into the repository.\n"
            "What went wrong: a repository-visible credential may be reused by an attacker.\n"
            "How to fix it: revoke or rotate the credential first, remove it from the codebase and history as appropriate, then load future values from a secret manager.\n"
            "Verification: rerun Gitleaks and confirm that no active copy remains."
        )
    elif eligible:
        reason = "LOW and MEDIUM non-secret findings may receive a constrained Groq remediation proposal; a human reviews the resulting PR."
        guide = (
            "Why this happened: a scanner identified a LOW or MEDIUM security issue.\n"
            "What went wrong: the affected code or dependency may not meet the expected secure baseline.\n"
            "How to fix it: use Apply AI fix to request a one-file proposal. The controller checks the patch, runs tests, rescans, and creates a PR only when validation succeeds.\n"
            "Verification: review the changed file and PR, then confirm the normal release pipeline passes before deployment."
        )
    else:
        reason = "HIGH, CRITICAL, secret, and otherwise ineligible findings require developer-led remediation and review."
        guide = (
            "Why this happened: the scanner identified an issue that is outside the LOW/MEDIUM automation policy.\n"
            "What went wrong: the issue may have significant security or behavior impact and must not be changed automatically.\n"
            "How to fix it: inspect the finding and affected file, apply a focused developer-reviewed fix, and add regression coverage where appropriate.\n"
            "Verification: rerun the relevant scanner and tests; the main security gate must pass before release."
        )
    return {
        "remediation_type": "AI_ELIGIBLE" if eligible else "MANUAL",
        "before_status": "BLOCKED", "after_status": "PENDING",
        "validation_summary": "Before: finding detected. After: remediation has not yet been validated.",
        "remediation_reason": reason, "remediation_guide": guide,
    }


def collect_findings():
    findings = []
    requested_sources = {
        source.strip().lower()
        for source in os.environ.get("PUBLISH_SCANNERS", "").split(",")
        if source.strip()
    }
    unknown_sources = requested_sources - SCANNER_SOURCES
    if unknown_sources:
        raise ValueError(f"Unsupported scanner source(s): {', '.join(sorted(unknown_sources))}")

    for item in load_scanner_findings("."):
        if requested_sources and item["source"].lower() not in requested_sources:
            continue
        profile = remediation_profile(item)
        file_path = item["affected_file"]
        if item.get("affected_line"):
            file_path = f"{file_path}:{item['affected_line']}"
        findings.append({
            "source": item["source"], "severity": item["severity"],
            "file_path": file_path, "rule_id": item["rule_id"],
            "vulnerability_id": item["vulnerability_id"],
            "package_name": item["package_name"],
            "installed_version": item["installed_version"],
            "affected_line": item["affected_line"],
            "scanner_recommendation": item["scanner_recommendation"],
            "message": item["description"], "fixed_version": item["fixed_version"] or "-",
            "ai_analysis": "", "proposed_remediation": "", "files_changed": "[]",
            "test_status": "NOT_RUN", "rescan_status": "NOT_RUN",
            "remediation_status": "PENDING", **profile,
        })
    return findings


def read_gate_status():
    # gate-status.txt is the authoritative result produced by Security Gate.
    if os.path.exists("gate-status.txt"):
        try:
            with open("gate-status.txt", encoding="utf-8") as f:
                value = f.read().strip().upper()
            if value in ("PASS", "FAIL"):
                return value
        except OSError:
            pass

    # Fall back to Jenkins environment variable.
    value = os.environ.get("GATE_STATUS", "").strip().upper()
    if value in ("PASS", "FAIL"):
        return value

    return "PENDING"


def main():
    findings_complete = os.environ.get("PUBLISH_FINDINGS", "0") == "1"
    findings = collect_findings() if findings_complete else []
    scan_scope = sorted({
        source.strip().lower()
        for source in os.environ.get("PUBLISH_SCANNERS", "").split(",")
        if source.strip()
    }) or sorted(SCANNER_SOURCES)
    payload = {
        "build_number": os.environ.get("DASHBOARD_BUILD_NUMBER", os.environ.get("BUILD_NUMBER", "local")),
        "commit_sha": os.environ.get("GIT_COMMIT", ""),
        "branch": os.environ.get("GIT_BRANCH", "main"),
        "triggered_by": os.environ.get("BUILD_USER", "jenkins"),
        "gate_status": os.environ.get("DASHBOARD_GATE_STATUS") or read_gate_status(),
        "pipeline_status": os.environ.get(
            "DASHBOARD_PIPELINE_STATUS", os.environ.get("PIPELINE_STATUS", "RUNNING")
        ),
        "current_stage": os.environ.get("PIPELINE_STAGE", ""),
        "jenkins_url": os.environ.get("BUILD_URL", ""),
        "deployed": os.environ.get("DEPLOYED", "0") == "1",
        "findings_complete": findings_complete,
        "scan_scope": scan_scope,
        "findings": findings,
    }

    body = json.dumps(payload).encode("utf-8")
    api_path = os.environ.get("DASHBOARD_API_PATH", "/api/builds")
    if not api_path.startswith("/") or "://" in api_path:
        raise ValueError("DASHBOARD_API_PATH must be a local URL path")
    req = urllib.request.Request(f"{DASHBOARD_URL.rstrip('/')}{api_path}", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    ingest_token = os.environ.get("DASHBOARD_INGEST_TOKEN", "")
    if ingest_token:
        req.add_header("Authorization", f"Bearer {ingest_token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            print(f"[publish] Dashboard build id={result.get('build_id')} stage={payload['current_stage']} status={payload['pipeline_status']} gate={payload['gate_status']}")
    except urllib.error.HTTPError as e:
        print(f"[publish] Dashboard rejected update: HTTP {e.code} {e.reason}")
        if os.environ.get("PUBLISH_REQUIRED", "0") == "1":
            raise SystemExit(1) from e
        print("[publish] Dashboard update skipped; pipeline continues.")
    except urllib.error.URLError as e:
        print(f"[publish] Could not reach dashboard-service at {DASHBOARD_URL}: {e}")
        if os.environ.get("PUBLISH_REQUIRED", "0") == "1":
            raise SystemExit(1) from e
        print("[publish] Dashboard update skipped; pipeline continues.")


if __name__ == "__main__":
    main()
