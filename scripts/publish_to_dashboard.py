#!/usr/bin/env python3
"""Publish the current Jenkins pipeline state and, when requested, findings."""
import json
import os
import urllib.request
import urllib.error

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:2001")


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default if default is not None else {}


def collect_findings():
    findings = []

    trivy = load_json("trivy-results.json", default={})
    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "source": "trivy", "severity": vuln.get("Severity", "LOW"),
                "file_path": vuln.get("PkgName", ""),
                "rule_id": vuln.get("VulnerabilityID", ""),
                "message": vuln.get("Title", ""),
                "fixed_version": vuln.get("FixedVersion", "-"),
            })

    semgrep = load_json("semgrep-results.json", default={})
    for res in semgrep.get("results", []):
        sev_raw = str(res.get("extra", {}).get("severity", "INFO")).upper()
        sev = "HIGH" if sev_raw == "ERROR" else ("MEDIUM" if sev_raw == "WARNING" else "LOW")
        findings.append({
            "source": "semgrep", "severity": sev,
            "file_path": f'{res.get("path", "")}:{res.get("start", {}).get("line", "")}',
            "rule_id": res.get("check_id", ""),
            "message": res.get("extra", {}).get("message", ""),
            "fixed_version": "-",
        })

    gitleaks = load_json("gitleaks-results.json", default=[])
    for leak in (gitleaks if isinstance(gitleaks, list) else []):
        findings.append({
            "source": "gitleaks", "severity": "CRITICAL",
            "file_path": leak.get("File", ""),
            "rule_id": leak.get("RuleID", "secret"),
            "message": leak.get("Description", "Possible hardcoded credential"),
            "fixed_version": "-",
        })

    for path, label in [("dockerfile-policy-results.json", "Dockerfile"),
                        ("k8s-policy-results.json", "Kubernetes")]:
        policy = load_json(path, default=[])
        entries = policy if isinstance(policy, list) else [policy]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                findings.append({
                    "source": "opa-policy", "severity": "HIGH",
                    "file_path": entry.get("filename", label),
                    "rule_id": label,
                    "message": str(failure.get("msg", failure)),
                    "fixed_version": "-",
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
    payload = {
        "build_number": os.environ.get("BUILD_NUMBER", "local"),
        "commit_sha": os.environ.get("GIT_COMMIT", ""),
        "branch": os.environ.get("GIT_BRANCH", "main"),
        "triggered_by": os.environ.get("BUILD_USER", "jenkins"),
        "gate_status": read_gate_status(),
        "pipeline_status": os.environ.get("PIPELINE_STATUS", "RUNNING"),
        "current_stage": os.environ.get("PIPELINE_STAGE", ""),
        "jenkins_url": os.environ.get("BUILD_URL", ""),
        "deployed": os.environ.get("DEPLOYED", "0") == "1",
        "findings_complete": findings_complete,
        "findings": findings,
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{DASHBOARD_URL}/api/builds", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            print(f"[publish] Dashboard build id={result.get('build_id')} stage={payload['current_stage']} status={payload['pipeline_status']} gate={payload['gate_status']}")
    except urllib.error.URLError as e:
        print(f"[publish] Could not reach dashboard-service at {DASHBOARD_URL}: {e}")
        print("[publish] Dashboard update skipped; pipeline continues.")


if __name__ == "__main__":
    main()
