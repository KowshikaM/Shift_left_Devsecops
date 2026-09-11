#!/usr/bin/env python3
"""
Publish to Dashboard
---------------------
Reads all the scanner result files produced in this pipeline run, packages
them into one payload, and POSTs it to the dashboard-service so it gets
saved permanently in the database and shown on the live dashboard.

Requires env vars (Jenkins provides most of these automatically):
  DASHBOARD_URL   - e.g. http://localhost:2001   (REPLACE with your real URL)
  BUILD_NUMBER, GIT_COMMIT, GIT_BRANCH, BUILD_USER (optional)
  GATE_STATUS     - 'PASS' or 'FAIL', read from gate-status.txt if not set
  DEPLOYED        - '1' if the deploy stage ran, else '0'
"""

import json
import os
import urllib.request
import urllib.error

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:2001")  # REPLACE ME


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default if default is not None else {}


def collect_findings():
    findings = []

    trivy = load_json("trivy-results.json", default={})
    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "source": "trivy", "severity": vuln.get("Severity", "LOW"),
                "file_path": vuln.get("PkgName", ""), "rule_id": vuln.get("VulnerabilityID", ""),
                "message": vuln.get("Title", ""), "fixed_version": vuln.get("FixedVersion", "-"),
            })

    semgrep = load_json("semgrep-results.json", default={})
    for res in semgrep.get("results", []):
        sev_raw = res.get("extra", {}).get("severity", "INFO").upper()
        sev = "HIGH" if sev_raw == "ERROR" else ("MEDIUM" if sev_raw == "WARNING" else "LOW")
        findings.append({
            "source": "semgrep", "severity": sev,
            "file_path": f'{res.get("path","")}:{res.get("start",{}).get("line","")}',
            "rule_id": res.get("check_id", ""), "message": res.get("extra", {}).get("message", ""),
            "fixed_version": "-",
        })

    gitleaks = load_json("gitleaks-results.json", default=[])
    for leak in (gitleaks if isinstance(gitleaks, list) else []):
        findings.append({
            "source": "gitleaks", "severity": "CRITICAL",
            "file_path": leak.get("File", ""), "rule_id": leak.get("RuleID", "secret"),
            "message": leak.get("Description", "Possible hardcoded credential"), "fixed_version": "-",
        })

    for path, label in [("dockerfile-policy-results.json", "Dockerfile"),
                         ("k8s-policy-results.json", "Kubernetes")]:
        policy = load_json(path, default=[])
        entries = policy if isinstance(policy, list) else [policy]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                findings.append({
                    "source": "opa-policy", "severity": "HIGH",
                    "file_path": entry.get("filename", label), "rule_id": label,
                    "message": str(failure.get("msg", failure)), "fixed_version": "-",
                })

    return findings


def read_gate_status():
    if os.environ.get("GATE_STATUS"):
        return os.environ["GATE_STATUS"]
    if os.path.exists("gate-status.txt"):
        with open("gate-status.txt") as f:
            return f.read().strip()
    return "FAIL"


def main():
    payload = {
        "build_number": os.environ.get("BUILD_NUMBER", "local"),
        "commit_sha": os.environ.get("GIT_COMMIT", ""),
        "branch": os.environ.get("GIT_BRANCH", "main"),
        "triggered_by": os.environ.get("BUILD_USER", "jenkins"),
        "gate_status": read_gate_status(),
        "deployed": os.environ.get("DEPLOYED", "0") == "1",
        "findings": collect_findings(),
    }

    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{DASHBOARD_URL}/api/builds", data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            print(f"[publish] Build recorded as id={result.get('build_id')} on dashboard-service.")
    except urllib.error.URLError as e:
        print(f"[publish] Could not reach dashboard-service at {DASHBOARD_URL}: {e}")
        print("[publish] Is 'docker compose up -d' running? Continuing without blocking the pipeline.")


if __name__ == "__main__":
    main()
