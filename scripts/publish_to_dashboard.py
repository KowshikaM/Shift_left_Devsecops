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


def remediation_profile(source, severity, message="", rule_id="", file_path=""):
    text = " ".join([source or "", message or "", rule_id or "", file_path or ""]).lower()

    if "gitleaks" in text or "secret" in text or "api key" in text or "token" in text or "credential" in text:
        return {
            "remediation_type": "MANUAL",
            "before_status": "BLOCKED",
            "after_status": "PENDING",
            "validation_summary": "Before: blocked by secret exposure. After: pending until the secret is removed and Gitleaks passes.",
            "remediation_reason": "This issue exposes secret material or sensitive credentials and should never be sent to an AI provider.",
            "remediation_guide": (
                "Why this happened: a credential or private secret was committed into the repository or configuration.\n"
                "What went wrong: the secret is now visible in source control and may be reused by attackers.\n"
                "How to fix it: revoke or rotate the credential, remove it from the codebase, replace it with a secret manager or environment variable, and confirm no copies remain.\n"
                "Verification: re-run Gitleaks, confirm the secret is gone, and then perform a clean security review before merge."
            ),
        }

    if "opa-policy" in text or "kubernetes" in text or "dockerfile" in text or "resource limit" in text or "run as non root" in text or "allow privilege escalation" in text:
        return {
            "remediation_type": "AI_ELIGIBLE",
            "before_status": "BLOCKED",
            "after_status": "PENDING",
            "validation_summary": "Before: blocked by policy check. After: pending until the AI patch is validated by Jenkins and the security gate passes.",
            "remediation_reason": "This is a deterministic security hardening fix that can be safely generated and re-validated by the pipeline.",
            "remediation_guide": (
                "Why this happened: the container or deployment configuration is missing a standard hardening requirement.\n"
                "What went wrong: the manifest violates the organization policy for secure execution.\n"
                "How to fix it: add the required resource limits, runAsNonRoot settings, or Dockerfile hardening changes.\n"
                "Verification: re-run the policy check and full security gate; if the scan goes PASS, the fix is ready for human review."
            ),
        }

    if "sql injection" in text or "command injection" in text or "path traversal" in text or "xss" in text or "unsafe deserialization" in text:
        return {
            "remediation_type": "MANUAL",
            "before_status": "BLOCKED",
            "after_status": "PENDING",
            "validation_summary": "Before: blocked by application-level injection finding. After: pending until the developer implements and validates the fix.",
            "remediation_reason": "This is application-level logic or validation work that affects business behavior and requires a developer review.",
            "remediation_guide": (
                "Why this happened: untrusted user input is being used in a dangerous sink without adequate validation or parameterization.\n"
                "What went wrong: the application logic is vulnerable to attacker-controlled input and may allow data theft or command execution.\n"
                "How to fix it: identify the unsafe input flow, replace string concatenation with parameterized queries or safe encoding, validate input types, and add a targeted regression test.\n"
                "Verification: rerun Semgrep, run the relevant application tests, and confirm the security gate passes before shipping."
            ),
        }

    if "semgrep" in text or "trivy" in text:
        return {
            "remediation_type": "AI_ASSISTED",
            "before_status": "BLOCKED",
            "after_status": "PENDING",
            "validation_summary": "Before: scanner block. After: pending review and validation after the proposed remediation.",
            "remediation_reason": "This may be fixable with a validated patch, but it still requires a developer to review the generated change.",
            "remediation_guide": (
                "Why this happened: the project is tripping a scanner rule for a dependency or code pattern that requires a careful patch.\n"
                "What went wrong: the issue is security-relevant and should be reviewed instead of auto-merged.\n"
                "How to fix it: use the AI proposal only as a starting point, validate the exact patch, and review the code path before creating the PR.\n"
                "Verification: re-run the scanner and the gate after the patch, then confirm the finding is eliminated before merge."
            ),
        }

    return {
        "remediation_type": "MANUAL",
        "before_status": "BLOCKED",
        "after_status": "PENDING",
        "validation_summary": "Before: blocked by the reported issue. After: pending until the developer fix is validated by the pipeline.",
        "remediation_reason": "This finding requires a careful human review because it is not a simple deterministic configuration fix.",
        "remediation_guide": (
            "Why this happened: the security scanner reported a real issue that needs careful code review.\n"
            "What went wrong: the application or infrastructure does not meet the expected secure baseline.\n"
            "How to fix it: inspect the exact affected file, understand the root cause, and create a small, reviewable patch.\n"
            "Verification: re-run the relevant scans and ensure the security gate passes before approving the change."
        ),
    }


def collect_findings():
    findings = []

    trivy = load_json("trivy-results.json", default={})
    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            profile = remediation_profile("trivy", vuln.get("Severity", "LOW"), vuln.get("Title", ""), vuln.get("VulnerabilityID", ""), vuln.get("PkgName", ""))
            findings.append({
                "source": "trivy", "severity": vuln.get("Severity", "LOW"),
                "file_path": vuln.get("PkgName", ""),
                "rule_id": vuln.get("VulnerabilityID", ""),
                "message": vuln.get("Title", ""),
                "fixed_version": vuln.get("FixedVersion", "-"),
                **profile,
            })

    semgrep = load_json("semgrep-results.json", default={})
    for res in semgrep.get("results", []):
        sev_raw = str(res.get("extra", {}).get("severity", "INFO")).upper()
        sev = "HIGH" if sev_raw == "ERROR" else ("MEDIUM" if sev_raw == "WARNING" else "LOW")
        profile = remediation_profile("semgrep", sev, res.get("extra", {}).get("message", ""), res.get("check_id", ""), f'{res.get("path", "")}:{res.get("start", {}).get("line", "")}')
        findings.append({
            "source": "semgrep", "severity": sev,
            "file_path": f'{res.get("path", "")}:{res.get("start", {}).get("line", "")}',
            "rule_id": res.get("check_id", ""),
            "message": res.get("extra", {}).get("message", ""),
            "fixed_version": "-",
            **profile,
        })

    gitleaks = load_json("gitleaks-results.json", default=[])
    for leak in (gitleaks if isinstance(gitleaks, list) else []):
        profile = remediation_profile("gitleaks", "CRITICAL", leak.get("Description", "Possible hardcoded credential"), leak.get("RuleID", "secret"), leak.get("File", ""))
        findings.append({
            "source": "gitleaks", "severity": "CRITICAL",
            "file_path": leak.get("File", ""),
            "rule_id": leak.get("RuleID", "secret"),
            "message": leak.get("Description", "Possible hardcoded credential"),
            "fixed_version": "-",
            **profile,
        })

    for path, label in [("dockerfile-policy-results.json", "Dockerfile"),
                        ("k8s-policy-results.json", "Kubernetes")]:
        policy = load_json(path, default=[])
        entries = policy if isinstance(policy, list) else [policy]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                detail = str(failure.get("msg", failure))
                profile = remediation_profile("opa-policy", "HIGH", detail, label, entry.get("filename", label))
                findings.append({
                    "source": "opa-policy", "severity": "HIGH",
                    "file_path": entry.get("filename", label),
                    "rule_id": label,
                    "message": detail,
                    "fixed_version": "-",
                    **profile,
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
