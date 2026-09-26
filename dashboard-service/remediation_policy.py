"""Shared severity policy and scanner report normalization."""

import json
import re
from pathlib import Path

AI_SEVERITIES = {"LOW", "MEDIUM"}
SECRET_SOURCES = {"gitleaks"}


def semgrep_severity(value):
    value = str(value or "INFO").upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(value, value)


def classify_finding(severity, source, rule_id="", message=""):
    """Return AI eligibility from deterministic policy, never model output."""
    severity = str(severity or "UNKNOWN").upper()
    source = str(source or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", f"{rule_id} {message}".lower())
    secret_like = source in SECRET_SOURCES or any(
        marker in text for marker in ("secret", "credential", "password", "api key", "token", "private key")
    )
    eligible = severity in AI_SEVERITIES and not secret_like
    return {
        "classification": "AI_ELIGIBLE" if eligible else "MANUAL",
        "ai_eligible": eligible,
        "reason": (
            "LOW and MEDIUM findings are eligible for controlled AI assistance."
            if eligible else
            "Only LOW and MEDIUM non-secret findings may use AI; HIGH/CRITICAL and secret findings require manual review."
        ),
    }


def normalized_repo_path(value):
    value = str(value or "").replace("\\", "/")
    for prefix in ("/src/", "/repo/", "/project/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    return value.lstrip("./")


def _trivy_file(target, package, package_type, repo_root):
    target = normalized_repo_path(target)
    candidate = Path(repo_root, target)
    if target and candidate.is_file() and (target == "Dockerfile" or target.startswith(("app/", "k8s/"))):
        return target
    target_lower = target.lower()
    package_type = str(package_type or "").lower()
    if package_type in {"npm", "node-pkg"} or target_lower.endswith(("package.json", "package-lock.json")):
        if Path(repo_root, "app", "package.json").is_file():
            return "app/package.json"
    return "Dockerfile"


def load_scanner_findings(report_dir=".", repo_root=None):
    """Normalize Trivy, Semgrep, Gitleaks and Conftest JSON reports."""
    root = Path(report_dir)
    project_root = Path(repo_root or report_dir)

    def load(name, default):
        try:
            with (root / name).open(encoding="utf-8-sig") as stream:
                return json.load(stream)
        except (OSError, json.JSONDecodeError):
            return default

    findings = []
    trivy = load("trivy-results.json", {})
    for result in trivy.get("Results", []) if isinstance(trivy, dict) else []:
        for vuln in result.get("Vulnerabilities", []) or []:
            target = result.get("Target", "")
            package = vuln.get("PkgName", "")
            findings.append({
                "source": "trivy", "vulnerability_id": vuln.get("VulnerabilityID", ""),
                "severity": str(vuln.get("Severity", "UNKNOWN")).upper(), "package_name": package,
                "affected_file": _trivy_file(target, package, result.get("Type", ""), project_root), "affected_line": None,
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "description": vuln.get("Title") or vuln.get("Description", ""),
                "scanner_recommendation": vuln.get("PrimaryURL", "") or vuln.get("Description", ""),
                "target": target, "rule_id": vuln.get("VulnerabilityID", ""),
            })

    semgrep = load("semgrep-results.json", {})
    for result in semgrep.get("results", []) if isinstance(semgrep, dict) else []:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        findings.append({
            "source": "semgrep", "vulnerability_id": result.get("check_id", ""),
            "severity": semgrep_severity(extra.get("severity")), "package_name": "",
            "affected_file": normalized_repo_path(result.get("path", "")),
            "affected_line": (result.get("start") or {}).get("line"),
            "installed_version": "", "fixed_version": "", "description": extra.get("message", ""),
            "scanner_recommendation": metadata.get("fix") or metadata.get("references", ""),
            "target": result.get("path", ""), "rule_id": result.get("check_id", ""),
        })

    gitleaks = load("gitleaks-results.json", [])
    for leak in gitleaks if isinstance(gitleaks, list) else []:
        findings.append({
            "source": "gitleaks", "vulnerability_id": leak.get("RuleID", "secret"),
            "severity": "CRITICAL", "package_name": "",
            "affected_file": normalized_repo_path(leak.get("File", "")),
            "affected_line": leak.get("StartLine"), "installed_version": "", "fixed_version": "",
            "description": leak.get("Description", "Possible exposed secret"),
            "scanner_recommendation": "Rotate the credential and remove it from source control.",
            "target": leak.get("File", ""), "rule_id": leak.get("RuleID", "secret"),
        })

    for report, label in (("dockerfile-policy-results.json", "Dockerfile"), ("k8s-policy-results.json", "Kubernetes")):
        data = load(report, [])
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            for failure in entry.get("failures", []) or []:
                message = str(failure.get("msg", failure))
                findings.append({
                    "source": "opa-policy", "vulnerability_id": "policy-violation", "severity": "HIGH",
                    "package_name": "", "affected_file": normalized_repo_path(entry.get("filename", label)),
                    "affected_line": None, "installed_version": "", "fixed_version": "",
                    "description": message, "scanner_recommendation": "Comply with the configured OPA policy.",
                    "target": label, "rule_id": label,
                })

    for finding in findings:
        finding.update(classify_finding(finding["severity"], finding["source"], finding["rule_id"], finding["description"]))
    return findings


def classify_report_directory(report_dir=".", output_path="ai-remediation-candidates.json"):
    findings = load_scanner_findings(report_dir)
    output = Path(report_dir, output_path)
    output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    eligible = sum(item["ai_eligible"] for item in findings)
    print(f"[AGENT] Classified {len(findings)} finding(s): {eligible} LOW/MEDIUM AI-eligible; {len(findings) - eligible} manual review.")
    for item in findings:
        disposition = "AI eligible" if item["ai_eligible"] else "Manual review required"
        print(f"[AGENT] {item['vulnerability_id']} severity={item['severity']}: {disposition}")
    return findings
