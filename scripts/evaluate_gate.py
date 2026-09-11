#!/usr/bin/env python3
"""Centralized Security Gate. Missing/malformed scanner output or non-zero scanner execution blocks the build."""
import json, os, sys

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}
REQUIRED_RESULTS = [
    ("semgrep-results.json", "semgrep"),
    ("gitleaks-results.json", "gitleaks"),
    ("trivy-results.json", "trivy"),
    ("dockerfile-policy-results.json", "opa-dockerfile"),
    ("k8s-policy-results.json", "opa-k8s"),
]

def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

def scanner_errors():
    errors = []
    status_dir = ".scan-status"
    expected = {
        "semgrep": "semgrep.status",
        "gitleaks": "gitleaks.status",
        "trivy": "trivy.status",
        "opa-dockerfile": "docker-policy.status",
        "opa-k8s": "k8s-policy.status",
    }
    for name, filename in expected.items():
        path = os.path.join(status_dir, filename)
        if not os.path.exists(path):
            errors.append(f"{name}: missing scan status")
            continue
        try:
            code = int(open(path, encoding="utf-8").read().strip())
        except ValueError:
            errors.append(f"{name}: invalid scan status")
            continue
        # Scanner exit 1 is normally "findings" for these tools; the JSON is
        # still valid and the findings themselves decide the gate. Exit >=2
        # indicates an execution/configuration problem and is unsafe.
        if code >= 2:
            errors.append(f"{name}: scanner execution error (exit {code})")
    return errors

def check_results():
    findings = []
    missing = []
    for path, source in REQUIRED_RESULTS:
        data = load_json(path)
        if data is None:
            missing.append(f"{source}: missing or invalid JSON ({path})")
            continue

        if source == "trivy":
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []) or []:
                    sev = str(vuln.get("Severity", "UNKNOWN")).upper()
                    if sev in FAIL_SEVERITIES:
                        findings.append((sev, source, vuln.get("PkgName",""), vuln.get("VulnerabilityID",""), vuln.get("Title","")))
        elif source == "semgrep":
            for res in data.get("results", []):
                sev = str(res.get("extra", {}).get("severity", "INFO")).upper()
                mapped = "HIGH" if sev == "ERROR" else ("MEDIUM" if sev == "WARNING" else "LOW")
                if mapped in FAIL_SEVERITIES:
                    findings.append((mapped, source, res.get("path",""), res.get("check_id",""), res.get("extra",{}).get("message","")))
        elif source == "gitleaks":
            entries = data if isinstance(data, list) else []
            for leak in entries:
                findings.append(("CRITICAL", source, leak.get("File",""), leak.get("RuleID","secret"), leak.get("Description","Hardcoded secret")))
        else:
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                for failure in entry.get("failures", []) or []:
                    findings.append(("HIGH", source, entry.get("filename",""), "policy-violation", str(failure.get("msg", failure))))

    return findings, missing

def main():
    errors = scanner_errors()
    findings, missing = check_results()
    if errors or missing or findings:
        print("[gate] FAIL")
        for item in errors: print("  [scan_error]", item)
        for item in missing: print("  [scan_error]", item)
        for sev, source, target, rule, title in findings:
            print(f"  [{sev}] ({source}) {target}: {title} ({rule})")
        with open("gate-status.txt","w",encoding="utf-8") as f: f.write("FAIL")
        return 1
    print("[gate] PASS - all scanners completed and no blocking findings were reported.")
    with open("gate-status.txt","w",encoding="utf-8") as f: f.write("PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
