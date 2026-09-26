#!/usr/bin/env python3
"""Deterministic controller for one LOW/MEDIUM Groq-assisted remediation."""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from groq_client import request_remediation
from remediation_policy import classify_finding, load_scanner_findings, normalized_repo_path

IMAGE_NAME = "secure-devops-demo"
APPROVED_ROOTS = ("app/", "k8s/")
MAX_FILE_BYTES = 100_000


def log(message):
    print(f"[AGENT] {message}", flush=True)


def run(command, *, cwd, timeout=900, input_text=None, check=True):
    result = subprocess.run(
        command, cwd=str(cwd), input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        shell=False, check=False,
    )
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Approved command failed (exit {result.returncode}): {Path(command[0]).name}")
    return result


def safe_target(value, root):
    target = normalized_repo_path(value).split(":", 1)[0]
    if not (target == "Dockerfile" or target.startswith(APPROVED_ROOTS)):
        raise RuntimeError("AI remediation is restricted to Dockerfile, app/, or k8s/ files")
    full = (root / target).resolve()
    if root.resolve() not in full.parents and full != root.resolve():
        raise RuntimeError("Affected file path escapes the repository")
    if not full.is_file():
        raise RuntimeError(f"Affected file does not exist: {target}")
    if full.stat().st_size > MAX_FILE_BYTES:
        raise RuntimeError("Affected file is too large for a bounded remediation request")
    return target, full


def docker_volume_path(path):
    return Path(path).resolve().as_posix()


def save_report(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def docker_json_scan(root, report_dir, scanner, command, timeout=900):
    result = run(command, cwd=root, timeout=timeout, check=False)
    output_path = report_dir / f"{scanner}-results.json"
    if result.returncode >= 2:
        raise RuntimeError(f"{scanner} scanner execution failed (exit {result.returncode})")
    try:
        if output_path.is_file():
            return json.loads(output_path.read_text(encoding="utf-8-sig"))
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{scanner} returned invalid JSON") from error


def scan_workspace(root, phase, ticket_id, *, build_image):
    phase_dir = root / ".ai-remediation" / phase
    phase_dir.mkdir(parents=True, exist_ok=True)
    mount = docker_volume_path(root)
    image_ref = f"{IMAGE_NAME}:ai-{ticket_id}-{phase}"

    if build_image:
        log(f"Building isolated validation image for {phase}")
        run(["docker", "build", "--tag", image_ref, "."], cwd=root)

    with tempfile.TemporaryDirectory(prefix="ai-remediation-scan-") as temporary:
        reports = Path(temporary)
        report_mount = docker_volume_path(reports)

        log(f"Running full Semgrep scan ({phase})")
        semgrep = docker_json_scan(root, reports, "semgrep", [
            "docker", "run", "--rm", "-v", f"{mount}:/src", "-v", f"{report_mount}:/reports",
            "returntocorp/semgrep", "semgrep", "scan", "--config", "p/owasp-top-ten",
            "--config", "p/javascript", "--json", "--output", "/reports/semgrep-results.json", "/src/app",
        ])

        log(f"Running full Gitleaks scan ({phase})")
        gitleaks = docker_json_scan(root, reports, "gitleaks", [
            "docker", "run", "--rm", "-v", f"{mount}:/repo", "-v", f"{report_mount}:/reports",
            "zricethezav/gitleaks:latest", "detect", "--source", "/repo", "--no-git",
            "--report-format", "json", "--report-path", "/reports/gitleaks-results.json",
        ])

        image_tar = reports / "image.tar"
        log(f"Running Trivy image scan ({phase})")
        run(["docker", "save", image_ref, "-o", str(image_tar)], cwd=root)
        trivy_run = run([
            "docker", "run", "--rm", "-v", f"{report_mount}:/out", "aquasec/trivy:latest",
            "image", "--input", "/out/image.tar", "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--timeout", "10m",
            "--output", "/out/trivy-results.json",
        ], cwd=root, timeout=900, check=False)
        if trivy_run.returncode >= 2:
            raise RuntimeError(f"Trivy scanner execution failed (exit {trivy_run.returncode})")
        try:
            trivy = json.loads((reports / "trivy-results.json").read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("Trivy returned missing or invalid JSON") from error

        log(f"Running Dockerfile and Kubernetes policy scans ({phase})")
        policy_results = {}
        for scanner, target in (("dockerfile-policy", "Dockerfile"), ("k8s-policy", "k8s/deployment.yaml")):
            policy = run([
                "docker", "run", "--rm", "-v", f"{mount}:/project", "openpolicyagent/conftest",
                "test", f"/project/{target}", "--policy", "/project/policy", "--output", "json",
            ], cwd=root, timeout=300, check=False)
            if policy.returncode >= 2:
                raise RuntimeError(f"{scanner} scanner execution failed (exit {policy.returncode})")
            try:
                policy_results[scanner] = json.loads(policy.stdout or "[]")
            except json.JSONDecodeError as error:
                raise RuntimeError(f"{scanner} returned invalid JSON") from error

        normalized_reports = {
            "trivy-results.json": trivy,
            "semgrep-results.json": semgrep,
            "gitleaks-results.json": gitleaks,
            "dockerfile-policy-results.json": policy_results["dockerfile-policy"],
            "k8s-policy-results.json": policy_results["k8s-policy"],
        }
        for filename, data in normalized_reports.items():
            save_report(reports / filename, json.dumps(data))
        findings = load_scanner_findings(reports, repo_root=root)
        if phase == "after":
            for filename, data in normalized_reports.items():
                save_report(phase_dir / filename, json.dumps(data))

    return findings, image_ref


def finding_matches(item, source, vulnerability_id, package_name=""):
    if source and item["source"].lower() != source.lower():
        return False
    if vulnerability_id and item["vulnerability_id"].lower() != vulnerability_id.lower():
        return False
    if package_name and item["package_name"].lower() != package_name.lower():
        return False
    return bool(vulnerability_id)


def fingerprint(item):
    return (
        item["source"].lower(), item["vulnerability_id"].lower(),
        item.get("package_name", "").lower(), item.get("affected_file", "").lower(),
        item.get("description", "").lower(),
    )


def scan_summary(findings, target_finding=None):
    counts = {}
    for finding in findings:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return json.dumps({
        "status": "COMPLETED",
        "finding_count": len(findings),
        "severity_counts": counts,
        "target_present": target_finding is not None,
        "scanners": ["Semgrep", "Gitleaks", "Trivy", "OPA/Conftest"],
    }, sort_keys=True)


def compare_scan_results(before, after, target):
    target_matches = [item for item in after if finding_matches(
        item, target["source"], target["vulnerability_id"], target.get("package_name", "")
    )]
    before_fingerprints = {fingerprint(item) for item in before}
    new_findings = [item for item in after if fingerprint(item) not in before_fingerprints]
    return target_matches, new_findings


def sanitize_context(value):
    patterns = (
        r"\bAKIA[0-9A-Z]{16}\b", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+",
    )
    for pattern in patterns:
        value = re.sub(pattern, "[REDACTED]", value)
    return value


def make_prompt(finding, path, source_text, root):
    context_path = root / "README.md"
    project_context = context_path.read_text(encoding="utf-8", errors="replace")[:4000] if context_path.is_file() else ""
    recommendation = finding.get("scanner_recommendation") or "No explicit scanner recommendation was supplied."
    return json.dumps({
        "task": "Propose one minimal security remediation using a unified diff for exactly the affected file.",
        "constraints": [
            "The diff must modify only the supplied affected file and must apply with git apply.",
            "Do not output shell commands, scripts to execute, credentials, URLs, or new dependencies.",
            "Do not change unrelated behavior. The Python controller, not you, runs all tests and scanners.",
            "Return the required structured JSON fields; use a unified diff in patch.",
        ],
        "vulnerability": {
            "vulnerability_id": finding["vulnerability_id"], "severity": finding["severity"],
            "source": finding["source"], "package": finding.get("package_name"),
            "affected_file": finding["affected_file"], "affected_line": finding.get("affected_line"),
            "installed_version": finding.get("installed_version"), "fixed_version": finding.get("fixed_version"),
            "description": finding.get("description"), "scanner_recommendation": recommendation,
        },
        "project_context": project_context,
        "affected_file_content": sanitize_context(source_text),
        "required_json": {
            "vulnerability_id": "same as input", "severity": "same as input",
            "affected_file": "same as input", "analysis": "cause and impact",
            "remediation": "concise proposed fix", "patch": "unified diff, one file only",
            "confidence": "HIGH, MEDIUM, or LOW", "tests_required": True,
            "reason": "why this is the minimal safe change",
        },
    }, ensure_ascii=False)


def validate_proposal(proposal, finding, target):
    required = ("vulnerability_id", "severity", "affected_file", "analysis", "remediation", "patch", "confidence", "tests_required", "reason")
    if any(key not in proposal for key in required):
        raise RuntimeError("Groq proposal is missing required structured fields")
    if str(proposal["vulnerability_id"]).lower() != finding["vulnerability_id"].lower():
        raise RuntimeError("Groq proposal changed the vulnerability ID")
    if str(proposal["severity"]).upper() != finding["severity"].upper():
        raise RuntimeError("Groq proposal changed the finding severity")
    if normalized_repo_path(proposal["affected_file"]) != target:
        raise RuntimeError("Groq proposal targets a different file")
    for key in ("analysis", "remediation", "patch", "reason"):
        if not isinstance(proposal[key], str) or not proposal[key].strip():
            raise RuntimeError(f"Groq proposal field {key} must be non-empty text")
    if str(proposal["confidence"]).upper() not in {"HIGH", "MEDIUM", "LOW"}:
        raise RuntimeError("Groq proposal has an invalid confidence value")
    if str(proposal["confidence"]).upper() == "LOW":
        raise RuntimeError("Groq confidence is low; manual review is required")
    if proposal["tests_required"] is not True:
        raise RuntimeError("Groq proposal must require tests")
    return proposal["patch"]


def validate_patch(patch, target):
    if len(patch.splitlines()) > 500:
        raise RuntimeError("Proposed patch exceeds the 500-line safety limit")
    changed_paths = []
    for line in patch.splitlines():
        if line.startswith(("--- ", "+++ ")):
            value = line[4:].split("\t", 1)[0]
            if value == "/dev/null" or not value.startswith(("a/", "b/")):
                raise RuntimeError("Patch contains an unsupported file path")
            changed_paths.append(value[2:])
    if not changed_paths or any(path != target for path in changed_paths) or len(set(changed_paths)) != 1:
        raise RuntimeError("Patch must modify exactly the reported file")
    if any(part == ".." for part in target.replace("\\", "/").split("/")):
        raise RuntimeError("Patch path traversal is not allowed")


def run_project_tests(root, image_ref):
    log("Running project tests in the validated Node image")
    mount = docker_volume_path(root)
    test = run([
        "docker", "run", "--rm", "-v", f"{mount}:/workspace",
        "-e", "NODE_PATH=/app/node_modules", "--entrypoint", "node", image_ref,
        "--test", "/workspace/app/index.test.js",
    ], cwd=root, timeout=300, check=False)
    if test.returncode != 0:
        raise RuntimeError("Project tests failed")
    return "PASS"


def git_branch(root, ticket_id):
    run(["git", "rev-parse", "--is-inside-work-tree"], cwd=root)
    branch = f"ai-remediation/ticket-{ticket_id}-{int(time.time())}"
    run(["git", "checkout", "-b", branch], cwd=root)
    return branch


def commit_one_file(root, target, ticket_id, vulnerability_id):
    run(["git", "add", "--", target], cwd=root)
    staged = run(["git", "diff", "--cached", "--name-only"], cwd=root)
    files = [line.strip().replace("\\", "/") for line in staged.stdout.splitlines() if line.strip()]
    if files != [target]:
        run(["git", "reset", "--", target], cwd=root, check=False)
        raise RuntimeError("Refusing to commit because staged changes include unexpected files")
    run([
        "git", "-c", "user.name=security-bot", "-c",
        "user.email=security-bot@users.noreply.github.com", "commit", "-m",
        f"fix: remediate {vulnerability_id} for ticket {ticket_id}",
    ], cwd=root)


def write_result(root, result):
    path = root / ".ai-fix-result.json"
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path


def remediate(args):
    root = Path.cwd().resolve()
    result = {
        "status": "FAIL", "remediation_status": "MANUAL_REVIEW",
        "vulnerability_id": args.vulnerability_id or args.rule,
        "severity": args.severity.upper(), "affected_file": args.file,
        "analysis": "", "proposed_remediation": "", "files_changed": [],
        "test_status": "NOT_RUN", "rescan_status": "NOT_RUN",
        "before_findings": [], "after_findings": [], "reason": "",
        "before_scan_result": "", "after_scan_result": "",
        "ticket_id": args.ticket_id, "provider": "Groq",
    }
    original_bytes = None
    modified = False
    try:
        classification = classify_finding(args.severity, args.source, args.rule, args.message)
        log(f"Vulnerability detected: {result['vulnerability_id']}")
        log(f"Severity: {args.severity.upper()}")
        if not re.fullmatch(r"[0-9]+", str(args.ticket_id)):
            raise RuntimeError("Ticket ID must be numeric")
        if not classification["ai_eligible"]:
            log("Automatic remediation disabled; manual security review required")
            raise RuntimeError(classification["reason"])

        log("Eligible for AI remediation")
        shutil.rmtree(root / ".ai-remediation", ignore_errors=True)
        (root / ".ai-fix-result.json").unlink(missing_ok=True)
        log("Running baseline security scans")
        baseline, _ = scan_workspace(root, "baseline", args.ticket_id, build_image=True)
        candidates = [item for item in baseline if finding_matches(
            item, args.source, args.vulnerability_id or args.rule, args.package_name
        )]
        if not candidates:
            raise RuntimeError("Requested finding was not present in the fresh baseline scan")
        finding = candidates[0]
        if finding["severity"] not in {"LOW", "MEDIUM"} or finding["severity"] != args.severity.upper():
            raise RuntimeError("Fresh scanner severity does not match the LOW/MEDIUM request; manual review is required")
        if not finding["ai_eligible"]:
            raise RuntimeError("Fresh scan classified this finding as manual-only")
        result.update({
            "vulnerability_id": finding["vulnerability_id"], "severity": finding["severity"],
            "affected_file": finding["affected_file"],
            "before_findings": [finding],
        })
        result["before_scan_result"] = scan_summary(baseline, finding)

        target, full_path = safe_target(finding["affected_file"], root)
        leaks = [item for item in baseline if item["source"] == "gitleaks" and item["affected_file"] == target]
        if leaks:
            raise RuntimeError("Gitleaks reported a secret in the target file; source content will not be sent to Groq")
        target_status = run(["git", "status", "--porcelain", "--", target], cwd=root, check=False)
        if target_status.stdout.strip():
            raise RuntimeError("Target file has pre-existing changes; refusing to overwrite developer work")
        original_bytes = full_path.read_bytes()
        source_text = original_bytes.decode("utf-8")
        branch = git_branch(root, args.ticket_id)
        result["branch"] = branch

        log("Inspecting affected file and scanner context")
        prompt = make_prompt(finding, target, source_text, root)
        log("Requesting structured remediation proposal from Groq")
        proposal, model = request_remediation(prompt)
        patch = validate_proposal(proposal, finding, target)
        validate_patch(patch, target)
        result.update({
            "analysis": proposal["analysis"], "proposed_remediation": proposal["remediation"],
            "reason": proposal["reason"], "model": model,
        })
        log("Validating one-file patch")
        checked = run(["git", "apply", "--check", "--"], cwd=root, input_text=patch, check=False)
        if checked.returncode != 0:
            raise RuntimeError("Proposed patch does not apply cleanly")
        applied = run(["git", "apply", "--"], cwd=root, input_text=patch, check=False)
        if applied.returncode != 0:
            raise RuntimeError("Git could not apply the validated patch")
        modified = True
        result["files_changed"] = [target]

        log("Building patched image and running tests")
        image_ref = f"{IMAGE_NAME}:ai-{args.ticket_id}-after"
        run(["docker", "build", "--tag", image_ref, "."], cwd=root)
        try:
            result["test_status"] = run_project_tests(root, image_ref)
        except Exception:
            result["test_status"] = "FAIL"
            raise
        log("Tests passed")

        log("Running full post-remediation security scans")
        try:
            after, _ = scan_workspace(root, "after", args.ticket_id, build_image=False)
        except Exception:
            result["rescan_status"] = "FAIL"
            raise
        result["after_findings"], new_findings = compare_scan_results(baseline, after, finding)
        result["after_scan_result"] = scan_summary(after, result["after_findings"][0] if result["after_findings"] else None)
        if result["after_findings"]:
            result["rescan_status"] = "FAIL"
            raise RuntimeError("Target vulnerability is still present after the patch")
        if new_findings:
            result["rescan_status"] = "FAIL"
            raise RuntimeError(f"Post-remediation scan found {len(new_findings)} new finding(s)")
        result["rescan_status"] = "PASS"
        result["status"] = "PASS"
        result["remediation_status"] = "VALIDATED_PR_READY"
        result["reason"] = proposal["reason"]
        result["validation_summary"] = "Target finding no longer appears; tests passed; all scanner checks completed with no new findings. Main release gate still controls deployment."
        log("Target finding resolved; no new findings; creating isolated commit")
        commit_one_file(root, target, args.ticket_id, finding["vulnerability_id"])
        result["commit"] = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
        log("Remediation committed on isolated branch; awaiting human PR review")
    except Exception as error:
        result["status"] = "FAIL"
        result["remediation_status"] = "MANUAL_REVIEW"
        result["reason"] = str(error)
        result["validation_summary"] = f"Remediation not validated: {error}"
        result["test_status"] = result.get("test_status", "NOT_RUN")
        if modified and original_bytes is not None:
            target = result.get("affected_file", "")
            try:
                _, full_path = safe_target(target, root)
                full_path.write_bytes(original_bytes)
                run(["git", "reset", "--", target], cwd=root, check=False)
                result["files_changed"] = []
                log("Validation failed; restored the original target file")
            except Exception as restore_error:
                result["reason"] += f"; rollback failed: {restore_error}"
        log(f"Manual review required: {result['reason']}")
    finally:
        write_result(root, result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Safely remediate one LOW/MEDIUM finding using Groq proposals.")
    parser.add_argument("--file", required=True)
    parser.add_argument("--rule", required=True)
    parser.add_argument("--message", default="")
    parser.add_argument("--ticket-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--severity", required=True)
    parser.add_argument("--vulnerability-id", default="")
    parser.add_argument("--package-name", default="")
    parser.add_argument("--installed-version", default="")
    parser.add_argument("--fixed-version", default="")
    args = parser.parse_args()
    result = remediate(args)
    print(f"[AGENT] Final status: {result['status']} ({result['remediation_status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
