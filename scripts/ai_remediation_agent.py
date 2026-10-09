#!/usr/bin/env python3
"""Deterministic controller for one LOW/MEDIUM Groq-assisted remediation."""

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from groq_client import request_remediation
from remediation_policy import classify_finding, load_scanner_findings, normalized_repo_path

IMAGE_NAME = "secure-devops-demo"
APPROVED_ROOTS = ("app/", "k8s/")
MAX_FILE_BYTES = 100_000


def log(message):
    print(f"[AGENT] {message}", flush=True)


def run(command, *, cwd, timeout=900, input_text=None, check=True, print_output=True):
    result = subprocess.run(
        command, cwd=str(cwd), input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        encoding="utf-8", errors="replace", shell=False, check=False,
    )
    if print_output and (result.stdout or result.stderr):
        encoding = sys.stdout.encoding or "utf-8"
        for output in (result.stdout, result.stderr):
            if output:
                printable = output.encode(encoding, errors="replace").decode(encoding)
                print(printable.rstrip(), flush=True)
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


def parse_scanner_report(scanner, raw):
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError(f"{scanner} returned an empty report")
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{scanner} returned invalid JSON") from error
    if scanner == "semgrep" and (not isinstance(report, dict) or not isinstance(report.get("results"), list)):
        raise RuntimeError("Semgrep returned a JSON report with an invalid shape")
    if scanner == "gitleaks" and not isinstance(report, list):
        raise RuntimeError("Gitleaks returned a JSON report with an invalid shape")
    if scanner == "trivy" and (not isinstance(report, dict) or not isinstance(report.get("Results"), list)):
        raise RuntimeError("Trivy returned a JSON report with an invalid shape")
    if scanner in {"dockerfile-policy", "k8s-policy"} and (not isinstance(report, list) or not report):
        raise RuntimeError(f"{scanner} returned a JSON report with an invalid shape")
    return report


def docker_json_scan(root, report_dir, scanner, command, timeout=900):
    result = run(command, cwd=root, timeout=timeout, check=False, print_output=False)
    output_path = report_dir / f"{scanner}-results.json"
    if result.returncode >= 2:
        raise RuntimeError(f"{scanner} scanner execution failed (exit {result.returncode})")
    try:
        raw = output_path.read_text(encoding="utf-8-sig") if output_path.is_file() else result.stdout or ""
        report = parse_scanner_report(scanner, raw)
    except RuntimeError as error:
        if result.stderr:
            log(f"{scanner} diagnostics: {result.stderr[-2000:]}")
        raise error
    except OSError as error:
        raise RuntimeError(f"{scanner} report could not be read") from error
    if result.returncode == 1:
        has_findings = bool(report.get("results")) if scanner == "semgrep" else bool(report)
        if not has_findings:
            raise RuntimeError(f"{scanner} returned exit code 1 with no findings in its report")
    return report


def scan_workspace(root, phase, ticket_id, *, build_image):
    phase_dir = root / ".ai-remediation" / phase
    phase_dir.mkdir(parents=True, exist_ok=True)
    mount = docker_volume_path(root)
    image_ref = f"{IMAGE_NAME}:ai-{ticket_id}-{phase}"

    if build_image:
        log(f"Building isolated validation image for {phase}")
        run(["docker", "build", "--tag", image_ref, "."], cwd=root)

    # Keep bind-mounted scan reports under the Jenkins workspace. On Windows,
    # Jenkins may run as SYSTEM and Docker Desktop cannot access C:\Windows\Temp.
    with tempfile.TemporaryDirectory(prefix="ai-remediation-scan-", dir=phase_dir) as temporary:
        reports = Path(temporary)
        container_reports = f"/src/{reports.relative_to(root).as_posix()}"

        log(f"Running full Semgrep scan ({phase})")
        semgrep = docker_json_scan(root, reports, "semgrep", [
            "docker", "run", "--rm", "-v", f"{mount}:/src",
            "returntocorp/semgrep", "semgrep", "scan", "--config", "p/owasp-top-ten",
            "--config", "p/javascript", "--quiet", "--json", "/src/app",
        ])

        log(f"Running full Gitleaks scan ({phase})")
        gitleaks = docker_json_scan(root, reports, "gitleaks", [
            "docker", "run", "--rm", "-v", f"{mount}:/src",
            "zricethezav/gitleaks:latest", "detect", "--source", "/src", "--no-git",
            "--report-format", "json", "--report-path", "-",
        ])

        image_tar = root / f".ai-remediation-{phase}-{ticket_id}-image.tar"
        log(f"Running Trivy image scan ({phase})")
        try:
            run(["docker", "save", image_ref, "-o", str(image_tar)], cwd=root)
            trivy_args = [
                "docker", "run", "--rm", "--user", "0:0", "-v", f"{mount}:/src",
                "-v", "ai-remediation-trivy-cache:/root/.cache/trivy", "aquasec/trivy:latest",
                "image", "--input", f"/src/{image_tar.name}", "--format", "json", "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--timeout", "30m",
            ]
            if phase == "after":
                trivy_args.append("--skip-db-update")
            trivy_run = run(trivy_args, cwd=root, timeout=2100, check=False, print_output=False)
        finally:
            image_tar.unlink(missing_ok=True)
        if trivy_run.returncode != 0:
            detail = (trivy_run.stderr or "").strip()[-1000:]
            raise RuntimeError(f"Trivy scanner execution failed (exit {trivy_run.returncode})" + (f": {detail}" if detail else ""))
        try:
            trivy = parse_scanner_report("trivy", trivy_run.stdout)
        except RuntimeError as error:
            if trivy_run.stderr:
                log(f"Trivy diagnostics: {trivy_run.stderr[-2000:]}")
            raise error
        if not isinstance(trivy, dict) or not isinstance(trivy.get("Results"), list):
            raise RuntimeError("Trivy returned a JSON report with an invalid shape")

        log(f"Running Dockerfile and Kubernetes policy scans ({phase})")
        policy_results = {}
        for scanner, target in (("dockerfile-policy", "Dockerfile"), ("k8s-policy", "k8s/deployment.yaml")):
            policy = run([
                "docker", "run", "--rm", "-v", f"{mount}:/project", "openpolicyagent/conftest",
                "test", f"/project/{target}", "--policy", "/project/policy", "--output", "json",
            ], cwd=root, timeout=300, check=False)
            if policy.returncode >= 2:
                raise RuntimeError(f"{scanner} scanner execution failed (exit {policy.returncode})")
            policy_results[scanner] = parse_scanner_report(scanner, policy.stdout)

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
    source_text = source_text.replace("\r\n", "\n").replace("\r", "\n")
    recommendation = finding.get("scanner_recommendation") or "No explicit scanner recommendation was supplied."
    return json.dumps({
        "task": "Propose one minimal security remediation as an exact-text edit to exactly the affected file.",
        "constraints": [
            f"The file field must be exactly {path}.",
            "The find field must be a non-empty exact contiguous excerpt from affected_file_content and must occur exactly once.",
            "The replace field must contain only replacement source text, not a patch or instructions; make a real minimal change.",
            "Do not include Markdown, diff headers, patch markers, or code fences in find or replace.",
            "Do not output shell commands, scripts to execute, credentials, URLs, or new dependencies.",
            "Do not change unrelated behavior. The Python controller, not you, runs all tests and scanners.",
            "Return one JSON object matching the response schema.",
        ],
        "vulnerability": {
            "vulnerability_id": finding["vulnerability_id"], "severity": finding["severity"],
            "source": finding["source"], "package": finding.get("package_name"),
            "affected_file": finding["affected_file"], "affected_line": finding.get("affected_line"),
            "installed_version": finding.get("installed_version"), "fixed_version": finding.get("fixed_version"),
            "description": finding.get("description"), "scanner_recommendation": recommendation,
        },
        "affected_file_content": sanitize_context(source_text),
        "required_json": {
            "vulnerability_id": "same as input", "severity": "same as input",
            "file": path, "analysis": "cause and impact",
            "remediation": "concise proposed fix", "find": "exact existing source excerpt",
            "replace": "replacement source excerpt",
            "confidence": "HIGH, MEDIUM, or LOW", "tests_required": True,
            "reason": "why this is the minimal safe change",
        },
    }, ensure_ascii=False)


def remediation_response_schema(finding, target):
    return {
        "type": "object",
        "properties": {
            "vulnerability_id": {"type": "string", "enum": [finding["vulnerability_id"]]},
            "severity": {"type": "string", "enum": [finding["severity"]]},
            "file": {"type": "string", "enum": [target]},
            "analysis": {"type": "string"},
            "remediation": {"type": "string"},
            "find": {"type": "string"},
            "replace": {"type": "string"},
            "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
            "tests_required": {"type": "boolean"},
            "reason": {"type": "string"},
        },
        "required": [
            "vulnerability_id", "severity", "file", "analysis", "remediation",
            "find", "replace", "confidence", "tests_required", "reason",
        ],
        "additionalProperties": False,
    }


def validate_proposal(proposal, finding, target):
    required = ("vulnerability_id", "severity", "file", "analysis", "remediation", "find", "replace", "confidence", "tests_required", "reason")
    if any(key not in proposal for key in required):
        raise RuntimeError("Groq proposal is missing required structured fields")
    if str(proposal["vulnerability_id"]).lower() != finding["vulnerability_id"].lower():
        raise RuntimeError("Groq proposal changed the vulnerability ID")
    if str(proposal["severity"]).upper() != finding["severity"].upper():
        raise RuntimeError("Groq proposal changed the finding severity")
    if proposal["file"] != target:
        raise RuntimeError("Groq proposal targets a different file")
    for key in ("analysis", "remediation", "find", "replace", "reason"):
        if not isinstance(proposal[key], str) or not proposal[key].strip():
            raise RuntimeError(f"Groq proposal field {key} must be non-empty text")
    if str(proposal["confidence"]).upper() not in {"HIGH", "MEDIUM", "LOW"}:
        raise RuntimeError("Groq proposal has an invalid confidence value")
    if str(proposal["confidence"]).upper() == "LOW":
        raise RuntimeError("Groq confidence is low; manual review is required")
    if proposal["tests_required"] is not True:
        raise RuntimeError("Groq proposal must require tests")
    return proposal


def apply_exact_edit(source_text, proposal, target):
    old_text = proposal["find"].replace("\r\n", "\n").replace("\r", "\n")
    new_text = proposal["replace"].replace("\r\n", "\n").replace("\r", "\n")
    if not old_text.strip() or not new_text.strip():
        raise RuntimeError("Structured edit must contain non-empty find and replace text")
    if old_text == new_text:
        raise RuntimeError("Structured edit does not change the source")
    newline_styles = set(re.findall(r"\r\n|\r|\n", source_text))
    if len(newline_styles) > 1:
        raise RuntimeError("Target file has mixed line endings; manual review is required")
    newline = next(iter(newline_styles), "\n")
    normalized_source = source_text.replace("\r\n", "\n").replace("\r", "\n")
    occurrences = normalized_source.count(old_text)
    if occurrences != 1:
        raise RuntimeError(f"Exact target text must occur once in {target}; found {occurrences}")
    updated = normalized_source.replace(old_text, new_text, 1)
    if newline != "\n":
        updated = updated.replace("\n", newline)
    return updated


def generate_unified_patch(source_text, updated_text, target):
    source_lf = source_text.replace("\r\n", "\n").replace("\r", "\n")
    updated_lf = updated_text.replace("\r\n", "\n").replace("\r", "\n")
    patch = "".join(difflib.unified_diff(
        source_lf.splitlines(keepends=True), updated_lf.splitlines(keepends=True),
        fromfile=f"a/{target}", tofile=f"b/{target}", n=3,
    ))
    if not patch:
        raise RuntimeError("Structured edit produced no source changes")
    validate_patch(patch, target)
    return patch


def validate_patch(patch, target):
    if not isinstance(patch, str) or not patch.strip():
        raise RuntimeError("Proposed patch must be non-empty text")
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
    hunk_header = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@(?: .*)?$")
    if not any(hunk_header.match(line) for line in patch.splitlines()):
        raise RuntimeError("Patch must contain at least one unified-diff hunk")


def request_valid_patch(prompt, finding, target, root, source_text):
    feedback = None
    for attempt in range(2):
        request_prompt = prompt
        if feedback:
            request_data = json.loads(prompt)
            request_data["edit_validation_feedback"] = feedback
            request_data["constraints"].append(
                "Return only the structured exact-text edit fields required by the schema; do not return a diff or patch."
            )
            request_prompt = json.dumps(request_data, ensure_ascii=False)
        proposal, model = request_remediation(
            request_prompt, response_schema=remediation_response_schema(finding, target),
        )
        proposal = validate_proposal(proposal, finding, target)
        updated_text = apply_exact_edit(source_text, proposal, target)
        patch = generate_unified_patch(source_text, updated_text, target)
        checked = run(
            ["git", "apply", "--check", "--"], cwd=root,
            input_text=patch, check=False, print_output=False,
        )
        if checked.returncode == 0:
            return proposal, model, patch, updated_text
        if attempt == 0:
            diagnostic = (checked.stderr or checked.stdout).strip()[:1000]
            feedback = (
                "The exact-text edit generated a patch rejected by git apply --check against the supplied original file. "
                f"Diagnostic: {diagnostic or 'no diagnostic text was returned'}. "
                "Return a corrected exact-text find/replace edit for the same single file."
            )
            log("Controller-generated patch failed git apply --check; requesting one corrected edit")
    raise RuntimeError("Controller-generated patch still does not apply cleanly")


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
    if not str(ticket_id).isdigit():
        raise RuntimeError("Ticket ID must be numeric before creating a remediation branch")
    branch = f"ai-remediation/ticket-{ticket_id}"
    existing = run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=root, check=False,
    )
    if existing.returncode not in {0, 1}:
        raise RuntimeError("Could not inspect the workspace-local remediation branch")
    if existing.returncode == 0:
        log(f"Resetting the workspace-local retry branch {branch} to the checked-out source revision")
        run(["git", "checkout", "-B", branch], cwd=root)
    else:
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
        proposal, model, patch, updated_text = request_valid_patch(prompt, finding, target, root, source_text)
        result.update({
            "analysis": proposal["analysis"], "proposed_remediation": proposal["remediation"],
            "reason": proposal["reason"], "model": model,
        })
        log("Validating one-file patch")
        applied = run(["git", "apply", "--"], cwd=root, input_text=patch, check=False)
        if applied.returncode != 0:
            raise RuntimeError("Git could not apply the validated patch")
        modified = True
        if full_path.read_bytes().decode("utf-8") != updated_text:
            raise RuntimeError("Applied patch did not produce the exact validated edit")
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
