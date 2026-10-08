import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch as mock_patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "dashboard-service"))

from remediation_policy import classify_finding, load_scanner_findings, semgrep_severity
from ai_remediation_agent import (
    apply_exact_edit, commit_one_file, compare_scan_results, docker_json_scan,
    generate_unified_patch, parse_scanner_report, remediation_response_schema, request_valid_patch,
    validate_patch, validate_proposal,
)


def edit_proposal(find="res.send(userInput)", replace="res.type('text').send(userInput)", file="app/index.js"):
    return {
        "vulnerability_id": "RULE-1", "severity": "MEDIUM", "file": file,
        "analysis": "User-controlled input is written to the response.",
        "remediation": "Return the value as plain text.",
        "find": find, "replace": replace, "confidence": "HIGH",
        "tests_required": True, "reason": "Minimal response handling change.",
    }


class RemediationPolicyTests(unittest.TestCase):
    def test_only_low_and_medium_non_secret_findings_are_eligible(self):
        self.assertTrue(classify_finding("LOW", "trivy")["ai_eligible"])
        self.assertTrue(classify_finding("MEDIUM", "semgrep")["ai_eligible"])
        self.assertFalse(classify_finding("HIGH", "opa-policy")["ai_eligible"])
        self.assertFalse(classify_finding("CRITICAL", "trivy")["ai_eligible"])
        self.assertFalse(classify_finding("LOW", "gitleaks")["ai_eligible"])
        self.assertFalse(classify_finding("MEDIUM", "semgrep", message="hardcoded API key")["ai_eligible"])
        self.assertFalse(classify_finding("LOW", "semgrep", message="possible api_key exposure")["ai_eligible"])

    def test_semgrep_warning_maps_to_medium(self):
        self.assertEqual(semgrep_severity("WARNING"), "MEDIUM")
        self.assertEqual(semgrep_severity("ERROR"), "HIGH")

    def test_scanner_reports_normalize_dependency_and_source_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app").mkdir()
            (root / "app" / "package.json").write_text("{}", encoding="utf-8")
            (root / "trivy-results.json").write_text(json.dumps({
                "Results": [{"Target": "app/package-lock.json", "Type": "npm", "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-1234", "Severity": "MEDIUM",
                    "PkgName": "express", "InstalledVersion": "4.1.0", "FixedVersion": "4.2.0",
                    "Title": "Example issue", "Description": "Example details",
                }]}, {"Target": "node:18 (debian 12)", "Type": "debian", "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-5678", "Severity": "LOW",
                    "PkgName": "libc6", "InstalledVersion": "2.0", "FixedVersion": "2.1",
                    "Title": "Base image issue",
                }]}],
            }), encoding="utf-8")
            (root / "semgrep-results.json").write_text(json.dumps({"results": [{
                "check_id": "javascript.test-rule", "path": "/src/app/index.js",
                "start": {"line": 7}, "extra": {"severity": "WARNING", "message": "Test finding"},
            }]}), encoding="utf-8")
            (root / "gitleaks-results.json").write_text("[]", encoding="utf-8")
            (root / "dockerfile-policy-results.json").write_text("[]", encoding="utf-8")
            (root / "k8s-policy-results.json").write_text("[]", encoding="utf-8")
            findings = load_scanner_findings(root, repo_root=root)
        trivy = next(item for item in findings if item["source"] == "trivy")
        os_vulnerability = next(item for item in findings if item.get("vulnerability_id") == "CVE-2026-5678")
        semgrep = next(item for item in findings if item["source"] == "semgrep")
        self.assertEqual(trivy["vulnerability_id"], "CVE-2026-1234")
        self.assertEqual(trivy["affected_file"], "app/package.json")
        self.assertEqual(trivy["installed_version"], "4.1.0")
        self.assertEqual(trivy["fixed_version"], "4.2.0")
        self.assertTrue(trivy["ai_eligible"])
        self.assertEqual(os_vulnerability["affected_file"], "Dockerfile")
        self.assertEqual(semgrep["affected_file"], "app/index.js")
        self.assertEqual(semgrep["affected_line"], 7)
        self.assertTrue(semgrep["ai_eligible"])

    def test_exact_edit_is_unique_and_preserves_line_endings(self):
        source = "before\r\nres.send(userInput)\r\nafter\r\n"
        updated = apply_exact_edit(source, edit_proposal(), "app/index.js")
        self.assertEqual(updated, "before\r\nres.type('text').send(userInput)\r\nafter\r\n")
        patch = generate_unified_patch(source, updated, "app/index.js")
        validate_patch(patch, "app/index.js")
        self.assertIn("--- a/app/index.js", patch)
        self.assertIn("+++ b/app/index.js", patch)

    def test_ambiguous_empty_noop_and_wrong_file_edits_are_rejected(self):
        cases = [
            ("x\nx\n", edit_proposal(find="x", replace="y"), "occur once"),
            ("x\n", edit_proposal(find="missing", replace="y"), "occur once"),
            ("x\n", edit_proposal(find="", replace="y"), "non-empty"),
            ("x\n", edit_proposal(find="x", replace=" "), "non-empty"),
            ("x\n", edit_proposal(find="x", replace="x"), "does not change"),
            ("x\n", edit_proposal(find="x", replace="y", file="app/../README.md"), "different file"),
        ]
        finding = {"vulnerability_id": "RULE-1", "severity": "MEDIUM"}
        for source, proposal, message in cases:
            with self.subTest(message=message):
                if proposal["file"] != "app/index.js":
                    with self.assertRaisesRegex(RuntimeError, message):
                        validate_proposal(proposal, finding, "app/index.js")
                else:
                    with self.assertRaisesRegex(RuntimeError, message):
                        apply_exact_edit(source, proposal, "app/index.js")
        with self.assertRaisesRegex(RuntimeError, "mixed line endings"):
            apply_exact_edit("a\nline\r\n", edit_proposal(find="a", replace="b"), "app/index.js")

    def test_proposal_cannot_change_severity_or_target(self):
        finding = {"vulnerability_id": "RULE-1", "severity": "MEDIUM"}
        for proposal in (
            {**edit_proposal(), "severity": "HIGH"},
            {**edit_proposal(), "file": "app/other.js"},
            {**edit_proposal(), "tests_required": False},
            {**edit_proposal(), "confidence": "LOW"},
        ):
            with self.subTest(proposal=proposal), self.assertRaises(RuntimeError):
                validate_proposal(proposal, finding, "app/index.js")

    def test_response_schema_is_strict_and_locks_file_and_finding_identity(self):
        finding = {"vulnerability_id": "RULE-1", "severity": "MEDIUM"}
        schema = remediation_response_schema(finding, "app/index.js")
        self.assertEqual(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["file"]["enum"], ["app/index.js"])
        self.assertEqual(schema["properties"]["vulnerability_id"]["enum"], ["RULE-1"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))

    def test_patch_validator_rejects_multi_file_and_malformed_hunks(self):
        valid = "--- a/app/index.js\n+++ b/app/index.js\n@@ -1 +1 @@\n-old\n+new\n"
        validate_patch(valid, "app/index.js")
        for invalid in (
            "", "--- a/app/index.js\n+++ b/app/index.js\n",
            "--- a/app/index.js\n+++ b/app/index.js\n@@ malformed @@\n-old\n+new\n",
            valid + "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/app/../README.md\n+++ b/app/../README.md\n@@ -1 +1 @@\n-x\n+y\n",
        ):
            with self.subTest(patch=invalid), self.assertRaises(RuntimeError):
                validate_patch(invalid, "app/index.js")

    def test_structured_edit_produces_locally_generated_preflight_checked_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_file = root / "app" / "index.js"
            target_file.parent.mkdir()
            target_file.write_text("res.send(userInput);\n", encoding="utf-8")
            original = target_file.read_bytes().decode("utf-8")
            import subprocess
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "add", "app/index.js"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            original = target_file.read_bytes().decode("utf-8")
            finding = {"vulnerability_id": "RULE-1", "severity": "MEDIUM"}
            prompt = json.dumps({"constraints": [], "affected_file_content": original})
            proposal = edit_proposal()
            with mock_patch("ai_remediation_agent.request_remediation", return_value=(proposal, "test-model")) as request:
                returned, model, patch_text, updated = request_valid_patch(
                    prompt, finding, "app/index.js", root, original,
                )
            self.assertIs(returned, proposal)
            self.assertEqual(model, "test-model")
            self.assertEqual(updated, original.replace("res.send(userInput);", "res.type('text').send(userInput);"))
            self.assertIn("@@ -1 +1 @@", patch_text)
            self.assertEqual(target_file.read_bytes().decode("utf-8"), original)
            request.assert_called_once()
            self.assertEqual(request.call_args.kwargs["response_schema"]["properties"]["file"]["enum"], ["app/index.js"])

    def test_git_apply_check_diagnostic_is_returned_to_one_correction_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_file = root / "app" / "index.js"
            target_file.parent.mkdir()
            target_file.write_text("res.send(userInput);\n", encoding="utf-8")
            original = target_file.read_bytes().decode("utf-8")
            finding = {"vulnerability_id": "RULE-1", "severity": "MEDIUM"}
            proposal = edit_proposal()
            checked_fail = SimpleNamespace(returncode=1, stderr="error: injected preflight diagnostic", stdout="")
            checked_pass = SimpleNamespace(returncode=0, stderr="", stdout="")
            prompt = json.dumps({"constraints": [], "affected_file_content": original})
            with mock_patch("ai_remediation_agent.request_remediation", side_effect=[(proposal, "test-model"), (proposal, "test-model")]) as request, \
                 mock_patch("ai_remediation_agent.run", side_effect=[checked_fail, checked_pass]) as git_run:
                _, _, patch_text, _ = request_valid_patch(prompt, finding, "app/index.js", root, original)
            self.assertEqual(request.call_count, 2)
            retry_prompt = json.loads(request.call_args_list[1].args[0])
            self.assertIn("git apply --check", retry_prompt["edit_validation_feedback"])
            self.assertIn("injected preflight diagnostic", retry_prompt["edit_validation_feedback"])
            self.assertEqual(git_run.call_count, 2)
            self.assertIn("--- a/app/index.js", patch_text)
            self.assertEqual(target_file.read_bytes().decode("utf-8"), original)

    def test_empty_invalid_or_wrong_shape_scanner_reports_fail_closed(self):
        cases = [
            ("semgrep", "", 0, "empty report"),
            ("semgrep", "{}", 0, "invalid shape"),
            ("gitleaks", "{}", 0, "invalid shape"),
            ("gitleaks", "", 0, "empty report"),
            ("semgrep", '{"results":[]}', 1, "exit code 1"),
            ("trivy", "", 0, "empty report"),
            ("trivy", '{"Results":null}', 0, "invalid shape"),
            ("dockerfile-policy", "[]", 0, "invalid shape"),
            ("k8s-policy", "", 0, "empty report"),
        ]
        for scanner, stdout, code, message in cases:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(scanner=scanner, stdout=stdout, code=code):
                result = SimpleNamespace(returncode=code, stdout=stdout, stderr="")
                with mock_patch("ai_remediation_agent.run", return_value=result):
                    with self.assertRaisesRegex(RuntimeError, message):
                        docker_json_scan(Path(temporary), Path(temporary), scanner, ["scanner"])

    def test_valid_empty_vulnerability_reports_are_distinct_from_missing_reports(self):
        self.assertEqual(parse_scanner_report("semgrep", '{"results":[]}'), {"results": []})
        self.assertEqual(parse_scanner_report("gitleaks", "[]"), [])
        self.assertEqual(parse_scanner_report("trivy", '{"Results":[]}'), {"Results": []})
        self.assertEqual(parse_scanner_report("dockerfile-policy", '[{"filename":"Dockerfile","successes":8}]'),
                         [{"filename": "Dockerfile", "successes": 8}])

    def test_rescan_comparison_detects_remaining_target_and_new_findings(self):
        target = {"source": "trivy", "vulnerability_id": "CVE-1", "package_name": "pkg", "affected_file": "Dockerfile"}
        self.assertEqual(compare_scan_results([target], [], target), ([], []))
        self.assertEqual(compare_scan_results([target], [target], target)[0], [target])
        new_finding = {"source": "trivy", "vulnerability_id": "CVE-2", "package_name": "pkg", "affected_file": "Dockerfile"}
        self.assertEqual(compare_scan_results([target], [new_finding], target)[1], [new_finding])

    def test_commit_stages_only_the_approved_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app").mkdir()
            target = root / "app" / "index.js"
            target.write_text("before\n", encoding="utf-8")
            import subprocess
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "add", "app/index.js"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            target.write_text("after\n", encoding="utf-8")
            (root / "README.md").write_text("unrelated untracked file\n", encoding="utf-8")
            commit_one_file(root, "app/index.js", "9", "CVE-TEST")
            changed = subprocess.run(
                ["git", "show", "--pretty=", "--name-only", "HEAD"],
                cwd=root, capture_output=True, text=True, check=True,
            ).stdout.splitlines()
            self.assertEqual(changed, ["app/index.js"])
            self.assertTrue((root / "README.md").exists())


if __name__ == "__main__":
    unittest.main()
