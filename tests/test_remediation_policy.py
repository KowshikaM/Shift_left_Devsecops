import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "dashboard-service"))

from remediation_policy import classify_finding, load_scanner_findings, semgrep_severity
from ai_remediation_agent import commit_one_file, compare_scan_results, validate_patch, validate_proposal


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

    def test_patch_must_change_only_expected_file(self):
        valid = "--- a/app/index.js\n+++ b/app/index.js\n@@ -1 +1 @@\n-old\n+new\n"
        validate_patch(valid, "app/index.js")
        invalid = "--- a/app/index.js\n+++ b/app/index.js\n--- a/README.md\n+++ b/README.md\n"
        with self.assertRaises(RuntimeError):
            validate_patch(invalid, "app/index.js")

    def test_proposal_cannot_change_severity_or_target(self):
        finding = {"vulnerability_id": "CVE-1", "severity": "LOW"}
        proposal = {
            "vulnerability_id": "CVE-1", "severity": "HIGH", "affected_file": "app/index.js",
            "analysis": "cause", "remediation": "fix", "patch": "diff",
            "confidence": "HIGH", "tests_required": True, "reason": "minimal",
        }
        with self.assertRaises(RuntimeError):
            validate_proposal(proposal, finding, "app/index.js")

    def test_rescan_comparison_detects_remaining_target_and_new_findings(self):
        target = {"source": "trivy", "vulnerability_id": "CVE-1", "package_name": "pkg", "affected_file": "Dockerfile"}
        baseline = [target]
        self.assertEqual(compare_scan_results(baseline, [], target), ([], []))
        self.assertEqual(compare_scan_results(baseline, [target], target)[0], [target])
        new_finding = {"source": "trivy", "vulnerability_id": "CVE-2", "package_name": "pkg", "affected_file": "Dockerfile"}
        self.assertEqual(compare_scan_results(baseline, [new_finding], target)[1], [new_finding])
        baseline_policy = {"source": "opa-policy", "vulnerability_id": "policy-violation", "package_name": "", "affected_file": "k8s/deployment.yaml", "description": "original policy"}
        new_policy = {**baseline_policy, "description": "new policy violation"}
        self.assertEqual(compare_scan_results([baseline_policy], [new_policy], target)[1], [new_policy])

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
