import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from ai_remediation_agent import git_branch


class RemediationBranchRetryTests(unittest.TestCase):
    def test_ticket_branch_name_is_stable_and_local_branch_can_be_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            (repo / "source.txt").write_text("source\n", encoding="utf-8")
            subprocess.run(["git", "add", "source.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
            source_branch = subprocess.run(
                ["git", "branch", "--show-current"], cwd=repo, check=True,
                capture_output=True, text=True,
            ).stdout.strip()

            first_branch = git_branch(repo, "17")
            subprocess.run(["git", "checkout", "-q", source_branch], cwd=repo, check=True)
            retry_branch = git_branch(repo, "17")

            self.assertEqual(first_branch, "ai-remediation/ticket-17")
            self.assertEqual(retry_branch, first_branch)
            current = subprocess.run(
                ["git", "branch", "--show-current"], cwd=repo, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(current, first_branch)

    def test_non_numeric_ticket_id_is_rejected_before_branch_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            with self.assertRaisesRegex(RuntimeError, "Ticket ID must be numeric"):
                git_branch(repo, "ticket-17")


if __name__ == "__main__":
    unittest.main()
