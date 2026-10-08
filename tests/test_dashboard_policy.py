import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard-service"))
import app as dashboard_app


class DashboardEligibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_callback_token = dashboard_app.DASHBOARD_CALLBACK_TOKEN
        dashboard_app.DASHBOARD_CALLBACK_TOKEN = "callback-test-token"
        dashboard_app.DB_PATH = str(Path(self.temp_dir.name) / "dashboard.db")
        dashboard_app.init_db()
        self.client = dashboard_app.app.test_client()

    def tearDown(self):
        dashboard_app.DASHBOARD_CALLBACK_TOKEN = self.previous_callback_token
        self.temp_dir.cleanup()

    def add_ticket(self, severity, source="trivy", message="Example vulnerability"):
        response = self.client.post("/api/builds", json={
            "build_number": "test-1", "commit_sha": severity + source,
            "gate_status": "FAIL", "findings_complete": True,
            "findings": [{
                "source": source, "severity": severity, "rule_id": "CVE-TEST",
                "vulnerability_id": "CVE-TEST", "message": message,
                "file_path": "Dockerfile", "remediation_type": "AI_ELIGIBLE",
            }],
        })
        self.assertEqual(response.status_code, 201)
        ticket = self.client.get("/api/tickets").get_json()[0]
        return ticket["id"]

    def test_high_finding_is_blocked_even_if_saved_as_ai_eligible(self):
        ticket_id = self.add_ticket("HIGH", source="opa-policy")
        with patch.object(dashboard_app, "trigger_jenkins_fix_job") as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "blocked")
        trigger.assert_not_called()

    def test_medium_non_secret_finding_can_trigger_existing_job(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "DASHBOARD_CALLBACK_TOKEN", "callback-test-token"), \
             patch.object(dashboard_app, "trigger_jenkins_fix_job", return_value=(True, None)) as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "requested")
        trigger.assert_called_once()
        second = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(second.status_code, 409)
        trigger.assert_called_once()

    def test_missing_jenkins_configuration_returns_actionable_error(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        with patch.object(dashboard_app, "JENKINS_USER", ""), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", ""), \
             patch.object(dashboard_app, "DASHBOARD_CALLBACK_TOKEN", ""), \
             patch.object(dashboard_app, "trigger_jenkins_fix_job") as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 503)
        self.assertIn("JENKINS_USER", response.get_json()["detail"])
        trigger.assert_not_called()

    def test_ticket_list_reports_ai_availability(self):
        self.add_ticket("MEDIUM", source="trivy")
        with patch.object(dashboard_app, "JENKINS_USER", ""), patch.object(dashboard_app, "JENKINS_API_TOKEN", ""):
            ticket = self.client.get("/api/tickets").get_json()[0]
        self.assertTrue(ticket["ai_eligible"])
        self.assertFalse(ticket["ai_action_available"])
        self.assertIn("LOW and MEDIUM", ticket["ai_block_reason"])

    def test_ticket_action_is_unavailable_without_callback_secret(self):
        self.add_ticket("MEDIUM", source="trivy")
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "DASHBOARD_CALLBACK_TOKEN", ""):
            ticket = self.client.get("/api/tickets").get_json()[0]
        self.assertTrue(ticket["ai_eligible"])
        self.assertFalse(ticket["ai_action_available"])

    def test_jenkins_build_request_does_not_include_callback_url_parameter(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        response_mock = object()
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "DASHBOARD_CALLBACK_TOKEN", "callback-test-token"), \
             patch.object(dashboard_app, "jenkins_crumb", return_value=(None, None)), \
             patch("app.urllib.request.urlopen", return_value=response_mock) as urlopen:
            response = self.client.post(
                f"/api/tickets/{ticket_id}/apply-ai-fix", headers={"Host": "attacker.example"},
            )
        self.assertEqual(response.status_code, 200)
        triggered = urlopen.call_args.args[0].full_url
        self.assertNotIn("DASHBOARD_CALLBACK_URL", triggered)
        self.assertNotIn("attacker.example", triggered)

    def test_same_file_secret_blocks_ai_for_medium_finding(self):
        ticket_id = self.add_ticket("MEDIUM", source="semgrep")
        ticket = self.client.get("/api/tickets").get_json()[0]
        with dashboard_app.app.app_context():
            db = dashboard_app.get_db()
            db.execute(
                "INSERT INTO findings (build_id, source, severity, file_path, rule_id, message) VALUES (?, ?, ?, ?, ?, ?)",
                (ticket["build_id"], "gitleaks", "CRITICAL", "/repo/Dockerfile", "secret", "Credential detected"),
            )
            db.commit()
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "trigger_jenkins_fix_job") as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Gitleaks secret", response.get_json()["remediation_reason"])
        trigger.assert_not_called()
        ticket = next(item for item in self.client.get("/api/tickets").get_json() if item["id"] == ticket_id)
        self.assertFalse(ticket["ai_eligible"])
        self.assertFalse(ticket["ai_action_available"])

    def test_low_secret_finding_is_blocked(self):
        ticket_id = self.add_ticket("LOW", source="gitleaks", message="credential detected")
        with patch.object(dashboard_app, "trigger_jenkins_fix_job") as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 400)
        trigger.assert_not_called()

    def test_explicit_retry_is_allowed_only_after_failed_ai_review_and_audited(self):
        ticket_id = self.add_ticket("MEDIUM", source="semgrep")
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "trigger_jenkins_fix_job", return_value=(True, None)) as trigger:
            initial = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
            self.assertEqual(initial.status_code, 200)
            failed = self.client.post(
                f"/api/tickets/{ticket_id}/validation-result",
                headers={"Authorization": "Bearer callback-test-token"},
                json={"status": "FAIL", "remediation_status": "MANUAL_REVIEW", "test_status": "NOT_RUN"},
            )
            self.assertEqual(failed.status_code, 200)
            retry = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
            self.assertEqual(retry.status_code, 200)
            self.assertEqual(retry.get_json()["status"], "requested")
        self.assertEqual(trigger.call_count, 2)
        ticket = next(item for item in self.client.get("/api/tickets").get_json() if item["id"] == ticket_id)
        self.assertEqual(ticket["ai_attempt_count"], 2)
        with dashboard_app.app.app_context():
            events = dashboard_app.get_db().execute(
                "SELECT event FROM audit_log WHERE finding_id=? ORDER BY id", (ticket_id,),
            ).fetchall()
        self.assertIn("ai_fix_retry_requested", [row["event"] for row in events])

    def test_trigger_failure_releases_ticket_reservation(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        with patch.object(dashboard_app, "JENKINS_USER", "test-user"), \
             patch.object(dashboard_app, "JENKINS_API_TOKEN", "test-token"), \
             patch.object(dashboard_app, "trigger_jenkins_fix_job", return_value=(False, "queue unavailable")):
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 502)
        ticket = next(item for item in self.client.get("/api/tickets").get_json() if item["id"] == ticket_id)
        self.assertEqual(ticket["status"], "open")
        self.assertEqual(ticket["remediation_status"], "PENDING")


    def test_validation_callback_persists_agent_evidence(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        response = self.client.post(f"/api/tickets/{ticket_id}/validation-result", json={
            "status": "PASS", "analysis": "Root cause analysis",
            "proposed_remediation": "Upgrade the affected package",
            "files_changed": ["app/package.json"], "test_status": "PASS",
            "rescan_status": "PASS", "remediation_status": "VALIDATED_PR_READY",
            "before_scan_result": "before summary", "after_scan_result": "after summary",
        }, headers={"Authorization": "Bearer callback-test-token"})
        self.assertEqual(response.status_code, 200)
        ticket = self.client.get("/api/tickets").get_json()[0]
        self.assertEqual(ticket["ai_analysis"], "Root cause analysis")
        self.assertEqual(ticket["proposed_remediation"], "Upgrade the affected package")
        self.assertEqual(ticket["files_changed"], '["app/package.json"]')
        self.assertEqual(ticket["test_status"], "PASS")
        self.assertEqual(ticket["after_scan_result"], "after summary")

    def test_validation_and_pr_callbacks_reject_missing_or_wrong_authentication(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        response = self.client.post(f"/api/tickets/{ticket_id}/validation-result", json={"status": "PASS"})
        self.assertEqual(response.status_code, 401)
        response = self.client.post(
            f"/api/tickets/{ticket_id}/mark-pr-opened", json={"pr_url": "https://github.com/example/repo/pull/1"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        self.assertEqual(response.status_code, 401)
        ticket = next(item for item in self.client.get("/api/tickets").get_json() if item["id"] == ticket_id)
        self.assertEqual(ticket["after_status"], "PENDING")


if __name__ == "__main__":
    unittest.main()
