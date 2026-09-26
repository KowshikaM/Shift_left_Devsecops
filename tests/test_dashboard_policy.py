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
        dashboard_app.DB_PATH = str(Path(self.temp_dir.name) / "dashboard.db")
        dashboard_app.init_db()
        self.client = dashboard_app.app.test_client()

    def tearDown(self):
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
        with patch.object(dashboard_app, "trigger_jenkins_fix_job", return_value=(True, None)) as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "requested")
        trigger.assert_called_once()

    def test_low_secret_finding_is_blocked(self):
        ticket_id = self.add_ticket("LOW", source="gitleaks", message="credential detected")
        with patch.object(dashboard_app, "trigger_jenkins_fix_job") as trigger:
            response = self.client.post(f"/api/tickets/{ticket_id}/apply-ai-fix")
        self.assertEqual(response.status_code, 400)
        trigger.assert_not_called()

    def test_validation_callback_persists_agent_evidence(self):
        ticket_id = self.add_ticket("MEDIUM", source="trivy")
        response = self.client.post(f"/api/tickets/{ticket_id}/validation-result", json={
            "status": "PASS", "analysis": "Root cause analysis",
            "proposed_remediation": "Upgrade the affected package",
            "files_changed": ["app/package.json"], "test_status": "PASS",
            "rescan_status": "PASS", "remediation_status": "VALIDATED_PR_READY",
            "before_scan_result": "before summary", "after_scan_result": "after summary",
        })
        self.assertEqual(response.status_code, 200)
        ticket = self.client.get("/api/tickets").get_json()[0]
        self.assertEqual(ticket["ai_analysis"], "Root cause analysis")
        self.assertEqual(ticket["proposed_remediation"], "Upgrade the affected package")
        self.assertEqual(ticket["files_changed"], '["app/package.json"]')
        self.assertEqual(ticket["test_status"], "PASS")
        self.assertEqual(ticket["after_scan_result"], "after summary")


if __name__ == "__main__":
    unittest.main()
