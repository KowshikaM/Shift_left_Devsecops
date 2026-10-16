import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard-service"))

import app as dashboard_app


class ScannerOnlyIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_db_path = dashboard_app.DB_PATH
        self.previous_ingest_token = dashboard_app.DASHBOARD_INGEST_TOKEN
        dashboard_app.DB_PATH = str(Path(self.temp_dir.name) / "dashboard.db")
        dashboard_app.DASHBOARD_INGEST_TOKEN = "test-ingest-token"
        dashboard_app.init_db()
        self.client = dashboard_app.app.test_client()

    def tearDown(self):
        dashboard_app.DB_PATH = self.previous_db_path
        dashboard_app.DASHBOARD_INGEST_TOKEN = self.previous_ingest_token
        self.temp_dir.cleanup()

    def payload(self, source="semgrep"):
        return {
            "build_number": "semgrep-test-7",
            "commit_sha": "test-commit-sha",
            "branch": "origin/e2e-finding-lifecycle-test",
            "gate_status": "NOT_APPLICABLE",
            "pipeline_status": "PASSED",
            "findings_complete": True,
            "scan_scope": ["semgrep"],
            "findings": [{
                "source": source,
                "severity": "MEDIUM",
                "file_path": "app/lifecycle-fixture.js:2",
                "rule_id": "javascript.test-rule",
                "vulnerability_id": "javascript.test-rule",
                "message": "Controlled lifecycle test finding",
            }],
        }

    def test_ingestion_requires_bearer_token(self):
        response = self.client.post("/api/scanner-builds", json=self.payload())
        self.assertEqual(response.status_code, 401)

    def test_ingestion_rejects_findings_outside_semgrep_scope(self):
        response = self.client.post(
            "/api/scanner-builds",
            json=self.payload(source="trivy"),
            headers={"Authorization": "Bearer test-ingest-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_authenticated_complete_semgrep_scan_is_persisted_without_gate_pass(self):
        response = self.client.post(
            "/api/scanner-builds",
            json=self.payload(),
            headers={"Authorization": "Bearer test-ingest-token"},
        )
        self.assertEqual(response.status_code, 201)

        build_id = response.get_json()["build_id"]
        stored = self.client.get(f"/api/builds/{build_id}").get_json()
        self.assertEqual(stored["build"]["build_number"], "semgrep-test-7")
        self.assertEqual(stored["build"]["commit_sha"], "test-commit-sha")
        self.assertEqual(stored["build"]["gate_status"], "NOT_APPLICABLE")
        self.assertEqual(len(stored["findings"]), 1)
        self.assertEqual(stored["findings"][0]["source"], "semgrep")


if __name__ == "__main__":
    unittest.main()