import os
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import publish_to_dashboard


class ScannerPublisherTests(unittest.TestCase):
    def test_scanner_only_metadata_overrides_pipeline_defaults(self):
        response = type("Response", (), {
            "__enter__": lambda self: self,
            "__exit__": lambda self, *args: None,
            "read": lambda self: b'{"build_id": 9}',
        })()
        environment = {
            "DASHBOARD_GATE_STATUS": "NOT_APPLICABLE",
            "DASHBOARD_PIPELINE_STATUS": "PASSED",
            "PIPELINE_STATUS": "RUNNING",
            "GATE_STATUS": "PENDING",
            "PUBLISH_FINDINGS": "0",
        }
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(publish_to_dashboard.urllib.request, "urlopen", return_value=response) as urlopen, \
             patch("sys.stdout", new_callable=io.StringIO):
            publish_to_dashboard.main()

        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload["gate_status"], "NOT_APPLICABLE")
        self.assertEqual(payload["pipeline_status"], "PASSED")

    def test_required_http_rejection_is_not_reported_as_unreachable(self):
        error = HTTPError("http://localhost:2001/api/scanner-builds", 401, "UNAUTHORIZED", {}, None)
        with patch.dict(os.environ, {"PUBLISH_REQUIRED": "1"}), \
             patch.object(publish_to_dashboard.urllib.request, "urlopen", side_effect=error), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit) as raised:
                publish_to_dashboard.main()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Dashboard rejected update: HTTP 401", output.getvalue())
        self.assertNotIn("Could not reach", output.getvalue())

    def test_scanner_scope_filters_other_report_families(self):
        reports = [
            {"source": "semgrep", "severity": "MEDIUM", "affected_file": "app/test.js",
             "rule_id": "javascript.test-rule", "vulnerability_id": "javascript.test-rule",
             "affected_line": 2, "description": "Test finding", "package_name": "",
             "installed_version": "", "fixed_version": "", "scanner_recommendation": ""},
            {"source": "trivy", "severity": "HIGH", "affected_file": "Dockerfile",
             "rule_id": "CVE-TEST", "vulnerability_id": "CVE-TEST",
             "affected_line": None, "description": "Other scan family", "package_name": "zlib",
             "installed_version": "1.0", "fixed_version": "1.1", "scanner_recommendation": ""},
        ]
        with patch.dict(os.environ, {"PUBLISH_SCANNERS": "semgrep"}), \
             patch.object(publish_to_dashboard, "load_scanner_findings", return_value=reports):
            findings = publish_to_dashboard.collect_findings()

        self.assertEqual([finding["source"] for finding in findings], ["semgrep"])

    def test_unknown_scanner_scope_is_rejected(self):
        with patch.dict(os.environ, {"PUBLISH_SCANNERS": "made-up-scanner"}):
            with self.assertRaises(ValueError):
                publish_to_dashboard.collect_findings()


if __name__ == "__main__":
    unittest.main()