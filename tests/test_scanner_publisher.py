import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import publish_to_dashboard


class ScannerPublisherTests(unittest.TestCase):
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