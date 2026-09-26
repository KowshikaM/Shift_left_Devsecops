#!/usr/bin/env python3
"""Import shim for the shared policy module packaged with the dashboard."""

import importlib.util
from pathlib import Path
import sys

_shared_path = Path(__file__).resolve().parents[1] / "dashboard-service" / "remediation_policy.py"
_spec = importlib.util.spec_from_file_location("_shared_remediation_policy", _shared_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load shared remediation policy at {_shared_path}")
_shared = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _shared
_spec.loader.exec_module(_shared)

AI_SEVERITIES = _shared.AI_SEVERITIES
SECRET_SOURCES = _shared.SECRET_SOURCES
classify_finding = _shared.classify_finding
classify_report_directory = _shared.classify_report_directory
load_scanner_findings = _shared.load_scanner_findings
normalized_repo_path = _shared.normalized_repo_path
semgrep_severity = _shared.semgrep_severity
