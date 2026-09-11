#!/usr/bin/env python3
"""Legacy bulk-AI entry point.

The secure pipeline deliberately does not run bulk AI remediation automatically.
Use the dashboard's "Apply AI fix" action, which invokes Jenkinsfile.single-fix,
validates the patch with the full security gate, and opens a human-reviewed PR
only after validation succeeds.
"""
print("[ai-remediation] Bulk automatic remediation is disabled by design.")
print("[ai-remediation] Use the dashboard ticket workflow -> Apply AI fix.")
