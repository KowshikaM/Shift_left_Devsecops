#!/usr/bin/env python3
"""Run the shared severity classifier against this build's scanner reports."""

from remediation_policy import classify_report_directory


if __name__ == "__main__":
    classify_report_directory()
