#!/usr/bin/env python3
"""Send authenticated Jenkins callbacks only to the reviewed local dashboard."""

import argparse
import json
import os
import urllib.parse
import urllib.request

TRUSTED_DASHBOARD_CALLBACK_URL = "http://localhost:2001"
ALLOWED_ENDPOINTS = {"validation-result", "mark-pr-opened", "mark-pr-failed"}


def validate_callback_url(value):
    """Require the exact allowlisted origin; reject URL tricks before using a token."""
    if not isinstance(value, str):
        raise RuntimeError("DASHBOARD_CALLBACK_URL must be a string")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise RuntimeError("DASHBOARD_CALLBACK_URL is malformed") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != "localhost"
        or port != 2001
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("DASHBOARD_CALLBACK_URL is not the trusted http://localhost:2001 destination")
    return TRUSTED_DASHBOARD_CALLBACK_URL


def post_dashboard_callback(callback_url, ticket, endpoint, payload, callback_token):
    trusted_url = validate_callback_url(callback_url)
    if endpoint not in ALLOWED_ENDPOINTS:
        raise RuntimeError("Unsupported dashboard callback endpoint")
    if not str(ticket).isdigit():
        raise RuntimeError("Dashboard ticket ID must be numeric")
    if not callback_token:
        raise RuntimeError("DASHBOARD_CALLBACK_TOKEN is required for dashboard callbacks")

    req = urllib.request.Request(
        f"{trusted_url}/api/tickets/{ticket}/{endpoint}",
        data=json.dumps(payload).encode("utf-8"), method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {callback_token}")
    with urllib.request.urlopen(req, timeout=10):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint", choices=sorted(ALLOWED_ENDPOINTS))
    parser.add_argument("payload_file")
    args = parser.parse_args()
    with open(args.payload_file, encoding="utf-8") as payload_file:
        payload = json.load(payload_file)
    post_dashboard_callback(
        os.environ.get("DASHBOARD_CALLBACK_URL", ""),
        os.environ.get("TICKET_ID", ""),
        args.endpoint,
        payload,
        os.environ.get("DASHBOARD_CALLBACK_TOKEN", ""),
    )
    print(f"[AGENT] Dashboard {args.endpoint} callback completed")


if __name__ == "__main__":
    main()
