#!/usr/bin/env python3
"""
Dashboard Service
------------------
A small, always-running web service that:
  - Receives scan results from Jenkins after every pipeline run (POST /api/builds)
  - Stores everything permanently in SQLite (build history + findings/tickets)
  - Serves a live dashboard website reading from that database
  - Lets a developer click "Apply AI Fix" on a ticket, which remotely
    triggers a focused Jenkins job that uses the configured OpenAI/Groq AI provider to propose a fix just that one
    finding and open a Pull Request

Run with:  python3 app.py   (or via the provided Dockerfile / docker-compose)
Listens on port 5000.
"""

import os
import sqlite3
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, g

DB_PATH = os.environ.get("DASHBOARD_DB_PATH", "dashboard.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# --- REPLACE THESE with your real Jenkins details for the "Apply AI Fix" button to work ---
JENKINS_URL = os.environ.get("JENKINS_URL", "http://localhost:8080")          # REPLACE ME
JENKINS_USER = os.environ.get("JENKINS_USER", "your-jenkins-username")        # REPLACE ME
JENKINS_API_TOKEN = os.environ.get("JENKINS_API_TOKEN", "your-jenkins-token") # REPLACE ME (Jenkins > your user > Security > API Token)
JENKINS_FIX_JOB = os.environ.get("JENKINS_FIX_JOB", "ai-single-fix")          # the parameterized Jenkins job name (see Jenkinsfile.single-fix)

app = Flask(__name__, static_folder="static")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def log_event(build_id, finding_id, event, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (build_id, finding_id, event, detail) VALUES (?, ?, ?, ?)",
        (build_id, finding_id, event, detail),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Ingestion - Jenkins calls this once per pipeline run
# ---------------------------------------------------------------------------
@app.route("/api/builds", methods=["POST"])
def create_build():
    payload = request.get_json(force=True)

    db = get_db()
    findings = payload.get("findings", [])
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1

    existing = db.execute(
        """SELECT id FROM builds WHERE build_number = ? AND commit_sha = ? LIMIT 1""",
        (payload.get("build_number", "unknown"), payload.get("commit_sha", "")),
    ).fetchone()

    if existing:
        build_id = existing["id"]
        db.execute(
            """UPDATE builds SET branch=?, triggered_by=?, gate_status=?,
               critical_count=?, high_count=?, medium_count=?, low_count=?,
               total_count=?, deployed=? WHERE id=?""",
            (payload.get("branch","main"), payload.get("triggered_by","unknown"),
             payload.get("gate_status","FAIL"), counts["CRITICAL"], counts["HIGH"],
             counts["MEDIUM"], counts["LOW"], len(findings),
             1 if payload.get("deployed") else 0, build_id)
        )
        db.execute("DELETE FROM findings WHERE build_id = ?", (build_id,))
    else:
        cur = db.execute(
            """INSERT INTO builds
               (build_number, commit_sha, branch, triggered_by, gate_status,
                critical_count, high_count, medium_count, low_count, total_count, deployed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (payload.get("build_number","unknown"), payload.get("commit_sha",""),
             payload.get("branch","main"), payload.get("triggered_by","unknown"),
             payload.get("gate_status","FAIL"), counts["CRITICAL"], counts["HIGH"],
             counts["MEDIUM"], counts["LOW"], len(findings),
             1 if payload.get("deployed") else 0)
        )
        build_id = cur.lastrowid

    for f in findings:
        db.execute(
            """INSERT INTO findings
               (build_id, source, severity, file_path, rule_id, message, fixed_version, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'open')""",
            (
                build_id, f.get("source", ""), f.get("severity", "LOW"),
                f.get("file_path", ""), f.get("rule_id", ""),
                f.get("message", ""), f.get("fixed_version", "-"),
            ),
        )
    db.commit()

    log_event(build_id, None, "build_ingested",
              f"Gate: {payload.get('gate_status')}, {len(findings)} finding(s)")

    return jsonify({"status": "ok", "build_id": build_id}), 201


# ---------------------------------------------------------------------------
# Read endpoints - the dashboard frontend calls these
# ---------------------------------------------------------------------------
@app.route("/api/builds", methods=["GET"])
def list_builds():
    db = get_db()
    rows = db.execute("SELECT * FROM builds ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/builds/<int:build_id>", methods=["GET"])
def get_build(build_id):
    db = get_db()
    build = db.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    if not build:
        return jsonify({"error": "not found"}), 404
    findings = db.execute("SELECT * FROM findings WHERE build_id = ?", (build_id,)).fetchall()
    return jsonify({"build": dict(build), "findings": [dict(f) for f in findings]})


@app.route("/api/tickets", methods=["GET"])
def list_tickets():
    """All findings across all builds that are not yet resolved, most recent first."""
    db = get_db()
    status_filter = request.args.get("status")
    query = """SELECT findings.*, builds.build_number, builds.commit_sha
               FROM findings JOIN builds ON findings.build_id = builds.id"""
    params = []
    if status_filter:
        query += " WHERE findings.status = ?"
        params.append(status_filter)
    query += " ORDER BY findings.id DESC LIMIT 200"
    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/trends", methods=["GET"])
def trends():
    """Findings count per build, oldest to newest - powers the trend chart."""
    db = get_db()
    rows = db.execute(
        """SELECT build_number, gate_status, critical_count, high_count,
                  medium_count, low_count, created_at
           FROM builds ORDER BY id ASC LIMIT 50"""
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/audit-log", methods=["GET"])
def audit_log():
    db = get_db()
    rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Ticket actions
# ---------------------------------------------------------------------------
def jenkins_crumb():
    """Jenkins CSRF protection requires a crumb token for POST requests."""
    req = urllib.request.Request(f"{JENKINS_URL}/crumbIssuer/api/json")
    auth = base64.b64encode(f"{JENKINS_USER}:{JENKINS_API_TOKEN}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("crumbRequestField"), data.get("crumb")
    except Exception as e:
        print(f"[jenkins] Could not fetch crumb (CSRF protection may be off): {e}")
        return None, None


def trigger_jenkins_fix_job(finding):
    """Remotely triggers the parameterized 'ai-single-fix' Jenkins job."""
    params = urllib.parse.urlencode({
        "FILE_PATH": finding["file_path"] or "",
        "RULE_ID": finding["rule_id"] or "",
        "MESSAGE": finding["message"] or "",
        "SOURCE": finding["source"] or "",
        "TICKET_ID": str(finding["id"]),
        "DASHBOARD_CALLBACK_URL": request.host_url.rstrip("/"),
    })
    url = f"{JENKINS_URL}/job/{JENKINS_FIX_JOB}/buildWithParameters?{params}"

    req = urllib.request.Request(url, method="POST")
    auth = base64.b64encode(f"{JENKINS_USER}:{JENKINS_API_TOKEN}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")

    field, crumb = jenkins_crumb()
    if field and crumb:
        req.add_header(field, crumb)

    try:
        urllib.request.urlopen(req, timeout=10)
        return True, None
    except urllib.error.URLError as e:
        return False, str(e)


@app.route("/api/tickets/<int:finding_id>/apply-ai-fix", methods=["POST"])
def apply_ai_fix(finding_id):
    db = get_db()
    finding = db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not finding:
        return jsonify({"error": "not found"}), 404

    ok, error = trigger_jenkins_fix_job(finding)

    if ok:
        db.execute("UPDATE findings SET status = 'ai_fix_requested', updated_at = ? WHERE id = ?",
                   (datetime.utcnow().isoformat(), finding_id))
        db.commit()
        log_event(finding["build_id"], finding_id, "ai_fix_requested",
                  "Developer clicked Apply AI Fix")
        return jsonify({"status": "requested"})
    else:
        log_event(finding["build_id"], finding_id, "ai_fix_trigger_failed", error)
        return jsonify({"status": "error", "detail": error}), 502


@app.route("/api/tickets/<int:finding_id>/mark-pr-opened", methods=["POST"])
def mark_pr_opened(finding_id):
    """Called by the Jenkins AI-fix job once it has opened the PR."""
    payload = request.get_json(force=True)
    db = get_db()
    db.execute(
        "UPDATE findings SET status = 'ai_fix_pr_opened', ai_explanation = ?, pr_url = ?, updated_at = ? WHERE id = ?",
        (payload.get("explanation", ""), payload.get("pr_url", ""), datetime.utcnow().isoformat(), finding_id),
    )
    db.commit()
    finding = db.execute("SELECT build_id FROM findings WHERE id = ?", (finding_id,)).fetchone()
    log_event(finding["build_id"], finding_id, "ai_fix_pr_opened", payload.get("pr_url", ""))
    return jsonify({"status": "ok"})


@app.route("/api/tickets/<int:finding_id>/resolve", methods=["POST"])
def resolve_ticket(finding_id):
    """Developer fixed it manually (or approved/merged the AI PR)."""
    payload = request.get_json(force=True) if request.data else {}
    db = get_db()
    db.execute(
        "UPDATE findings SET status = 'resolved', updated_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), finding_id),
    )
    db.commit()
    finding = db.execute("SELECT build_id FROM findings WHERE id = ?", (finding_id,)).fetchone()
    log_event(finding["build_id"], finding_id, "resolved", payload.get("note", "Marked resolved"))
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        init_db()  # CREATE TABLE IF NOT EXISTS is safe to re-run
    app.run(host="0.0.0.0", port=5000, debug=False)
