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
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        conn.executescript(f.read())

    # The dashboard uses a persistent SQLite volume. CREATE TABLE IF NOT EXISTS
    # does not add new columns to an existing table, so apply tiny idempotent
    # migrations whenever the container starts.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(builds)").fetchall()}
    migrations = {
        "pipeline_status": "ALTER TABLE builds ADD COLUMN pipeline_status TEXT NOT NULL DEFAULT 'RUNNING'",
        "current_stage": "ALTER TABLE builds ADD COLUMN current_stage TEXT",
        "jenkins_url": "ALTER TABLE builds ADD COLUMN jenkins_url TEXT",
        "updated_at": "ALTER TABLE builds ADD COLUMN updated_at TEXT",
    }
    for column, statement in migrations.items():
        if column not in columns:
            conn.execute(statement)

    finding_columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    finding_migrations = {
        "remediation_type": "ALTER TABLE findings ADD COLUMN remediation_type TEXT DEFAULT 'MANUAL'",
        "remediation_reason": "ALTER TABLE findings ADD COLUMN remediation_reason TEXT",
        "remediation_guide": "ALTER TABLE findings ADD COLUMN remediation_guide TEXT",
        "before_status": "ALTER TABLE findings ADD COLUMN before_status TEXT DEFAULT 'BLOCKED'",
        "after_status": "ALTER TABLE findings ADD COLUMN after_status TEXT DEFAULT 'PENDING'",
        "validation_summary": "ALTER TABLE findings ADD COLUMN validation_summary TEXT",
    }
    for column, statement in finding_migrations.items():
        if column not in finding_columns:
            conn.execute(statement)

    if "updated_at" not in columns:
        conn.execute("UPDATE builds SET updated_at = COALESCE(created_at, datetime('now')) WHERE updated_at IS NULL")

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
    findings = payload.get("findings", []) or []
    findings_complete = bool(payload.get("findings_complete", False))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = str(finding.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    build_number = payload.get("build_number", "unknown")
    commit_sha = payload.get("commit_sha", "")
    existing = db.execute(
        "SELECT id FROM builds WHERE build_number = ? AND commit_sha = ? LIMIT 1",
        (build_number, commit_sha),
    ).fetchone()

    now = datetime.utcnow().isoformat()
    gate_status = payload.get("gate_status", "PENDING")
    pipeline_status = payload.get("pipeline_status", "RUNNING")
    current_stage = payload.get("current_stage", "")
    jenkins_url = payload.get("jenkins_url", "")
    deployed = 1 if payload.get("deployed") else 0

    if existing:
        build_id = existing["id"]
        db.execute(
            """UPDATE builds SET branch=?, triggered_by=?, gate_status=?, pipeline_status=?,
               current_stage=?, jenkins_url=?, critical_count=?, high_count=?, medium_count=?,
               low_count=?, total_count=?, deployed=?, updated_at=? WHERE id=?""",
            (payload.get("branch", "main"), payload.get("triggered_by", "unknown"),
             gate_status, pipeline_status, current_stage, jenkins_url,
             counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
             len(findings), deployed, now, build_id),
        )
        if findings_complete:
            db.execute("DELETE FROM findings WHERE build_id = ?", (build_id,))
    else:
        cur = db.execute(
            """INSERT INTO builds
               (build_number, commit_sha, branch, triggered_by, gate_status, pipeline_status,
                current_stage, jenkins_url, critical_count, high_count, medium_count, low_count,
                total_count, deployed, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (build_number, commit_sha, payload.get("branch", "main"),
             payload.get("triggered_by", "unknown"), gate_status, pipeline_status,
             current_stage, jenkins_url, counts["CRITICAL"], counts["HIGH"],
             counts["MEDIUM"], counts["LOW"], len(findings), deployed, now, now),
        )
        build_id = cur.lastrowid

    # Stage updates only change pipeline metadata. The final/gate publication
    # sends findings_complete=true so the finding list is replaced atomically.
    if findings_complete:
        for finding in findings:
            db.execute(
                """INSERT INTO findings
                   (build_id, source, severity, file_path, rule_id, message, fixed_version, status,
                    remediation_type, remediation_reason, remediation_guide, before_status, after_status,
                    validation_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)""",
                (build_id, finding.get("source", ""), finding.get("severity", "LOW"),
                 finding.get("file_path", ""), finding.get("rule_id", ""),
                 finding.get("message", ""), finding.get("fixed_version", "-"),
                 finding.get("remediation_type", "MANUAL"),
                 finding.get("remediation_reason", "Follow the remediation guide for a manual fix."),
                 finding.get("remediation_guide", "Review the issue details and fix it in the affected file."),
                 finding.get("before_status", "BLOCKED"),
                 finding.get("after_status", "PENDING"),
                 finding.get("validation_summary", "Before: blocked. After: validation pending.")),
            )

    db.commit()
    log_event(
        build_id, None, "pipeline_update",
        f"Stage: {current_stage or 'unknown'}, Status: {pipeline_status}, Gate: {gate_status}, Findings: {len(findings)}"
    )

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

    remediation_type = str(finding["remediation_type"] or "MANUAL").upper()
    if remediation_type not in {"AI_ELIGIBLE", "AI_ASSISTED"}:
        log_event(finding["build_id"], finding_id, "ai_fix_blocked_manual",
                  "AI is blocked because the finding requires manual remediation.")
        return jsonify({
            "status": "blocked",
            "detail": "This finding requires manual remediation. Review the remediation guide before changing the code.",
            "remediation_type": remediation_type,
            "remediation_reason": finding["remediation_reason"] or "Manual review required.",
        }), 400

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


@app.route("/api/tickets/<int:finding_id>/validation-result", methods=["POST"])
def update_validation_result(finding_id):
    """Update the existing ticket with the real post-remediation validation outcome."""
    payload = request.get_json(force=True) if request.data else {}
    db = get_db()
    finding = db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not finding:
        return jsonify({"error": "not found"}), 404

    status = str(payload.get("status", "PENDING")).upper()
    if status not in {"PASS", "FAIL", "PENDING"}:
        status = "PENDING"

    validation_summary = payload.get("validation_summary") or (
        f"Before: {finding['before_status'] or 'BLOCKED'}. After: {status}."
    )
    ttl = payload.get("explanation") or validation_summary

    db.execute(
        "UPDATE findings SET status = ?, after_status = ?, validation_summary = ?, ai_explanation = ?, updated_at = ? WHERE id = ?",
        ("ai_fix_validated" if status in {"PASS", "FAIL"} else "ai_fix_pending",
         status,
         validation_summary,
         ttl,
         datetime.utcnow().isoformat(),
         finding_id),
    )
    db.commit()

    finding = db.execute("SELECT build_id FROM findings WHERE id = ?", (finding_id,)).fetchone()
    log_event(finding["build_id"], finding_id, "validation_result", f"after_status={status}; {validation_summary}")
    return jsonify({"status": "ok", "after_status": status})


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
