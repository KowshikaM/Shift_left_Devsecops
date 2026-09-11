-- Builds table: one row per pipeline run
CREATE TABLE IF NOT EXISTS builds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_number TEXT NOT NULL,
    commit_sha TEXT,
    branch TEXT,
    triggered_by TEXT,
    gate_status TEXT NOT NULL,           -- 'PASS' or 'FAIL'
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0,
    deployed INTEGER DEFAULT 0,          -- 1 if this build was deployed
    created_at TEXT DEFAULT (datetime('now'))
);

-- Findings/tickets table: one row per individual vulnerability found in a build
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_id INTEGER NOT NULL REFERENCES builds(id),
    source TEXT NOT NULL,                -- 'trivy' | 'semgrep' | 'gitleaks' | 'opa-policy'
    severity TEXT NOT NULL,
    file_path TEXT,
    rule_id TEXT,
    message TEXT,
    fixed_version TEXT,
    status TEXT DEFAULT 'open',          -- 'open' | 'ai_fix_requested' | 'ai_fix_pr_opened' | 'resolved_manually' | 'resolved'
    ai_explanation TEXT,
    pr_url TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Audit log: a plain-English event trail for every action the system takes
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_id INTEGER REFERENCES builds(id),
    finding_id INTEGER REFERENCES findings(id),
    event TEXT NOT NULL,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
