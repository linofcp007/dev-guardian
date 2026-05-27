-- dev-guardian MCP server — initial schema (version 1).
-- Authoritative reference: .specs/dev-guardian-mcp/design.md → "SQLite schema".

CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_meta (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id                TEXT PRIMARY KEY,
  scan_type         TEXT NOT NULL,
  project_path      TEXT NOT NULL,
  tree_hash         TEXT NOT NULL,
  started_at        TEXT NOT NULL,
  finished_at       TEXT,
  status            TEXT NOT NULL,
  tools_run         TEXT NOT NULL DEFAULT '[]',
  missing_tools     TEXT NOT NULL DEFAULT '[]',
  report_dir        TEXT,
  error             TEXT,
  cached_from       TEXT,
  meta              TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scans_tree_hash  ON scans(tree_hash);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);

CREATE TABLE IF NOT EXISTS findings (
  fingerprint      TEXT NOT NULL,
  scan_id          TEXT NOT NULL,
  tool             TEXT NOT NULL,
  rule_id          TEXT,
  severity         TEXT NOT NULL,
  category         TEXT NOT NULL,
  subcategory      TEXT,
  title            TEXT NOT NULL,
  message          TEXT,
  file_path        TEXT,
  line_start       INTEGER,
  line_end         INTEGER,
  snippet          TEXT,
  fix_available    INTEGER NOT NULL DEFAULT 0,
  fix_applied      INTEGER NOT NULL DEFAULT 0,
  raw              TEXT,
  PRIMARY KEY (fingerprint, scan_id),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_category    ON findings(category);

CREATE TABLE IF NOT EXISTS cves (
  cve_id              TEXT NOT NULL,
  package_name        TEXT NOT NULL,
  installed_version   TEXT,
  fixed_version       TEXT,
  severity            TEXT NOT NULL,
  first_seen_scan_id  TEXT NOT NULL,
  last_seen_scan_id   TEXT NOT NULL,
  PRIMARY KEY (cve_id, package_name, installed_version),
  FOREIGN KEY (first_seen_scan_id) REFERENCES scans(id),
  FOREIGN KEY (last_seen_scan_id)  REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS suppressions (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_fingerprint  TEXT NOT NULL,
  reason               TEXT NOT NULL,
  created_at           TEXT NOT NULL,
  expires_at           TEXT,
  created_by           TEXT
);

CREATE INDEX IF NOT EXISTS idx_suppressions_fp          ON suppressions(finding_fingerprint);
CREATE INDEX IF NOT EXISTS idx_suppressions_expires_at  ON suppressions(expires_at);

CREATE TABLE IF NOT EXISTS baselines (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id  TEXT NOT NULL,
  set_at   TEXT NOT NULL,
  note     TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tree_cache (
  tree_hash   TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL,
  scan_type   TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS stack_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stack_captured_at ON stack_snapshots(captured_at DESC);
