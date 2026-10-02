-- 017_llm_scan.sql
-- The LLM-assisted scan's plans and tasks, so a plan survives a server restart
-- and resumes by plan_id (NFR-2, US-3.AC-4).
--
-- Holds no code and no prompts: a task names files and lines, and the brief is
-- rebuilt from them. Structured fields (limits, estimate, target, result) are
-- JSON text, read whole and never queried by key.
--
-- Additive: two new tables, no change to an existing one. `scan_id` points at
-- the plan's `llm_scan` scan; retention deletes a plan's rows with that scan
-- and holds the scan back while the plan is open (storage/maintenance.ts).

CREATE TABLE IF NOT EXISTS llm_scan_plans (
  id                  TEXT PRIMARY KEY,
  project_path        TEXT NOT NULL,
  scan_id             TEXT NOT NULL REFERENCES scans(id),
  modes               TEXT NOT NULL,
  prompt_version      TEXT NOT NULL,
  tree_hash           TEXT NOT NULL,
  surface_snapshot_id INTEGER,
  limits              TEXT NOT NULL,
  estimate            TEXT NOT NULL,
  confirmed           INTEGER NOT NULL DEFAULT 0,
  status              TEXT NOT NULL DEFAULT 'open',
  not_eligible        TEXT NOT NULL DEFAULT '[]',
  set_aside           TEXT NOT NULL DEFAULT '[]',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_llm_scan_plans_project ON llm_scan_plans(project_path, created_at);
CREATE INDEX IF NOT EXISTS idx_llm_scan_plans_scan ON llm_scan_plans(scan_id);

CREATE TABLE IF NOT EXISTS llm_scan_tasks (
  plan_id          TEXT NOT NULL REFERENCES llm_scan_plans(id),
  task_id          TEXT NOT NULL,
  kind             TEXT NOT NULL,
  target           TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'open',
  lease_token      TEXT,
  lease_expires_at TEXT,
  attempts         INTEGER NOT NULL DEFAULT 0,
  file_hashes      TEXT NOT NULL DEFAULT '{}',
  brief_chars      INTEGER,
  response_chars   INTEGER,
  independence     TEXT,
  result           TEXT,
  closed_reason    TEXT,
  delivered_at     TEXT,
  closed_at        TEXT,
  PRIMARY KEY (plan_id, task_id)
);
