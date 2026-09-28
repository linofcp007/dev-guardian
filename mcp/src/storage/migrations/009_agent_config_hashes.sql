-- 009_agent_config_hashes.sql
-- What `audit_agent_config` compares each run against: one hash per MCP
-- server entry it found last time, keyed by project + where the entry lives.
--
-- `entry_key` is "<source label>::<server name>" (e.g.
-- ".mcp.json::dev-guardian" or "~/.claude.json::some-server") — the same
-- entry, addressed the same way, run over run. `hash` is sha256 of the
-- entry's own JSON (command/args/env/url/type, keys sorted so re-serialising
-- the file does not itself look like a change).
--
-- Deliberately carries NO `scan_id` / no FOREIGN KEY on `scans(id)` — same
-- reasoning `storage/maintenance.ts` already documents for
-- `surface_snapshots` and `finding_validations`: this is CURRENT STATE keyed
-- by project, not scan history, so it must survive scan retention pruning a
-- project's old `agent_audit` scans. A future column that DOES reference
-- `scans(id)` must be indexed and added to `deleteScans` in
-- `storage/maintenance.ts`, per that file's own header — this table has none,
-- so nothing there needs to change.
--
-- One row per (project_path, entry_key); each audit run upserts the rows it
-- saw. A row for an entry that has since been removed from every config file
-- is left in place rather than deleted — harmless (it is simply never looked
-- up again unless the same entry_key reappears), and deleting it would need
-- either a full-table diff per project on every run or a second migration to
-- track "still present", neither of which the brief asked for.

CREATE TABLE IF NOT EXISTS agent_config_hashes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  entry_key    TEXT NOT NULL,
  hash         TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (project_path, entry_key)
);

CREATE INDEX IF NOT EXISTS idx_agent_config_hashes_project ON agent_config_hashes(project_path);
