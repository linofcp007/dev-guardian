-- 012_mcp_tool_pins.sql
-- What `audit_mcp_tools` compares each run against: the tool definitions an
-- MCP server served the last time it was audited, one hash per tool.
--
-- `server_key` is "<config source label>::<server name>" (e.g.
-- ".mcp.json::github") — the same addressing `agent_config_hashes.entry_key`
-- uses, so one server declared in two files is two servers here: they can
-- launch different commands. `hash` is sha256 of the canonical JSON
-- (keys sorted) of `{name, description, inputSchema, annotations}` — a
-- changed hash is a definition that changed under the same name, the "rug
-- pull" that `mcp-tool-definition-changed` reports.
--
-- `mcp_server_pins` records that a server WAS audited, with its tool count:
-- a server that answered with no tools at all has no row in
-- `mcp_tool_pins`, and without this the next audit could not tell "had
-- nothing" (every tool now is new) from "never audited" (nothing to compare).
--
-- Deliberately carries NO `scan_id` / no FOREIGN KEY on `scans(id)` — same
-- reasoning as `009_agent_config_hashes.sql`: this is CURRENT STATE keyed by
-- project, not scan history, so it must survive retention pruning a
-- project's old `mcp_tool_audit` scans. Nothing in `storage/maintenance.ts`
-- needs to change for it.
--
-- Only a server whose listing completed is written, and its set is replaced
-- whole: a tool it no longer lists is deleted once the audit has reported it
-- removed (unlike 009, whose stale rows are harmless because nothing reports
-- them; here a stale row would be reported "removed" on every run).

CREATE TABLE IF NOT EXISTS mcp_tool_pins (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  server_key   TEXT NOT NULL,
  tool_name    TEXT NOT NULL,
  hash         TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (project_path, server_key, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_pins_server ON mcp_tool_pins(project_path, server_key);

CREATE TABLE IF NOT EXISTS mcp_server_pins (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  server_key   TEXT NOT NULL,
  tool_count   INTEGER NOT NULL,
  audited_at   TEXT NOT NULL,
  UNIQUE (project_path, server_key)
);
