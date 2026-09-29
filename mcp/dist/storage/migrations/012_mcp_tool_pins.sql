-- 012_mcp_tool_pins.sql
-- What `audit_mcp_tools` compares each run against: the tool definitions an
-- MCP server served the last time it was audited, one hash per tool.
--
-- `server_key` is JSON of `[<config source label>, <server name>]`
-- (`mcpaudit/select.ts#serverPinKey`) — injective, unlike
-- "<source>::<name>", so one server declared in two files is two servers
-- here: they can launch different commands. `tool_name` holds the ITEM key
-- (`mcpaudit/pins.ts#pinKey`): a tool's bare name, or `<kind>:<id>` for a
-- prompt, resource, resource template or the server's instructions.
-- `hash` is `v<scheme>:<sha256>` of the item's canonical JSON (keys sorted)
-- — for a tool `{name, title, description, inputSchema, outputSchema,
-- annotations}`; several definitions served under one key are pinned
-- together (their hashes, sorted). A changed hash is a definition that
-- changed under the same name, the "rug pull" that
-- `mcp-tool-definition-changed` reports. A `-` before the hash is a
-- TOMBSTONE: an item no longer served, kept so that one coming back changed
-- is reported as a change, not as new.
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
-- A server whose listing completed has its set replaced whole — an item it
-- no longer lists becomes a tombstone once reported removed (a resource,
-- which is data, is dropped instead); a listing a budget cut short only adds
-- to the stored set and never tombstones what it did not see.

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
