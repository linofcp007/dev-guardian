/**
 * Tool-definition pins for `audit_mcp_tools`.
 *
 * Keyed by (project_path, server_key, tool_name) — see
 * `migrations/012_mcp_tool_pins.sql` for why this carries no `scan_id`, and
 * why a server-level row exists beside the per-tool ones. Each audit reads a
 * server's previous pins to decide what changed, then replaces them with
 * what the server served this time.
 */

import type { DB, Statement } from './db.js';
import { nowIso } from './repoUtil.js';

export interface McpToolPin {
  tool_name: string;
  hash: string;
}

export interface PinnedToolName {
  server_key: string;
  tool_name: string;
}

interface PinRow {
  tool_name: string;
  hash: string;
}

export class McpToolPinsRepo {
  private readonly getPinsStmt: Statement<[string, string], PinRow>;
  private readonly hasServerStmt: Statement<[string, string], { n: number }>;
  private readonly listNamesStmt: Statement<[string], PinnedToolName>;
  private readonly deletePinsStmt: Statement<[string, string]>;
  private readonly insertPinStmt: Statement<[string, string, string, string, string]>;
  private readonly upsertServerStmt: Statement<[string, string, number, string]>;

  constructor(private readonly db: DB) {
    this.getPinsStmt = db.prepare<[string, string], PinRow>(`
      SELECT tool_name, hash FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
    this.hasServerStmt = db.prepare<[string, string], { n: number }>(`
      SELECT COUNT(*) AS n FROM mcp_server_pins WHERE project_path = ? AND server_key = ?
    `);
    this.listNamesStmt = db.prepare<[string], PinnedToolName>(`
      SELECT server_key, tool_name FROM mcp_tool_pins WHERE project_path = ? ORDER BY server_key, tool_name
    `);
    this.deletePinsStmt = db.prepare<[string, string]>(`
      DELETE FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
    this.insertPinStmt = db.prepare<[string, string, string, string, string]>(`
      INSERT INTO mcp_tool_pins (project_path, server_key, tool_name, hash, updated_at) VALUES (?, ?, ?, ?, ?)
    `);
    this.upsertServerStmt = db.prepare<[string, string, number, string]>(`
      INSERT INTO mcp_server_pins (project_path, server_key, tool_count, audited_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(project_path, server_key) DO UPDATE SET
        tool_count = excluded.tool_count, audited_at = excluded.audited_at
    `);
  }

  /** The tool hashes recorded for one server, keyed by tool name. Empty when none. */
  getServerPins(projectPath: string, serverKey: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const row of this.getPinsStmt.all(projectPath, serverKey)) out.set(row.tool_name, row.hash);
    return out;
  }

  /** Whether this server has been audited before — with or without tools. */
  hasServer(projectPath: string, serverKey: string): boolean {
    return (this.hasServerStmt.get(projectPath, serverKey)?.n ?? 0) > 0;
  }

  /** Every pinned tool of a project, with the server that serves it. */
  listToolNames(projectPath: string): PinnedToolName[] {
    return this.listNamesStmt.all(projectPath);
  }

  /**
   * Replace one server's pins with `pins`, in one transaction: a tool not in
   * `pins` is dropped, and the server is recorded as audited even when
   * `pins` is empty. Duplicate tool names keep the last one.
   */
  replaceServerPins(projectPath: string, serverKey: string, pins: readonly McpToolPin[]): void {
    const unique = new Map<string, string>();
    for (const pin of pins) unique.set(pin.tool_name, pin.hash);
    const at = nowIso();
    const tx = this.db.transaction(() => {
      this.deletePinsStmt.run(projectPath, serverKey);
      for (const [toolName, hash] of unique) this.insertPinStmt.run(projectPath, serverKey, toolName, hash, at);
      this.upsertServerStmt.run(projectPath, serverKey, unique.size, at);
    });
    tx();
  }
}
