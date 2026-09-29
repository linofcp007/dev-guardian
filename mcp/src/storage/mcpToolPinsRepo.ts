/**
 * Definition pins for `audit_mcp_tools`.
 *
 * Keyed by (project_path, server_key, key) — see
 * `migrations/012_mcp_tool_pins.sql` for why this carries no `scan_id`, and
 * why a server-level row exists beside the per-item ones. The item key is
 * `mcpaudit/pins.ts`'s `pinKey`: a tool's bare name, or `<kind>:<id>` for a
 * prompt, resource or resource template. It is stored in the column named
 * `tool_name`, which is what it held when only tools were pinned. Each audit
 * reads a server's previous pins to decide what changed, then replaces them
 * with what the server served this time.
 */

import type { DB, Statement } from './db.js';
import { nowIso } from './repoUtil.js';

export interface McpPin {
  /** `pinKey(kind, id)`: a tool's name, or `<kind>:<id>`. */
  key: string;
  /** `v<scheme>:<sha256 hex>`, or bare hex for scheme 1. */
  hash: string;
}

export interface PinnedKey {
  server_key: string;
  key: string;
}

interface PinRow {
  key: string;
  hash: string;
}

export class McpToolPinsRepo {
  private readonly getPinsStmt: Statement<[string, string], PinRow>;
  private readonly hasServerStmt: Statement<[string, string], { n: number }>;
  private readonly listKeysStmt: Statement<[string], PinnedKey>;
  private readonly deletePinsStmt: Statement<[string, string]>;
  private readonly insertPinStmt: Statement<[string, string, string, string, string]>;
  private readonly upsertServerStmt: Statement<[string, string, number, string]>;
  private readonly upsertPinStmt: Statement<[string, string, string, string, string]>;

  constructor(private readonly db: DB) {
    this.getPinsStmt = db.prepare<[string, string], PinRow>(`
      SELECT tool_name AS key, hash FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
    this.hasServerStmt = db.prepare<[string, string], { n: number }>(`
      SELECT COUNT(*) AS n FROM mcp_server_pins WHERE project_path = ? AND server_key = ?
    `);
    this.listKeysStmt = db.prepare<[string], PinnedKey>(`
      SELECT server_key, tool_name AS key FROM mcp_tool_pins
      WHERE project_path = ? AND hash NOT LIKE '-%'
      ORDER BY server_key, tool_name
    `);
    this.deletePinsStmt = db.prepare<[string, string]>(`
      DELETE FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
    this.insertPinStmt = db.prepare<[string, string, string, string, string]>(`
      INSERT INTO mcp_tool_pins (project_path, server_key, tool_name, hash, updated_at) VALUES (?, ?, ?, ?, ?)
    `);
    this.upsertPinStmt = db.prepare<[string, string, string, string, string]>(`
      INSERT INTO mcp_tool_pins (project_path, server_key, tool_name, hash, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(project_path, server_key, tool_name) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at
    `);
    this.upsertServerStmt = db.prepare<[string, string, number, string]>(`
      INSERT INTO mcp_server_pins (project_path, server_key, tool_count, audited_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(project_path, server_key) DO UPDATE SET
        tool_count = excluded.tool_count, audited_at = excluded.audited_at
    `);
  }

  /** The hashes recorded for one server, keyed by item key. Empty when none. */
  getServerPins(projectPath: string, serverKey: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const row of this.getPinsStmt.all(projectPath, serverKey)) out.set(row.key, row.hash);
    return out;
  }

  /** Whether this server has been audited before — with or without items. */
  hasServer(projectPath: string, serverKey: string): boolean {
    return (this.hasServerStmt.get(projectPath, serverKey)?.n ?? 0) > 0;
  }

  /** Every LIVE pinned item key of a project (tombstones left out), with the server that serves it. */
  listPinKeys(projectPath: string): PinnedKey[] {
    return this.listKeysStmt.all(projectPath);
  }

  /**
   * Add or update `pins` for one server without removing any other: for a
   * listing a budget cut short, where an item not seen may still be served.
   */
  upsertServerPins(projectPath: string, serverKey: string, pins: readonly McpPin[]): void {
    const at = nowIso();
    const tx = this.db.transaction(() => {
      for (const pin of pins) this.upsertPinStmt.run(projectPath, serverKey, pin.key, pin.hash, at);
      const stored = [...this.getServerPins(projectPath, serverKey).values()];
      this.upsertServerStmt.run(projectPath, serverKey, stored.filter((h) => !h.startsWith('-')).length, at);
    });
    tx();
  }

  /**
   * Replace one server's pins with `pins`, in one transaction: an item not in
   * `pins` is dropped, and the server is recorded as audited even when
   * `pins` is empty. Duplicate keys keep the last one. `mcp_server_pins.
   * tool_count` counts the live pins (a tombstone is `-` + hash).
   */
  replaceServerPins(projectPath: string, serverKey: string, pins: readonly McpPin[]): void {
    const unique = new Map<string, string>();
    for (const pin of pins) unique.set(pin.key, pin.hash);
    const at = nowIso();
    const tx = this.db.transaction(() => {
      this.deletePinsStmt.run(projectPath, serverKey);
      for (const [key, hash] of unique) this.insertPinStmt.run(projectPath, serverKey, key, hash, at);
      this.upsertServerStmt.run(projectPath, serverKey, [...unique.values()].filter((h) => !h.startsWith('-')).length, at);
    });
    tx();
  }
}
