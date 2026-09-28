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
import { nowIso } from './repoUtil.js';
export class McpToolPinsRepo {
    db;
    getPinsStmt;
    hasServerStmt;
    listKeysStmt;
    deletePinsStmt;
    insertPinStmt;
    upsertServerStmt;
    constructor(db) {
        this.db = db;
        this.getPinsStmt = db.prepare(`
      SELECT tool_name AS key, hash FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
        this.hasServerStmt = db.prepare(`
      SELECT COUNT(*) AS n FROM mcp_server_pins WHERE project_path = ? AND server_key = ?
    `);
        this.listKeysStmt = db.prepare(`
      SELECT server_key, tool_name AS key FROM mcp_tool_pins WHERE project_path = ? ORDER BY server_key, tool_name
    `);
        this.deletePinsStmt = db.prepare(`
      DELETE FROM mcp_tool_pins WHERE project_path = ? AND server_key = ?
    `);
        this.insertPinStmt = db.prepare(`
      INSERT INTO mcp_tool_pins (project_path, server_key, tool_name, hash, updated_at) VALUES (?, ?, ?, ?, ?)
    `);
        this.upsertServerStmt = db.prepare(`
      INSERT INTO mcp_server_pins (project_path, server_key, tool_count, audited_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(project_path, server_key) DO UPDATE SET
        tool_count = excluded.tool_count, audited_at = excluded.audited_at
    `);
    }
    /** The hashes recorded for one server, keyed by item key. Empty when none. */
    getServerPins(projectPath, serverKey) {
        const out = new Map();
        for (const row of this.getPinsStmt.all(projectPath, serverKey))
            out.set(row.key, row.hash);
        return out;
    }
    /** Whether this server has been audited before — with or without items. */
    hasServer(projectPath, serverKey) {
        return (this.hasServerStmt.get(projectPath, serverKey)?.n ?? 0) > 0;
    }
    /** Every pinned item key of a project, with the server that serves it. */
    listPinKeys(projectPath) {
        return this.listKeysStmt.all(projectPath);
    }
    /**
     * Replace one server's pins with `pins`, in one transaction: an item not in
     * `pins` is dropped, and the server is recorded as audited even when
     * `pins` is empty. Duplicate keys keep the last one. `mcp_server_pins.
     * tool_count` counts every pinned item.
     */
    replaceServerPins(projectPath, serverKey, pins) {
        const unique = new Map();
        for (const pin of pins)
            unique.set(pin.key, pin.hash);
        const at = nowIso();
        const tx = this.db.transaction(() => {
            this.deletePinsStmt.run(projectPath, serverKey);
            for (const [key, hash] of unique)
                this.insertPinStmt.run(projectPath, serverKey, key, hash, at);
            this.upsertServerStmt.run(projectPath, serverKey, unique.size, at);
        });
        tx();
    }
}
//# sourceMappingURL=mcpToolPinsRepo.js.map