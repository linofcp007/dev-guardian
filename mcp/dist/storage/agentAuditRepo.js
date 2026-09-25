/**
 * Config-entry hash repository for `audit_agent_config`.
 *
 * Keyed by (project_path, entry_key) — see `migrations/009_agent_config_hashes.sql`
 * for why this carries no `scan_id`. One row per MCP server entry the audit
 * has ever seen for a project; each run reads the previous hashes to decide
 * what changed, then upserts its own.
 */
import { nowIso } from './repoUtil.js';
export class AgentAuditRepo {
    db;
    getHashesStmt;
    upsertStmt;
    constructor(db) {
        this.db = db;
        this.getHashesStmt = db.prepare(`
      SELECT entry_key, hash FROM agent_config_hashes WHERE project_path = ?
    `);
        this.upsertStmt = db.prepare(`
      INSERT INTO agent_config_hashes (project_path, entry_key, hash, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(project_path, entry_key) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at
    `);
    }
    /** Every hash recorded for `projectPath`, keyed by entry_key. Empty map when none. */
    getHashes(projectPath) {
        const rows = this.getHashesStmt.all(projectPath);
        const out = new Map();
        for (const row of rows)
            out.set(row.entry_key, row.hash);
        return out;
    }
    /** Insert-or-update `entries` for `projectPath` in one transaction. No-op on an empty array. */
    upsertHashes(projectPath, entries) {
        if (entries.length === 0)
            return;
        const updatedAt = nowIso();
        const tx = this.db.transaction((rows) => {
            for (const entry of rows) {
                this.upsertStmt.run(projectPath, entry.entry_key, entry.hash, updatedAt);
            }
        });
        tx(entries);
    }
}
//# sourceMappingURL=agentAuditRepo.js.map