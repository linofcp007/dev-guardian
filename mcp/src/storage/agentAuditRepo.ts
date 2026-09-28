/**
 * Config-entry hash repository for `audit_agent_config`.
 *
 * Keyed by (project_path, entry_key) — see `migrations/009_agent_config_hashes.sql`
 * for why this carries no `scan_id`. One row per MCP server entry the audit
 * has ever seen for a project; each run reads the previous hashes to decide
 * what changed, then upserts its own.
 */

import type { DB, Statement } from './db.js';
import { nowIso } from './repoUtil.js';

export interface AgentConfigHashEntry {
  entry_key: string;
  hash: string;
}

interface HashRow {
  entry_key: string;
  hash: string;
}

export class AgentAuditRepo {
  private readonly getHashesStmt: Statement<[string], HashRow>;
  private readonly upsertStmt: Statement<[string, string, string, string]>;

  constructor(private readonly db: DB) {
    this.getHashesStmt = db.prepare<[string], HashRow>(`
      SELECT entry_key, hash FROM agent_config_hashes WHERE project_path = ?
    `);
    this.upsertStmt = db.prepare<[string, string, string, string]>(`
      INSERT INTO agent_config_hashes (project_path, entry_key, hash, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(project_path, entry_key) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at
    `);
  }

  /** Every hash recorded for `projectPath`, keyed by entry_key. Empty map when none. */
  getHashes(projectPath: string): Map<string, string> {
    const rows = this.getHashesStmt.all(projectPath);
    const out = new Map<string, string>();
    for (const row of rows) out.set(row.entry_key, row.hash);
    return out;
  }

  /** Insert-or-update `entries` for `projectPath` in one transaction. No-op on an empty array. */
  upsertHashes(projectPath: string, entries: readonly AgentConfigHashEntry[]): void {
    if (entries.length === 0) return;
    const updatedAt = nowIso();
    const tx = this.db.transaction((rows: readonly AgentConfigHashEntry[]) => {
      for (const entry of rows) {
        this.upsertStmt.run(projectPath, entry.entry_key, entry.hash, updatedAt);
      }
    });
    tx(entries);
  }
}
