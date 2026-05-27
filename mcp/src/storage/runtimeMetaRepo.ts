/**
 * Runtime-meta repository — small key-value store for things the server
 * decided once and wants to reuse on the next boot.
 *
 * Current users: shell choice (probed once on Windows, then cached).
 */

import type { Database as DB, Statement } from 'better-sqlite3';
import { nowIso } from './repoUtil.js';

interface RuntimeMetaRow {
  key: string;
  value: string;
  updated_at: string;
}

export class RuntimeMetaRepo {
  private readonly upsertStmt: Statement<[string, string, string]>;
  private readonly getStmt: Statement<[string], RuntimeMetaRow>;
  private readonly deleteStmt: Statement<[string]>;

  constructor(db: DB) {
    this.upsertStmt = db.prepare(`
      INSERT INTO runtime_meta (key, value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `);
    this.getStmt = db.prepare<[string], RuntimeMetaRow>(
      `SELECT * FROM runtime_meta WHERE key = ?`,
    );
    this.deleteStmt = db.prepare(`DELETE FROM runtime_meta WHERE key = ?`);
  }

  set(key: string, value: string): void {
    this.upsertStmt.run(key, value, nowIso());
  }

  setJson(key: string, value: unknown): void {
    this.set(key, JSON.stringify(value));
  }

  get(key: string): string | null {
    const row = this.getStmt.get(key);
    return row?.value ?? null;
  }

  getJson<T>(key: string): T | null {
    const raw = this.get(key);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  delete(key: string): void {
    this.deleteStmt.run(key);
  }
}
