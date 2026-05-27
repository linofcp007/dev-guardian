/**
 * Stack-snapshots repository.
 *
 * Each invocation of the `detect_stack` tool persists one row here. The
 * resource `guardian://stack` returns the latest snapshot; the diff over
 * time is exposed via `listRecent()` should a future tool want to surface
 * "your stack changed on date X".
 */

import type { Database as DB, Statement } from 'better-sqlite3';
import type { StackSnapshot } from '../types.js';
import { nowIso, parseJsonObject } from './repoUtil.js';

interface StackRow {
  id: number;
  project_path: string;
  captured_at: string;
  json: string;
}

export interface InsertStackSnapshotInput {
  project_path: string;
  snapshot: StackSnapshot;
}

export interface PersistedStackSnapshot {
  id: number;
  project_path: string;
  captured_at: string;
  snapshot: StackSnapshot;
}

export class StackRepo {
  private readonly insertStmt: Statement<[string, string, string]>;
  private readonly getLatestStmt: Statement<[], StackRow>;
  private readonly listRecentStmt: Statement<[number], StackRow>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO stack_snapshots (project_path, captured_at, json)
      VALUES (?, ?, ?)
    `);
    this.getLatestStmt = db.prepare<[], StackRow>(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT 1
    `);
    this.listRecentStmt = db.prepare<[number], StackRow>(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT ?
    `);
  }

  insert(input: InsertStackSnapshotInput): PersistedStackSnapshot {
    const capturedAt = nowIso();
    const json = JSON.stringify(input.snapshot);
    const info = this.insertStmt.run(input.project_path, capturedAt, json);
    return {
      id: Number(info.lastInsertRowid),
      project_path: input.project_path,
      captured_at: capturedAt,
      snapshot: input.snapshot,
    };
  }

  getLatest(): PersistedStackSnapshot | null {
    const row = this.getLatestStmt.get();
    return row ? rowToSnapshot(row) : null;
  }

  listRecent(limit = 10): PersistedStackSnapshot[] {
    return this.listRecentStmt.all(limit).map(rowToSnapshot);
  }
}

function rowToSnapshot(row: StackRow): PersistedStackSnapshot {
  return {
    id: row.id,
    project_path: row.project_path,
    captured_at: row.captured_at,
    snapshot: parseJsonObject<Record<string, unknown>>(row.json, {}) as unknown as StackSnapshot,
  };
}
