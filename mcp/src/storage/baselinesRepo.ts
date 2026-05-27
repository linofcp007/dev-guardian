/**
 * Baselines repository.
 *
 * Only one baseline is "active" at any time — the most recently inserted row.
 * Older rows are kept for audit/history; the resource layer reads the latest
 * via `getActive()`.
 */

import type { Database as DB, Statement } from 'better-sqlite3';
import type { Baseline } from '../types.js';
import { nowIso } from './repoUtil.js';

interface BaselineRow {
  id: number;
  scan_id: string;
  set_at: string;
  note: string | null;
}

export interface SetBaselineInput {
  scan_id: string;
  note?: string;
}

export class BaselinesRepo {
  private readonly insertStmt: Statement<[string, string, string | null]>;
  private readonly getActiveStmt: Statement<[], BaselineRow>;
  private readonly listAllStmt: Statement<[], BaselineRow>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO baselines (scan_id, set_at, note) VALUES (?, ?, ?)
    `);
    this.getActiveStmt = db.prepare<[], BaselineRow>(`
      SELECT * FROM baselines ORDER BY id DESC LIMIT 1
    `);
    this.listAllStmt = db.prepare<[], BaselineRow>(`
      SELECT * FROM baselines ORDER BY id DESC
    `);
  }

  set(input: SetBaselineInput): Baseline {
    const setAt = nowIso();
    const info = this.insertStmt.run(input.scan_id, setAt, input.note ?? null);
    const b: Baseline = {
      id: Number(info.lastInsertRowid),
      scan_id: input.scan_id,
      set_at: setAt,
    };
    if (input.note !== undefined) b.note = input.note;
    return b;
  }

  getActive(): Baseline | null {
    const row = this.getActiveStmt.get();
    return row ? rowToBaseline(row) : null;
  }

  listAll(): Baseline[] {
    return this.listAllStmt.all().map(rowToBaseline);
  }
}

function rowToBaseline(row: BaselineRow): Baseline {
  const b: Baseline = { id: row.id, scan_id: row.scan_id, set_at: row.set_at };
  if (row.note !== null) b.note = row.note;
  return b;
}
