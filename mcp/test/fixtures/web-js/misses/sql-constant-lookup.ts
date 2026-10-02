/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2).
 *
 * The interpolated value is a lookup in a constant object with fixed keys:
 * whatever the caller passes, the SQL can only receive one of the object's
 * own literal values. Inline, and through a variable with a fallback -- the
 * second is the spike's decoy D01 (`src/repositories/shifts.ts:55`).
 */

import { db } from './db.js';

const SORT_COLUMNS: Record<string, string> = {
  start: 'starts_at',
  ward: 'ward',
  title: 'title',
};

const DIRECTIONS = { asc: 'ASC', desc: 'DESC' } as const;

export function listSorted(sort: string) {
  return db.prepare(`SELECT * FROM shifts ORDER BY ${SORT_COLUMNS[sort]}`).all();
}

export function listSortedWithFallback(sort: string | undefined) {
  const orderBy = SORT_COLUMNS[sort ?? ''] ?? SORT_COLUMNS.start;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${orderBy}`).all();
}

export function listDirected(dir: 'asc' | 'desc') {
  return db.prepare(`SELECT * FROM shifts ORDER BY starts_at ${DIRECTIONS[dir]}`).all();
}
