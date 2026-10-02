/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2).
 *
 * The interpolated value is a ternary between two literals: the SQL receives
 * `ASC` or `DESC` and nothing else. Inline, and through a variable -- the
 * second is the spike's decoy D01 (`src/repositories/shifts.ts:56`).
 */

import { Pool } from 'pg';
import { db } from './db.js';

const pool = new Pool();

export function listByStart(dir: string) {
  return db.prepare(`SELECT * FROM shifts ORDER BY starts_at ${dir === 'desc' ? 'DESC' : 'ASC'}`).all();
}

export async function listByWard(dir: string) {
  const direction = dir === 'desc' ? 'DESC' : 'ASC';
  return pool.query(`SELECT * FROM shifts ORDER BY ward ${direction}`);
}
