/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2).
 *
 * The value is converted to a number before it reaches the SQL text
 * (`Number(x)`, `parseInt(x, 10)`, a `Math` function): the worst a caller can
 * send is `NaN`. Interpolated inline, through a variable, and concatenated;
 * the `Math` one is this repository's `db.ts#setBusyTimeout`.
 */

import createKnex from 'knex';
import type { Connection } from 'mysql2/promise';
import { db } from './db.js';

const knex = createKnex({ client: 'pg' });

export function page(limit: string, offset: string) {
  return db.prepare(`SELECT * FROM shifts LIMIT ${Number(limit)} OFFSET ${parseInt(offset, 10)}`).all();
}

export async function top(conn: Connection, n: string) {
  const count = Number(n);
  const [rows] = await conn.query(`SELECT * FROM orders ORDER BY total DESC LIMIT ${count}`);
  return rows;
}

export async function invoicesOfYear(year: string) {
  return knex.raw('SELECT * FROM invoices WHERE year = ' + parseInt(year, 10));
}

export function setBusyTimeout(ms: number) {
  db.exec(`PRAGMA busy_timeout = ${Math.max(0, Math.floor(ms))}`);
}

export function capped(n: string) {
  const limit = Math.min(100, Number(n));
  return db.prepare(`SELECT * FROM shifts LIMIT ${limit}`).all();
}
