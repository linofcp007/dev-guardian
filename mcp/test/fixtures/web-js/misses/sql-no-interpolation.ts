/**
 * web-js-sql-template -- nothing here may fire (EC-1, US-1.AC-1).
 *
 * A template literal with no interpolation is a string literal written with
 * backticks -- on one line, and across lines the way the spike app writes its
 * statements. A concatenation of two literals has no value that is not a
 * literal in it.
 */

import type { Client } from 'pg';
import { db } from './db.js';

export function ping() {
  return db.prepare(`SELECT 1`).get();
}

export function upcoming() {
  return db
    .prepare(
      `SELECT * FROM shifts WHERE ends_at >= ? AND status != 'cancelled'
       ORDER BY starts_at`,
    )
    .all(new Date().toISOString());
}

export async function now(client: Client) {
  return client.query(`SELECT now()`);
}

export function firstShift() {
  return db.prepare('SELECT * FROM shifts ' + 'WHERE id = ?').get(1);
}
