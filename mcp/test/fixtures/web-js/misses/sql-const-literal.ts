/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2).
 *
 * A `const` bound to a literal (module level, used inside a function; and
 * local), a generated placeholder list with a literal separator through a
 * variable and through `.map`, and a lookup in a constant-named object by
 * property. The value can only be a literal of the code.
 */

import { db } from './db.js';

const TABLE = 'shifts';
const COLUMNS = { id: 'id', title: 'title' };

export function all() {
  return db.prepare(`SELECT * FROM ${TABLE}`).all();
}

export function localConst() {
  const order = 'starts_at';
  return db.prepare(`SELECT * FROM shifts ORDER BY ${order}`).all();
}

export function byProperty() {
  return db.prepare(`SELECT ${COLUMNS.title} FROM shifts`).all();
}

export function placeholders(n: number, ids: number[]) {
  const marks = Array(n).fill('?').join(',');
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${marks})`).all(...ids);
}

export function mapped(ids: number[]) {
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${ids.map(() => '?').join(', ')})`).all(...ids);
}
