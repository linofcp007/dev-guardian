/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2, D-2, D-4).
 *
 * Module constants interpolated into SQL text, the way a repository class
 * builds its queries: a template literal with no substitution, on one line
 * and on several (D-2: Semgrep hands the rule a template's text without its
 * closing backtick, and the exclusion used to demand one), a number and a
 * concatenation of literals (D-4). Used inside class methods and in a
 * function. A constant a function computes (`const X = build('a')`) still
 * fires: the rule cannot tell its value from a request value (pack header).
 */

import { db } from './db.js';

const COLUMNS = `id, title, starts_at,
  ends_at, owner_id`;
const OPEN_ONLY = `(status = 'open' OR status = 'leased')`;
const BUSY_TIMEOUT_MS = 5000;
const MATCHES = '(s.shift_id = f.id) ' + 'AND (s.owner_id = f.owner_id)';

export class ShiftsRepo {
  byId(id: number) {
    return db.prepare(`SELECT ${COLUMNS} FROM shifts WHERE id = ?`).get(id);
  }

  open() {
    return db.prepare(`SELECT ${COLUMNS} FROM shifts WHERE ${OPEN_ONLY}`).all();
  }

  busy() {
    return db.prepare(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`).run();
  }

  matched() {
    return db.prepare(`SELECT f.id FROM shifts f JOIN signups s ON ${MATCHES}`).all();
  }
}

export function localTemplateConstant() {
  const order = `starts_at`;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${order}`).all();
}
