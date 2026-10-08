/**
 * web-js-sql-template, an IN list joined from the caller's values -- every `// BUG` line fires the rule exactly once.
 *
 * The spike's decoy D01 interpolates `${where.join(' AND ')}` -- an array
 * holding only literal SQL fragments -- and must stay silent (US-1.AC-3).
 * This is the same call on values the caller passes in, which is SQL
 * injection (US-1.AC-1): an exclusion that excused every `.join(...)` to
 * keep D01 quiet would excuse this one too.
 */

import { db } from './db.js';

export function shiftsByIds(ids: string[]) {
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${ids.join(',')})`).all(); // BUG: web-js-sql-template -- join of caller-supplied values
}

// A WHERE list that the same function fills with an interpolated request value:
// the `.join(' AND ')` is then NOT a join of literals, and the clause that
// excuses a local array of literals must not excuse this one.
export function filtered(req: { query: { name: string } }) {
  const where = ['1=1'];
  where.push(`name = '${req.query.name}'`);
  return db.prepare(`SELECT * FROM shifts WHERE ${where.join(' AND ')}`).all(); // BUG: web-js-sql-template -- join of an array that took an interpolated push
}
