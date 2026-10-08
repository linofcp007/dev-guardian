/**
 * web-js-sql-template, the shapes that LOOK like an excluded one but are not -- every `// BUG` line fires the rule exactly once.
 *
 * Each exclusion of the rule (US-1.AC-2) is written so that the value can only
 * be one of several literals. These are the near-misses that fail that test:
 * a constant NAME that holds request data, a `let` reassigned from the
 * request, and a placeholder list whose separator is not a literal.
 */

import { db } from './db.js';

export function sortedBy(req: { query: { sort: string } }) {
  const SORT = req.query.sort;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${SORT}`).all(); // BUG: web-js-sql-template -- UPPER_CASE name, request value
}

export function reassigned(req: { query: { col: string } }) {
  let col = 'starts_at';
  col = req.query.col;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${col}`).all(); // BUG: web-js-sql-template -- let reassigned from the request
}

export function reassignedLater(req: { query: { col: string } }) {
  let col = 'starts_at';
  console.log('sorting');
  col = req.query.col;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${col}`).all(); // BUG: web-js-sql-template -- let reassigned after another statement
}

export function separatorFromRequest(req: { query: { sep: string } }) {
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${Array(2).fill('?').join(req.query.sep)})`).all(); // BUG: web-js-sql-template -- generated placeholders, separator from the request
}

export function separatorInVariable(req: { query: { sep: string } }) {
  const marks = Array(2).fill('?').join(req.query.sep);
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${marks})`).all(); // BUG: web-js-sql-template -- the same, through a variable
}
