/**
 * web-js-sql-template, the shapes that LOOK like an excluded one but are not -- every `// BUG` line fires the rule exactly once.
 *
 * Each exclusion of the rule (US-1.AC-2) is written so that the value can only
 * be one of several literals. These are the near-misses that fail that test:
 * a constant NAME that holds request data, a `let` reassigned from the
 * request, a placeholder list whose separator is not a literal, an object
 * named like `Math` that is not the global one, and an `Array.from` whose
 * callback returns the caller's values rather than `'?'`.
 */

import { db } from './db.js';

const MathLike = { max: (value: string) => value };

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

export function mathLookAlike(req: { query: { col: string } }) {
  return db.prepare(`SELECT * FROM shifts ORDER BY ${MathLike.max(req.query.col)}`).all(); // BUG: web-js-sql-template -- not the global Math, returns the request text
}

export function arrayFromValues(ids: string[]) {
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${Array.from({ length: ids.length }, (_, i) => ids[i]).join(',')})`).all(); // BUG: web-js-sql-template -- Array.from whose callback returns the values
}
