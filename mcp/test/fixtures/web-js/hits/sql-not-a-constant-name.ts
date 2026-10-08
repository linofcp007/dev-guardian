/**
 * web-js-sql-template -- every `// BUG` line fires the rule exactly once.
 *
 * A name never makes a value a constant: only what it is bound to does (D-4).
 * A value from the request under a PascalCase name, or under one capital
 * letter, still fires -- as one under an UPPER_CASE name does
 * (`sql-exclusion-escapes.ts`).
 */

import Database from 'better-sqlite3';

const db = new Database('app.db');

export function byOrder(req: { query: { order: string } }) {
  const Order = req.query.order;
  return db.prepare(`SELECT * FROM shifts ORDER BY ${Order}`).all(); // BUG: web-js-sql-template -- PascalCase name
}

export function byTitle(title: string) {
  const T = title;
  return db.prepare(`SELECT * FROM shifts WHERE title = '${T}'`).all(); // BUG: web-js-sql-template -- one capital letter
}
