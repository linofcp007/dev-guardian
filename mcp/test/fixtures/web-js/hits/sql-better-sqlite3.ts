/**
 * web-js-sql-template on better-sqlite3 -- every `// BUG` line fires the rule exactly once.
 *
 * The statement handed to the driver is a template literal with an
 * interpolation, or a concatenation with a value that is not a literal
 * (US-1.AC-1). One interpolated value per marked line.
 */

import Database from 'better-sqlite3';

const db = new Database('app.db');

export function userByName(name: string) {
  return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get(); // BUG: web-js-sql-template -- prepare, template literal
}

export function userById(id: string) {
  return db.prepare('SELECT * FROM users WHERE id = ' + id).get(); // BUG: web-js-sql-template -- prepare, concatenation
}

export function purge(table: string) {
  db.exec(`DELETE FROM ${table}`); // BUG: web-js-sql-template -- exec, template literal
}
