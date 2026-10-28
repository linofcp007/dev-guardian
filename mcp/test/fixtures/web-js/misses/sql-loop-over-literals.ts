/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-2).
 *
 * The interpolated value is the variable of a `for (... of ...)` over a closed
 * set: an array of string literals written in the loop, or a `const` of this
 * file bound to one -- exported and `as const`, or plain and only read (an
 * `includes` is not a push) -- used in a function and in a class method, with
 * the SQL inline and in a variable. Whatever the loop runs, the SQL receives
 * one of those literals.
 * The shapes of this repository's `maintenance.ts#takePruneBatch` and
 * `dbProvenance.ts#summarizeDatabase`.
 */

import { db } from './db.js';

export const KEYED_TABLES = [
  'scans',
  'suppressions',
  'baselines',
] as const;

const SWEPT = ['findings', "scan_cves"];

// Read, never mutated: a method call on the array is not a push.
export function isSwept(table: string) {
  return SWEPT.includes(table);
}

export function countPerScan(ids: string[]) {
  const list = ids.map(() => '?').join(', ');
  for (const table of ['findings', 'scan_cves']) {
    db.prepare(`SELECT scan_id, COUNT(*) AS n FROM ${table} WHERE scan_id IN (${list}) GROUP BY scan_id`).all(...ids);
  }
}

export function pathsPerTable() {
  for (const table of KEYED_TABLES) {
    db.prepare(`SELECT project_path, COUNT(*) AS n FROM "${table}" GROUP BY project_path`).all();
  }
}

export class Sweeper {
  sweep(before: string) {
    for (const table of SWEPT) {
      const sql = `DELETE FROM ${table} WHERE created_at < ?`;
      db.prepare(sql).run(before);
    }
  }
}
