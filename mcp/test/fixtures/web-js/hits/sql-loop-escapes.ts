/**
 * web-js-sql-template, loops that LOOK like a loop over a closed set but are not -- every `// BUG` line fires the rule exactly once.
 *
 * The exclusion of a loop variable (US-1.AC-2) holds only when the array is
 * written as string literals, in the loop or in a `const` of this file that
 * nothing pushes into or assigns by index, and the loop body never assigns the
 * variable (Semgrep reads `for (let` and `for (const` as one shape). A name
 * never makes an array closed (D-4), and the value interpolated beside the
 * loop variable is still judged on its own.
 */

import { db } from './db.js';

const REQUESTED = process.argv.slice(2);
const EXTENDED = ['scans', 'findings'];
const PATCHED = ['scans', 'findings'];

export function extend(name: string) {
  EXTENDED.push(name);
}

export function patch(name: string) {
  PATCHED[0] = name;
}

export function fromCaller(TABLES: string[]) {
  for (const table of TABLES) {
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- loop over the caller's array, UPPER_CASE name
  }
}

export function withARequestValue(req: { query: { extra: string } }) {
  for (const table of ['scans', req.query.extra]) {
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- an array literal holding a request value
  }
}

export function fromAConstOfInput() {
  for (const table of REQUESTED) {
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- a const bound to the process's input
  }
}

export function pushedInto() {
  for (const table of EXTENDED) {
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- a const array another function pushes into
  }
}

export function assignedByIndex() {
  for (const table of PATCHED) {
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- a const array another function assigns by index
  }
}

export function reassigned(req: { query: { table?: string } }) {
  for (let table of ['scans', 'findings']) {
    if (req.query.table) {
      table = req.query.table;
    }
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- the loop variable reassigned from the request
  }
}

export function appended(req: { query: { suffix: string } }) {
  for (let table of ['scans', 'findings']) {
    table += req.query.suffix;
    db.prepare(`DELETE FROM ${table}`).run(); // BUG: web-js-sql-template -- the loop variable appended to from the request
  }
}

export function besideTheLoopVariable(owner: string) {
  for (const table of ['scans', 'findings']) {
    db.prepare(`DELETE FROM ${table} WHERE owner = '${owner}'`).run(); // BUG: web-js-sql-template -- the owner, not the table
  }
}
