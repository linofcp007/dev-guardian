/**
 * web-js-sql-template on mysql2 -- every `// BUG` line fires the rule exactly once.
 *
 * `query` and `execute` with the statement built from a value that is not a
 * literal. `execute` is a prepared statement only when the values go in the
 * second argument; with the value spliced into the text it is as injectable
 * as `query` (US-1.AC-1; the test plan's T-01 names `execute`).
 */

import type { Connection } from 'mysql2/promise';

export async function ordersWithStatus(conn: Connection, status: string) {
  const [rows] = await conn.query(`SELECT * FROM orders WHERE status = '${status}'`); // BUG: web-js-sql-template -- query, template literal
  return rows;
}

export async function orderById(conn: Connection, id: string) {
  const [rows] = await conn.execute('SELECT * FROM orders WHERE id = ' + id); // BUG: web-js-sql-template -- execute, concatenation
  return rows;
}
