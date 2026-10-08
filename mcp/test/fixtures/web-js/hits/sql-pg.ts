/**
 * web-js-sql-template on pg (node-postgres) -- every `// BUG` line fires the rule exactly once.
 *
 * `client.query` and `pool.query` with the statement built from a value that
 * is not a literal (US-1.AC-1).
 */

import { Pool } from 'pg';
import type { Client } from 'pg';

const pool = new Pool();

export async function byEmail(client: Client, email: string) {
  return client.query(`SELECT * FROM users WHERE email = '${email}'`); // BUG: web-js-sql-template -- client.query, template literal
}

export async function byId(id: string) {
  return pool.query('SELECT * FROM users WHERE id = ' + id); // BUG: web-js-sql-template -- pool.query, concatenation
}
