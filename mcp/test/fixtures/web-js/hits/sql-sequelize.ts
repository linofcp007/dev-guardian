/**
 * web-js-sql-template on sequelize.query -- every `// BUG` line fires the rule exactly once.
 *
 * `sequelize.query` runs its first argument as SQL text; a value spliced into
 * it bypasses `replacements` and `bind` (US-1.AC-1).
 */

import { QueryTypes, Sequelize } from 'sequelize';

const sequelize = new Sequelize('postgres://localhost/app');

export async function invoicesOf(customer: string) {
  return sequelize.query(`SELECT * FROM invoices WHERE customer = '${customer}'`, { type: QueryTypes.SELECT }); // BUG: web-js-sql-template -- sequelize.query, template literal
}

export async function invoiceById(id: string) {
  return sequelize.query('SELECT * FROM invoices WHERE id = ' + id); // BUG: web-js-sql-template -- sequelize.query, concatenation
}
