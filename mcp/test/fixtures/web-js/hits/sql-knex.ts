/**
 * web-js-sql-template on knex.raw -- every `// BUG` line fires the rule exactly once.
 *
 * `knex.raw` is knex's escape hatch: the first argument is SQL text, and a
 * value spliced into it bypasses the bindings (US-1.AC-1).
 */

import createKnex from 'knex';

const knex = createKnex({ client: 'pg' });

export async function searchProducts(term: string) {
  return knex.raw(`SELECT * FROM products WHERE name ILIKE '%${term}%'`); // BUG: web-js-sql-template -- knex.raw, template literal
}

export async function productsIn(category: string) {
  return knex.raw('SELECT * FROM products WHERE category = ' + category); // BUG: web-js-sql-template -- knex.raw, concatenation
}
