/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-1).
 *
 * The parameterised form of every hit: the statement is a literal and the
 * values are bound. A rule that fired here would accuse the fix it
 * prescribes. The `knex.raw` binding is itself a template with an
 * interpolation -- in the SECOND argument, where a value belongs.
 */

import createKnex from 'knex';
import type { Connection } from 'mysql2/promise';
import type { Client } from 'pg';
import { Sequelize } from 'sequelize';
import { db } from './db.js';

const knex = createKnex({ client: 'pg' });
const sequelize = new Sequelize('postgres://localhost/app');

export function userByName(name: string) {
  return db.prepare('SELECT * FROM users WHERE name = ?').get(name);
}

export async function byEmail(client: Client, email: string) {
  return client.query('SELECT * FROM users WHERE email = $1', [email]);
}

export async function orderById(conn: Connection, id: string) {
  const [rows] = await conn.execute('SELECT * FROM orders WHERE id = ?', [id]);
  return rows;
}

export async function searchProducts(term: string) {
  return knex.raw('SELECT * FROM products WHERE name ILIKE ?', [`%${term}%`]);
}

export async function invoicesOf(customer: string) {
  return sequelize.query('SELECT * FROM invoices WHERE customer = :customer', { replacements: { customer } });
}
