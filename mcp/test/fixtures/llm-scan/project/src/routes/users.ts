import { Router } from 'express';
import { query } from '../db.js';

export const usersRouter = Router();

usersRouter.get('/', async (_req, res) => {
  res.json(await query('SELECT id, name FROM users ORDER BY id', []));
});

usersRouter.get('/:id', async (req, res) => {
  // The id is concatenated into the statement text.
  const rows = await query(`SELECT id, name, email FROM users WHERE id = ${req.params.id}`, []);
  res.json(rows[0] ?? null);
});

usersRouter.post('/', async (req, res) => {
  const { name, email, role } = req.body;
  await query('INSERT INTO users (name, email, role) VALUES (?, ?, ?)', [name, email, role]);
  res.status(201).end();
});

usersRouter.put('/:id', async (req, res) => {
  await query('UPDATE users SET name = ? WHERE id = ?', [req.body.name, req.params.id]);
  res.status(204).end();
});

usersRouter.delete('/:id', async (req, res) => {
  await query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).end();
});

usersRouter.get('/:id/export', async (req, res) => {
  const rows = await query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(rows);
});
