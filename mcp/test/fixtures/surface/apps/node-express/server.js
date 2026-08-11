import express from 'express';

import usersRouter from './routes/users.js';

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env['SESSION_SECRET'];

app.use(express.json());
app.use('/api/users', usersRouter);

app.get('/health', (req, res) => res.json({ ok: true }));
app.post('/login', (req, res) => res.status(204).end());

/**
 * Not routes. `cache.get` is a two-argument method call on an object, which is
 * exactly the shape `$APP.$METHOD($PATH, ...)` matches — the $PATH literal
 * guard is what keeps it out, because its first argument is not a "/" path.
 */
export async function warmCache(cache) {
  await cache.get('users:all', { ttl: 60 });
  return fetch('https://api.example.com/v1/ping', { method: 'GET' });
}

app.listen(PORT, () => console.log(`listening on ${PORT} (secret set: ${Boolean(SESSION_SECRET)})`));

export default app;
