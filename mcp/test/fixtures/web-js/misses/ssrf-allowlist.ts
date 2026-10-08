/**
 * web-js-ssrf -- nothing here may fire (US-3.AC-2).
 *
 * The URL from the request is used only after an EXACT comparison with a
 * list of permitted values: an early return on an array's `includes`, and a
 * block guarded by a Set's `has`.
 */

import axios from 'axios';
import { Router } from 'express';

const ALLOWED_FEEDS = ['https://status.example.com/feed.xml', 'https://news.example.com/rss'];
const ALLOWED_HOOKS = new Set(['https://hooks.example.com/a', 'https://hooks.example.com/b']);

export const allowlisted = Router();

allowlisted.get('/feed', async (req, res) => {
  const url = String(req.query.url);
  if (!ALLOWED_FEEDS.includes(url)) {
    res.status(400).end();
    return;
  }
  const reply = await fetch(url);
  res.send(await reply.text());
});

allowlisted.post('/hook', async (req, res) => {
  const target = String(req.body.target);
  if (ALLOWED_HOOKS.has(target)) {
    await axios.post(target, { ping: true });
  }
  res.sendStatus(204);
});
