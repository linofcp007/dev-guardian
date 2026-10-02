/**
 * web-js-ssrf -- nothing here may fire (US-3.AC-1: the URL of the request).
 *
 * The outgoing URL is a constant. In the first handler the incoming request
 * IS sent on -- as the body, which does not decide where the server
 * connects.
 */

import axios from 'axios';
import { Router } from 'express';

const STATUS_URL = 'https://status.example.com/api/v1/summary';

export const outbound = Router();

outbound.post('/notify', async (req, res) => {
  await fetch('https://hooks.example.com/notify', { method: 'POST', body: JSON.stringify(req.body) });
  res.sendStatus(202);
});

outbound.get('/status', async (_req, res) => {
  const reply = await axios.get(STATUS_URL);
  res.json(reply.data);
});
