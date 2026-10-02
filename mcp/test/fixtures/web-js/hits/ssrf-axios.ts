/**
 * web-js-ssrf into axios -- every `// BUG` line fires the rule exactly once.
 *
 * The URL argument of `axios.get` / `axios.post` taken from the request
 * (US-3.AC-1). The request body sent as the PAYLOAD is not the finding: only
 * the URL decides where the server connects.
 */

import axios from 'axios';
import { Router } from 'express';

export const proxyRouter = Router();

proxyRouter.get('/proxy', async (req, res) => {
  const reply = await axios.get(String(req.query.target)); // BUG: web-js-ssrf -- query, axios.get
  res.send(reply.data);
});

proxyRouter.post('/callbacks', async (req, res) => {
  await axios.post(req.body.callbackUrl, { delivered: true }); // BUG: web-js-ssrf -- body, axios.post
  res.sendStatus(204);
});
