/**
 * web-js-ssrf into the call forms the other hits/ files leave out -- every `// BUG` line fires the rule exactly once.
 *
 * `axios(url)` (the function itself, not `axios.get`), `got.get(url)` (a
 * method of `got`), and `http.get` / `https.get` (the shorthand of
 * `request`): each is its own alternative of the sink (US-3.AC-1), and each
 * needed a fixture of its own so the ablation can tell it from its siblings.
 */

import axios from 'axios';
import got from 'got';
import http from 'node:http';
import https from 'node:https';
import { Router } from 'express';

export const callFormsRouter = Router();

callFormsRouter.get('/axios', async (req, res) => {
  const reply = await axios(String(req.query.target)); // BUG: web-js-ssrf -- query, axios(...)
  res.send(reply.data);
});

callFormsRouter.get('/got', async (req, res) => {
  const reply = await got.get(String(req.query.feed)); // BUG: web-js-ssrf -- query, got.get
  res.send(reply.body);
});

callFormsRouter.get('/http', (req, res) => {
  http.get(String(req.query.url), (reply) => reply.pipe(res)); // BUG: web-js-ssrf -- query, http.get
});

callFormsRouter.get('/https', (req, res) => {
  https.get(req.body.url, (reply) => reply.pipe(res)); // BUG: web-js-ssrf -- body, https.get
});
