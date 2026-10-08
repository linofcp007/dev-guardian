/**
 * web-js-ssrf into http.request / https.request -- every `// BUG` line fires the rule exactly once.
 *
 * The host of the outgoing request taken from a route parameter, and the
 * whole URL taken from the body (US-3.AC-1). What the request body WRITES to
 * the connection (`out.end(...)`) is not the finding.
 */

import http from 'node:http';
import https from 'node:https';
import { Router } from 'express';

export const relayRouter = Router();

relayRouter.get('/ping/:host', (req, res) => {
  const out = http.request(`http://${req.params.host}/health`, (reply) => res.sendStatus(reply.statusCode ?? 502)); // BUG: web-js-ssrf -- params as the host, http.request
  out.end();
});

relayRouter.post('/relay', (req, res) => {
  const out = https.request(req.body.endpoint, { method: 'POST' }, (reply) => reply.pipe(res)); // BUG: web-js-ssrf -- body, https.request
  out.end(JSON.stringify(req.body.payload));
});
