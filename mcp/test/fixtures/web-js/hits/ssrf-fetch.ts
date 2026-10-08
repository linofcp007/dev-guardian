/**
 * web-js-ssrf into fetch -- every `// BUG` line fires the rule exactly once.
 *
 * A value of the incoming request becomes the URL of an outgoing one, in the
 * same function (US-3.AC-1): the server fetches whatever the caller names,
 * cloud metadata endpoints and internal services included.
 */

import type { Request, Response } from 'express';

export async function preview(req: Request, res: Response) {
  const upstream = await fetch(String(req.query.url)); // BUG: web-js-ssrf -- query, fetch
  res.status(upstream.status).send(await upstream.text());
}

export async function testWebhook(req: Request, res: Response) {
  const hook = req.body.webhookUrl;
  const reply = await fetch(hook, { method: 'POST', body: '{}' }); // BUG: web-js-ssrf -- body through a variable, fetch
  res.json({ status: reply.status });
}
