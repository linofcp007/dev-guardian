/**
 * web-js-ssrf into got -- every `// BUG` line fires the rule exactly once.
 *
 * A feed reader that fetches the feed the caller names (US-3.AC-1).
 */

import got from 'got';
import { Router } from 'express';

export const feedRouter = Router();

feedRouter.get('/feeds/preview', async (req, res) => {
  const body = await got(String(req.query.feed)).text(); // BUG: web-js-ssrf -- query, got
  res.type('application/xml').send(body);
});
