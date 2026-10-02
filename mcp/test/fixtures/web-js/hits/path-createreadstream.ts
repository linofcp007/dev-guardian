/**
 * web-js-path-traversal into fs.createReadStream -- every `// BUG` line fires the rule exactly once.
 *
 * A route parameter joined to the log directory and streamed back (US-2.AC-1).
 */

import fs from 'node:fs';
import path from 'node:path';
import { Router } from 'express';

const LOG_DIR = '/var/log/app';

export const logsRouter = Router();

logsRouter.get('/logs/:file', (req, res) => {
  fs.createReadStream(path.join(LOG_DIR, req.params.file)).pipe(res); // BUG: web-js-path-traversal -- params, join, fs.createReadStream
});

logsRouter.post('/logs/tail', (req, res) => {
  const name = req.body.file;
  fs.createReadStream(path.resolve(LOG_DIR, name), { start: 0 }).pipe(res); // BUG: web-js-path-traversal -- body through a variable, resolve, fs.createReadStream
});
