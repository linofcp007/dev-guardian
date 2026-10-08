/**
 * web-js-path-traversal into res.sendFile -- every `// BUG` line fires the rule exactly once.
 *
 * `res.sendFile` refuses `..` only when it is given a `root` option; with an
 * absolute path built by `path.join` / `path.resolve` it sends whatever the
 * path names (US-2.AC-1).
 */

import path from 'node:path';
import express from 'express';

const PUBLIC_DIR = path.join(__dirname, 'public');

const app = express();

app.get('/pages', (req, res) => {
  res.sendFile(path.resolve(PUBLIC_DIR, String(req.query.page))); // BUG: web-js-path-traversal -- query, resolve, res.sendFile
});

app.get('/assets/:name', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, req.params.name)); // BUG: web-js-path-traversal -- params, join, res.sendFile
});

export default app;
