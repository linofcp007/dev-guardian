/**
 * web-js-path-traversal into fs.readFile / fs.readFileSync -- every `// BUG` line fires the rule exactly once.
 *
 * A value of `req.query` / `req.params` reaches `path.join` / `path.resolve`
 * in the same function, and the result is read with no containment check
 * (US-2.AC-1). `../../etc/passwd` walks out of the directory.
 *
 * The join sits INSIDE the read on every marked line, so the line is the
 * same whether the rule reports the path being built or the read it reaches.
 * The two-line S06 shape (join, then read) is the spike app's (T-06).
 */

import fs from 'node:fs';
import path from 'node:path';
import express from 'express';

const DOCS_DIR = path.join(__dirname, 'docs');

export const docsRouter = express.Router();

docsRouter.get('/docs', (req, res) => {
  fs.readFile(path.join(DOCS_DIR, String(req.query.name)), 'utf8', (err, text) => { // BUG: web-js-path-traversal -- query, join, fs.readFile
    if (err) {
      res.status(404).end();
      return;
    }
    res.type('text/plain').send(text);
  });
});

docsRouter.get('/docs/:name/raw', (req, res) => {
  const text = fs.readFileSync(path.resolve(DOCS_DIR, req.params.name), 'utf8'); // BUG: web-js-path-traversal -- params, resolve, fs.readFileSync
  res.type('text/plain').send(text);
});
