/**
 * web-js-path-traversal -- nothing here may fire (US-2.AC-2).
 *
 * `path.basename` between the request and the join strips every directory
 * component, so the read stays in the directory it names. Through a variable
 * (the S06 fix), and inline.
 */

import fs from 'node:fs';
import path from 'node:path';
import { Router } from 'express';

const UPLOAD_DIR = '/srv/app/uploads';
const DOCS_DIR = '/srv/app/docs';

export const filesRouter = Router();

filesRouter.get('/download', (req, res) => {
  const name = path.basename(String(req.query.file ?? ''));
  res.download(path.join(UPLOAD_DIR, name));
});

filesRouter.get('/docs/:name', (req, res) => {
  fs.readFile(path.join(DOCS_DIR, path.basename(req.params.name)), 'utf8', (err, text) => {
    res.send(err ? '' : text);
  });
});
