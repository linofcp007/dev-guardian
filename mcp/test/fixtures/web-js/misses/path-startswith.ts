/**
 * web-js-path-traversal -- nothing here may fire (US-2.AC-2).
 *
 * The path is resolved, then compared with the base directory
 * (`startsWith` on the result of `path.resolve`) before anything is read or
 * sent. Three shapes of the same check: an early return, a guarded block,
 * and a throw.
 */

import fs from 'node:fs';
import path from 'node:path';
import { Router } from 'express';

const BASE_DIR = path.resolve('/srv/app/files');

export const contained = Router();

contained.get('/files', (req, res) => {
  const target = path.resolve(BASE_DIR, String(req.query.file));
  if (!target.startsWith(BASE_DIR + path.sep)) {
    res.status(400).end();
    return;
  }
  res.sendFile(target);
});

contained.get('/files/:name/stream', (req, res) => {
  const target = path.resolve(BASE_DIR, req.params.name);
  if (target.startsWith(BASE_DIR + path.sep)) {
    fs.createReadStream(target).pipe(res);
  } else {
    res.sendStatus(404);
  }
});

contained.post('/files/fetch', (req, res) => {
  const target = path.resolve(BASE_DIR, req.body.file);
  if (!target.startsWith(BASE_DIR + path.sep)) throw new Error('outside the files directory');
  res.download(target);
});
