/**
 * web-js-path-traversal into res.download -- every `// BUG` line fires the rule exactly once.
 *
 * The second handler is the spike's S06 (`src/routes/attachments.ts:77-81`)
 * with the join moved into the download, so the line is unambiguous here; the
 * original two-line shape is checked against the spike app itself (T-06).
 */

import path from 'node:path';
import { Router } from 'express';

const EXPORT_DIR = '/srv/app/exports';
const UPLOAD_DIR = '/srv/app/uploads';

export const downloadRouter = Router();

downloadRouter.post('/export', (req, res) => {
  res.download(path.join(EXPORT_DIR, req.body.file)); // BUG: web-js-path-traversal -- body, join, res.download
});

downloadRouter.get('/download', (req, res) => {
  const file = String(req.query.file ?? '');
  if (!file) {
    res.status(400).end();
    return;
  }
  res.download(path.join(UPLOAD_DIR, file)); // BUG: web-js-path-traversal -- query through a variable, join, res.download
});
