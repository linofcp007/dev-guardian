import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Router } from 'express';

export const filesRouter = Router();

const UPLOADS = '/srv/uploads';

filesRouter.get('/:name', async (req, res) => {
  // No normalisation: '../' walks out of the uploads directory.
  const body = await readFile(join(UPLOADS, req.params.name));
  res.type('application/octet-stream').send(body);
});

filesRouter.post('/upload', async (req, res) => {
  const name = String(req.query.name ?? 'upload.bin').replace(/[^a-z0-9._-]/gi, '_');
  res.json({ stored: join(UPLOADS, name), bytes: Number(req.headers['content-length'] ?? 0) });
});
