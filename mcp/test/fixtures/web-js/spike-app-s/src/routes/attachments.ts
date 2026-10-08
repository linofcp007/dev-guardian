import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import express, { Router } from 'express';
import { config } from '../config.js';
import { currentUser } from '../middleware/auth.js';
import { HttpError, asyncHandler, notFound } from '../middleware/errors.js';
import { parseId } from '../middleware/validate.js';
import * as attachments from '../repositories/attachments.js';
import * as shifts from '../repositories/shifts.js';

const ALLOWED_TYPES: Record<string, string> = {
  'application/pdf': '.pdf',
  'image/jpeg': '.jpg',
  'image/png': '.png',
};

export const attachmentRouter = Router({ mergeParams: true });

attachmentRouter.get(
  '/',
  asyncHandler((req, res) => {
    const me = currentUser(req);
    const shift = shifts.findInClinic(parseId(req), me.clinicId);
    if (!shift) throw notFound('Shift');
    const items = attachments.listForShift(shift.id).map((a) => ({
      id: a.id,
      name: a.original_name,
      file: a.stored_name,
      contentType: a.content_type,
      size: a.size,
      createdAt: a.created_at,
    }));
    res.json({ items });
  }),
);

attachmentRouter.post(
  '/',
  express.raw({ type: Object.keys(ALLOWED_TYPES), limit: config.maxUploadBytes }),
  asyncHandler(async (req, res) => {
    const me = currentUser(req);
    const shift = shifts.findInClinic(parseId(req), me.clinicId);
    if (!shift) throw notFound('Shift');

    const contentType = String(req.headers['content-type'] ?? '').split(';')[0]?.trim() ?? '';
    const extension = ALLOWED_TYPES[contentType];
    if (!extension) throw new HttpError(415, 'Only PDF, JPEG and PNG files are accepted');
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      throw new HttpError(400, 'Empty upload');
    }

    const originalName = String(req.headers['x-file-name'] ?? 'certificate').slice(0, 120);
    const storedName = `${randomUUID()}${extension}`;
    await fsp.writeFile(path.join(config.uploadDir, storedName), req.body, { mode: 0o640 });

    const created = attachments.create({
      shiftId: shift.id,
      clinicId: me.clinicId,
      uploaderId: me.sub,
      originalName,
      storedName,
      contentType,
      size: req.body.length,
    });
    res.status(201).json({ id: created.id, file: created.stored_name });
  }),
);

export const downloadRouter = Router();

downloadRouter.get(
  '/download',
  asyncHandler((req, res) => {
    currentUser(req);
    const file = String(req.query.file ?? '');
    if (!file) throw new HttpError(400, 'file is required');
    const target = path.join(config.uploadDir, file);
    if (!fs.existsSync(target)) throw notFound('Attachment');
    res.download(target);
  }),
);
