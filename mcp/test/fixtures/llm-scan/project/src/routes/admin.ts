import { Router } from 'express';
import { runReport } from '../util/shell.js';

export const adminRouter = Router();

// Mounted without requireAuth in app.ts.
adminRouter.get('/stats', async (req, res) => {
  const out = await runReport(String(req.query.report ?? 'daily'));
  res.type('text/plain').send(out);
});
