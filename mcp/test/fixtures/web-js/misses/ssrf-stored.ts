/**
 * web-js-ssrf -- nothing here may fire: STORED SSRF, out of reach by design (EC-4).
 *
 * This IS server-side request forgery -- the spike's S05: a clinic admin
 * stores a pager URL, and the server later fetches it with no host, scheme or
 * address restriction. But the URL comes from a database row, not from the
 * request being handled, and no rule that follows `req.query` / `req.params` /
 * `req.body` within one function can reach it. The pack documents this as a
 * known gap (the `llm-scan` feature covers it); this file pins that the rule
 * does not pretend otherwise by firing on the stored value's read.
 */

import { Router } from 'express';
import { db } from './db.js';

interface ClinicRow {
  pager_url: string | null;
}

export async function notifyClinic(clinicId: number, payload: unknown) {
  const clinic = db.prepare('SELECT pager_url FROM clinics WHERE id = ?').get(clinicId) as ClinicRow | undefined;
  if (!clinic || !clinic.pager_url) return;
  await fetch(clinic.pager_url, { method: 'POST', body: JSON.stringify(payload) });
}

export const pagerRouter = Router();

pagerRouter.post('/clinics/test-pager', async (_req, res) => {
  const me = res.locals.user as { clinicId: number };
  await notifyClinic(me.clinicId, { event: 'ping' });
  res.sendStatus(202);
});
