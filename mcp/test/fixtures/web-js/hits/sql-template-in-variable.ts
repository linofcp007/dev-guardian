/**
 * web-js-sql-template, the S04 shape of the spike's synthetic app -- every `// BUG` line fires the rule exactly once.
 *
 * The repository receives the request's text by PARAMETER (the route that
 * reads `req.query` is in another file), builds the statement in a variable
 * and prepares it on the next line. A taint rule from `req.*` cannot see
 * this, which is why the SQL rule is a pattern over the statement (design of
 * record). The finding is on the line where the SQL text is BUILT: the
 * spike's answer key puts S04 on the template (lines 63-64), not on the
 * `prepare` that runs it (line 66) -- US-1.AC-3.
 */

import { db } from './db.js';

export function searchShifts(clinicId: number, term: string) {
  const sql = `SELECT * FROM shifts WHERE clinic_id = ? AND title LIKE '%${term}%'`; // BUG: web-js-sql-template -- template in a variable, prepared below
  return db.prepare(sql).all(clinicId);
}

export function shiftsInWard(ward: string) {
  const sql = 'SELECT * FROM shifts WHERE ward = ' + ward; // BUG: web-js-sql-template -- concatenation in a variable, prepared below
  return db.prepare(sql).all();
}
