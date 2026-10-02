/**
 * web-js-sql-template -- nothing here may fire (EC-2).
 *
 * The interpolated value is a run of generated placeholders, `?,?,?`, made
 * with `Array(n).fill('?').join(',')`; the values themselves are bound. This
 * is how an `IN (...)` list is parameterised with a driver that has no array
 * binding, and it is the fix the rule's message should be able to prescribe.
 */

import { db } from './db.js';

export function shiftsByIds(ids: number[]) {
  const placeholders = Array(ids.length).fill('?').join(',');
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${placeholders})`).all(...ids);
}

export function shiftsByIdsInline(ids: number[]) {
  return db.prepare(`SELECT * FROM shifts WHERE id IN (${Array(ids.length).fill('?').join(',')})`).all(...ids);
}

export function shiftsInWards(wards: string[]) {
  const marks = new Array(wards.length).fill('?').join(', ');
  return db.prepare(`SELECT * FROM shifts WHERE ward IN (${marks})`).all(...wards);
}
