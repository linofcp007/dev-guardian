import { db } from '../db.js';
import type { ShiftRow, ShiftStatus } from '../types.js';

const SORT_COLUMNS: Record<string, string> = {
  start: 'starts_at',
  ward: 'ward',
  title: 'title',
};

export interface ShiftFilter {
  clinicId: number;
  from?: string;
  to?: string;
  assigneeId?: number;
  status?: ShiftStatus;
  sort?: string;
  dir?: string;
  limit: number;
  offset: number;
}

export function findById(id: number): ShiftRow | undefined {
  return db.prepare('SELECT * FROM shifts WHERE id = ?').get(id) as ShiftRow | undefined;
}

export function findInClinic(id: number, clinicId: number): ShiftRow | undefined {
  return db.prepare('SELECT * FROM shifts WHERE id = ? AND clinic_id = ?').get(id, clinicId) as
    | ShiftRow
    | undefined;
}

export function list(filter: ShiftFilter): ShiftRow[] {
  const where: string[] = ['clinic_id = @clinicId'];
  const params: Record<string, unknown> = {
    clinicId: filter.clinicId,
    limit: filter.limit,
    offset: filter.offset,
  };
  if (filter.from) {
    where.push('starts_at >= @from');
    params.from = filter.from;
  }
  if (filter.to) {
    where.push('starts_at < @to');
    params.to = filter.to;
  }
  if (filter.assigneeId !== undefined) {
    where.push('assignee_id = @assigneeId');
    params.assigneeId = filter.assigneeId;
  }
  if (filter.status) {
    where.push('status = @status');
    params.status = filter.status;
  }
  const orderBy = SORT_COLUMNS[filter.sort ?? ''] ?? SORT_COLUMNS.start;
  const direction = filter.dir === 'desc' ? 'DESC' : 'ASC';
  const sql = `SELECT * FROM shifts WHERE ${where.join(' AND ')}
    ORDER BY ${orderBy} ${direction} LIMIT @limit OFFSET @offset`;
  return db.prepare(sql).all(params) as ShiftRow[];
}

export function search(clinicId: number, term: string): ShiftRow[] {
  const sql = `SELECT * FROM shifts
    WHERE clinic_id = ${clinicId} AND (title LIKE '%${term}%' OR ward LIKE '%${term}%' OR notes LIKE '%${term}%')
    ORDER BY starts_at DESC LIMIT 100`;
  return db.prepare(sql).all() as ShiftRow[];
}

export function listForAssignee(userId: number, from: string): ShiftRow[] {
  return db
    .prepare(
      `SELECT * FROM shifts WHERE assignee_id = ? AND ends_at >= ? AND status != 'cancelled'
       ORDER BY starts_at`,
    )
    .all(userId, from) as ShiftRow[];
}

export interface NewShift {
  clinicId: number;
  title: string;
  ward: string;
  startsAt: string;
  endsAt: string;
  assigneeId?: number | null;
  notes?: string | null;
}

export function create(input: NewShift): ShiftRow {
  const status: ShiftStatus = input.assigneeId ? 'assigned' : 'open';
  const info = db
    .prepare(
      `INSERT INTO shifts (clinic_id, title, ward, starts_at, ends_at, assignee_id, status, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      input.clinicId,
      input.title,
      input.ward,
      input.startsAt,
      input.endsAt,
      input.assigneeId ?? null,
      status,
      input.notes ?? null,
    );
  return findById(Number(info.lastInsertRowid)) as ShiftRow;
}

export interface ShiftPatch {
  title?: string;
  ward?: string;
  startsAt?: string;
  endsAt?: string;
  notes?: string | null;
}

export function update(id: number, patch: ShiftPatch): ShiftRow | undefined {
  db.prepare(
    `UPDATE shifts SET
       title = COALESCE(?, title),
       ward = COALESCE(?, ward),
       starts_at = COALESCE(?, starts_at),
       ends_at = COALESCE(?, ends_at),
       notes = COALESCE(?, notes)
     WHERE id = ?`,
  ).run(
    patch.title ?? null,
    patch.ward ?? null,
    patch.startsAt ?? null,
    patch.endsAt ?? null,
    patch.notes ?? null,
    id,
  );
  return findById(id);
}

export function assign(id: number, userId: number | null) {
  db.prepare('UPDATE shifts SET assignee_id = ?, status = ? WHERE id = ?').run(
    userId,
    userId ? 'assigned' : 'open',
    id,
  );
}

export function cancel(id: number) {
  db.prepare("UPDATE shifts SET status = 'cancelled' WHERE id = ?").run(id);
}
