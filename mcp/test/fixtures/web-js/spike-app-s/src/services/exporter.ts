import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { config } from '../config.js';
import { db } from '../db.js';
import * as users from '../repositories/users.js';
import type { ShiftRow } from '../types.js';

const run = promisify(execFile);

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  const text = String(value);
  const guarded = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

export function toCsv(rows: Record<string, unknown>[]): string {
  const first = rows[0];
  if (!first) return '';
  const columns = Object.keys(first);
  const lines = [columns.join(',')];
  for (const row of rows) {
    lines.push(columns.map((column) => csvCell(row[column])).join(','));
  }
  return lines.join('\n') + '\n';
}

export function rosterRows(clinicId: number): Record<string, unknown>[] {
  return db
    .prepare('SELECT * FROM users WHERE clinic_id = ? ORDER BY display_name')
    .all(clinicId) as Record<string, unknown>[];
}

export function activeRosterCount(clinicId: number): number {
  return users.listAllForClinic(clinicId).filter((u) => u.active === 1).length;
}

export function shiftRows(clinicId: number, from: string, to: string): ShiftRow[] {
  return db
    .prepare(
      `SELECT * FROM shifts WHERE clinic_id = ? AND starts_at >= ? AND starts_at < ?
       ORDER BY starts_at`,
    )
    .all(clinicId, from, to) as ShiftRow[];
}

export async function gzipText(text: string): Promise<Buffer> {
  const target = path.join(config.tmpDir, `export-${randomUUID()}.txt`);
  await fs.writeFile(target, text, { mode: 0o600 });
  try {
    await run('gzip', ['-9', '-n', '-f', target]);
    return await fs.readFile(`${target}.gz`);
  } finally {
    await fs.rm(target, { force: true });
    await fs.rm(`${target}.gz`, { force: true });
  }
}
