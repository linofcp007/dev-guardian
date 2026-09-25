/**
 * Startup housekeeping: the orphaned-scan reaper and scan retention.
 *
 * Both are best-effort. Neither may ever stop the server: a reaper that could
 * not take the write lock, or a prune that hit a corrupt row, leaves the
 * database exactly as usable as before, so each step logs its failure and the
 * server starts anyway. (A reaper failure used to be fatal — exit 1 — the
 * moment another process held the write lock at startup.)
 *
 * ---- Retention -------------------------------------------------------------
 *
 * Nothing was ever deleted: every scan, finding and CVE row accumulated for
 * the life of the project. {@link pruneScans} keeps the newest N scans per
 * (project_path, scan_type) — `GUARDIAN_RETENTION_SCANS`, default
 * {@link DEFAULT_RETENTION_SCANS}, `0` disables — and deletes the rest with
 * every row that points at them. What refers to a scan, per the schema
 * (migrations 001–005), and what happens to it:
 *
 *   - `baselines.scan_id`   → the scan is NEVER deleted (it is the baseline).
 *   - a `running` scan      → NEVER deleted: its owner is still writing to it.
 *   - `findings.scan_id`, `scan_cves.scan_id`, `tree_cache.scan_id`
 *                           → deleted with the scan.
 *   - `cves.first_seen_scan_id` / `last_seen_scan_id` (the legacy table,
 *     no longer read) → those rows are deleted too; they reference scans
 *     without ON DELETE CASCADE, so leaving them would fail the delete.
 *
 * Surface snapshots (`surface_snapshots`) and `finding_validations` carry no
 * scan reference at all — a snapshot is keyed by project and tree hash — so no
 * scan is held back on their account. `scans.cached_from` exists in the schema
 * but nothing writes it (a cache hit returns the original scan's own row), and
 * an audit scan's `meta.sub_scan_ids` is informational JSON nothing reads. A
 * future table that references `scans(id)` must be added to the list above
 * and to {@link deleteBatch}.
 */

import type { DB } from './db.js';

export const DEFAULT_RETENTION_SCANS = 50;

/** Scans deleted per write transaction, so the lock is never held for long. */
const PRUNE_BATCH = 200;

export interface RetentionLimit {
  /** Scans to keep per (project, scan type); 0 disables pruning. */
  keep: number;
  /** Set when the configured value was unusable and the default applies. */
  warning?: string;
}

/** Reads `GUARDIAN_RETENTION_SCANS`: a non-negative integer, or the default. */
export function resolveRetentionLimit(raw: string | undefined): RetentionLimit {
  const value = raw?.trim() ?? '';
  if (value === '') return { keep: DEFAULT_RETENTION_SCANS };
  if (/^\d+$/.test(value)) return { keep: Number.parseInt(value, 10) };
  return {
    keep: DEFAULT_RETENTION_SCANS,
    warning:
      `GUARDIAN_RETENTION_SCANS='${raw}' is not a non-negative integer; ` +
      `keeping the newest ${DEFAULT_RETENTION_SCANS} scans per project and scan type.`,
  };
}

export interface PruneResult {
  /** Scans deleted (their findings, CVE rows and cache rows went with them). */
  deleted: number;
}

// Ranked newest-first within each (project, scan type) — the same
// `started_at DESC, rowid DESC` order every history query in scansRepo uses.
const DOOMED_SQL = `
  SELECT id FROM (
    SELECT id, status,
           ROW_NUMBER() OVER (
             PARTITION BY project_path, scan_type
             ORDER BY started_at DESC, rowid DESC
           ) AS rn
    FROM scans
  )
  WHERE rn > ?
    AND status <> 'running'
    AND id NOT IN (SELECT scan_id FROM baselines)
  LIMIT ${PRUNE_BATCH}
`;

/**
 * Deletes every scan beyond the newest `keep` per (project, scan type),
 * except those a baseline points at and those still running. See the module
 * header for what goes with each scan. `keep <= 0` deletes nothing.
 *
 * The doomed set is chosen INSIDE each write transaction, not before it, so a
 * baseline another process sets on a scan in the meantime is honoured.
 */
export function pruneScans(db: DB, keep: number): PruneResult {
  if (!(keep > 0)) return { deleted: 0 };
  const selectDoomed = db.prepare<[number], { id: string }>(DOOMED_SQL);
  const batch = db.transaction((): number => {
    const ids = selectDoomed.all(keep).map((r) => r.id);
    if (ids.length > 0) deleteBatch(db, ids);
    return ids.length;
  });

  let deleted = 0;
  for (;;) {
    const n = batch();
    deleted += n;
    if (n < PRUNE_BATCH) return { deleted };
  }
}

function deleteBatch(db: DB, ids: string[]): void {
  const list = ids.map(() => '?').join(', ');
  db.prepare<string[]>(`DELETE FROM findings WHERE scan_id IN (${list})`).run(...ids);
  db.prepare<string[]>(`DELETE FROM scan_cves WHERE scan_id IN (${list})`).run(...ids);
  db.prepare<string[]>(`DELETE FROM tree_cache WHERE scan_id IN (${list})`).run(...ids);
  db.prepare<string[]>(
    `DELETE FROM cves WHERE first_seen_scan_id IN (${list}) OR last_seen_scan_id IN (${list})`,
  ).run(...ids, ...ids);
  db.prepare<string[]>(`DELETE FROM scans WHERE id IN (${list})`).run(...ids);
}

/** The slice of `Storage` startup maintenance needs. */
export interface MaintenanceTarget {
  scans: { reapRunning(): number };
  rawHandle(): DB;
}

/**
 * The server's startup housekeeping: reap orphaned scans, then prune. Each
 * step is independent and non-fatal — see the module header.
 */
export function runStartupMaintenance(
  storage: MaintenanceTarget,
  log: (line: string) => void,
  env: Record<string, string | undefined> = process.env,
): void {
  try {
    const reaped = storage.scans.reapRunning();
    if (reaped > 0) log(`reaped ${reaped} orphaned scan(s)`);
  } catch (error) {
    log(`reaper failed (continuing): ${describe(error)}`);
  }

  const limit = resolveRetentionLimit(env['GUARDIAN_RETENTION_SCANS']);
  if (limit.warning !== undefined) log(limit.warning);
  if (limit.keep === 0) return;
  try {
    const { deleted } = pruneScans(storage.rawHandle(), limit.keep);
    if (deleted > 0) {
      log(`pruned ${deleted} scan(s) beyond the newest ${limit.keep} per project and scan type`);
    }
  } catch (error) {
    log(`retention failed (continuing): ${describe(error)}`);
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
