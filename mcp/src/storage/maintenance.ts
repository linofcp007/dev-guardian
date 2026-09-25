/**
 * Startup housekeeping: the orphaned-scan reaper and scan retention.
 *
 * Both are best-effort. Neither may ever stop the server: a reaper that could
 * not take the write lock, or a prune that hit a corrupt row, leaves the
 * database exactly as usable as before, so each step logs its failure and the
 * server starts anyway. (A reaper failure used to be fatal — exit 1 — the
 * moment another process held the write lock at startup.)
 *
 * The reaper runs before the server connects (it only touches `running`
 * rows, a handful at most). Retention does NOT: {@link scheduleRetention}
 * runs it after the connection is up, in short batches with a per-startup
 * work budget, and leaves whatever the budget did not reach for the next
 * start — so a large backlog can neither delay startup nor hold the write
 * lock long enough to push another process into its busy timeout.
 *
 * ---- Retention -------------------------------------------------------------
 *
 * Nothing was ever deleted: every scan, finding and CVE row accumulated for
 * the life of the project. Retention keeps the newest N scans per
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
 * Every one of those columns is indexed (migration 005 added the three that
 * were not). Without the indexes each deleted scan cost two full scans of
 * `cves` and one of `tree_cache` — for the explicit deletes and again for
 * SQLite's foreign-key check — which measured 21.5 s for 2950 scans over 60k
 * legacy CVE rows, all of it under one write lock. With the indexes and
 * {@link PRUNE_BATCH}-scan batches, the same backlog took 1.1 s of work in 59
 * transactions, the longest holding the lock for 59 ms.
 *
 * Surface snapshots (`surface_snapshots`) and `finding_validations` carry no
 * scan reference at all — a snapshot is keyed by project and tree hash — so no
 * scan is held back on their account. `scans.cached_from` exists in the schema
 * but nothing writes it (a cache hit returns the original scan's own row), and
 * an audit scan's `meta.sub_scan_ids` is informational JSON nothing reads. A
 * future table that references `scans(id)` must be added to the list above,
 * indexed, and deleted in {@link deleteScans}.
 */

import type { DB } from './db.js';

export const DEFAULT_RETENTION_SCANS = 50;

/**
 * Scans deleted per write transaction. With every referencing column indexed
 * a batch this size holds the write lock for milliseconds, not seconds.
 */
export const PRUNE_BATCH = 50;

/** Work (not wall-clock) time retention may spend per server start. */
export const RETENTION_BUDGET_MS = 1000;

/** How long after connecting retention starts, so the host's handshake goes first. */
export const RETENTION_START_DELAY_MS = 2000;

/** Pause between batches, so another process can take the write lock in between. */
export const RETENTION_BATCH_GAP_MS = 20;

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

// Ranked newest-first within each (project, scan type) — the same
// `started_at DESC, rowid DESC` order every history query in scansRepo uses —
// and returned OLDEST first, so a run the budget cuts short has removed the
// oldest history and left the most recent.
const PRUNABLE_SQL = `
  SELECT id FROM (
    SELECT id, status, started_at, rowid AS rid,
           ROW_NUMBER() OVER (
             PARTITION BY project_path, scan_type
             ORDER BY started_at DESC, rowid DESC
           ) AS rn
    FROM scans
  )
  WHERE rn > ?
    AND status <> 'running'
    AND id NOT IN (SELECT scan_id FROM baselines)
  ORDER BY started_at ASC, rid ASC
`;

/**
 * Every scan beyond the newest `keep` per (project, scan type), except those
 * a baseline points at and those still running. A plain read — no write lock.
 * A scan found here stays prunable: newer scans only push it further down,
 * and {@link deleteScans} re-checks the two exclusions under the lock.
 */
export function listPrunableScans(db: DB, keep: number): string[] {
  if (!(keep > 0)) return [];
  return db.prepare<[number], { id: string }>(PRUNABLE_SQL).all(keep).map((r) => r.id);
}

/**
 * Deletes `ids` and every row that points at them, in ONE short write
 * transaction. Re-checks, under the lock, that each is still not running and
 * not a baseline — a baseline set by another process since the ids were
 * listed is honoured. Returns how many scans were deleted.
 */
export function deleteScans(db: DB, ids: readonly string[]): number {
  if (ids.length === 0) return 0;
  return db.transaction((): number => {
    const list = ids.map(() => '?').join(', ');
    const eligible = db
      .prepare<string[], { id: string }>(
        `SELECT id FROM scans WHERE id IN (${list})
           AND status <> 'running' AND id NOT IN (SELECT scan_id FROM baselines)`,
      )
      .all(...ids)
      .map((r) => r.id);
    if (eligible.length === 0) return 0;
    const del = eligible.map(() => '?').join(', ');
    db.prepare<string[]>(`DELETE FROM findings WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare<string[]>(`DELETE FROM scan_cves WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare<string[]>(`DELETE FROM tree_cache WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare<string[]>(
      `DELETE FROM cves WHERE first_seen_scan_id IN (${del}) OR last_seen_scan_id IN (${del})`,
    ).run(...eligible, ...eligible);
    return db.prepare<string[]>(`DELETE FROM scans WHERE id IN (${del})`).run(...eligible).changes;
  })();
}

export interface PruneBudget {
  /** Scans per write transaction. Default {@link PRUNE_BATCH}. */
  batchSize?: number;
  /** Stop after this many batches. Default: no limit. */
  maxBatches?: number;
  /** Stop starting new batches once this much work time has passed. Default: no limit. */
  budgetMs?: number;
  /** Clock, for tests. Default `performance.now()`. */
  now?: () => number;
}

export interface PruneResult {
  /** Scans deleted (their findings, CVE rows and cache rows went with them). */
  deleted: number;
  /** Prunable scans left for a later run because the budget ran out. */
  remaining: number;
  /** True when nothing prunable is left. */
  complete: boolean;
}

/**
 * Synchronous retention within a budget: lists the prunable scans once, then
 * deletes them batch by batch, each batch its own short write transaction,
 * until none are left or the budget is spent. The server does not call this
 * directly — it uses {@link scheduleRetention}, which spreads the same batches
 * over timer ticks.
 */
export function pruneScans(db: DB, keep: number, budget: PruneBudget = {}): PruneResult {
  const now = budget.now ?? (() => performance.now());
  const started = now();
  const pending = listPrunableScans(db, keep);
  const batchSize = budget.batchSize ?? PRUNE_BATCH;
  let deleted = 0;
  let batches = 0;
  while (pending.length > 0) {
    if (budget.maxBatches !== undefined && batches >= budget.maxBatches) break;
    if (budget.budgetMs !== undefined && now() - started >= budget.budgetMs) break;
    deleted += deleteScans(db, pending.splice(0, batchSize));
    batches += 1;
  }
  return { deleted, remaining: pending.length, complete: pending.length === 0 };
}

/** The slice of `Storage` startup maintenance needs. */
export interface MaintenanceTarget {
  scans: { reapRunning(): number };
  rawHandle(): DB;
}

/**
 * Fails scans whose owning process died (see `ScansRepo.reapRunning`). Runs
 * before the server connects; never throws.
 */
export function reapOrphanedScans(storage: MaintenanceTarget, log: (line: string) => void): void {
  try {
    const reaped = storage.scans.reapRunning();
    if (reaped > 0) log(`reaped ${reaped} orphaned scan(s)`);
  } catch (error) {
    log(`reaper failed (continuing): ${describe(error)}`);
  }
}

/** Runs `fn` after `ms`; returns a function that cancels it. */
export type Defer = (fn: () => void, ms: number) => () => void;

const defaultDefer: Defer = (fn, ms) => {
  const timer = setTimeout(fn, ms);
  // Retention alone must never keep a process alive.
  timer.unref();
  return () => clearTimeout(timer);
};

export interface RetentionSchedule {
  env?: Record<string, string | undefined>;
  defer?: Defer;
  budgetMs?: number;
  batchSize?: number;
  startDelayMs?: number;
  now?: () => number;
}

/**
 * Starts retention in the background: after {@link RETENTION_START_DELAY_MS},
 * one batch per timer tick ({@link RETENTION_BATCH_GAP_MS} apart), until
 * nothing prunable is left or {@link RETENTION_BUDGET_MS} of work has been
 * spent — the rest waits for the next start. Logs what it did; logs and stops
 * on any error; never throws. Returns a function that cancels whatever has
 * not run yet (the server calls it on shutdown, before closing the database).
 */
export function scheduleRetention(
  storage: MaintenanceTarget,
  log: (line: string) => void,
  options: RetentionSchedule = {},
): () => void {
  const limit = resolveRetentionLimit((options.env ?? process.env)['GUARDIAN_RETENTION_SCANS']);
  if (limit.warning !== undefined) log(limit.warning);
  if (limit.keep === 0) return () => {};

  const defer = options.defer ?? defaultDefer;
  const now = options.now ?? (() => performance.now());
  const budgetMs = options.budgetMs ?? RETENTION_BUDGET_MS;
  const batchSize = options.batchSize ?? PRUNE_BATCH;
  let cancelled = false;
  let cancelNext: () => void = () => {};
  let pending: string[] | undefined;
  let spent = 0;
  let deleted = 0;

  const finish = (left: number): void => {
    if (deleted === 0 && left === 0) return;
    log(
      `pruned ${deleted} scan(s) beyond the newest ${limit.keep} per project and scan type` +
        (left > 0 ? `; ${left} left for the next start (retention budget ${budgetMs} ms)` : ''),
    );
  };

  const tick = (): void => {
    if (cancelled) return;
    const t0 = now();
    let left: number;
    try {
      const db = storage.rawHandle();
      pending ??= listPrunableScans(db, limit.keep);
      deleted += deleteScans(db, pending.splice(0, batchSize));
      left = pending.length;
    } catch (error) {
      log(`retention failed (continuing): ${describe(error)}`);
      return;
    }
    spent += now() - t0;
    if (left === 0 || spent >= budgetMs) {
      finish(left);
      return;
    }
    cancelNext = defer(tick, RETENTION_BATCH_GAP_MS);
  };

  cancelNext = defer(tick, options.startDelayMs ?? RETENTION_START_DELAY_MS);
  return () => {
    cancelled = true;
    cancelNext();
  };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
