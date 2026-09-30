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
 * every row that points at them. Scoped scans (`meta.scope`, a single-plugin
 * `wp_vuln_check`) are counted apart from whole-project ones, and scans that
 * measured nothing (failed, cancelled, coverage `none`) apart from usable
 * ones: N of each, so neither pre-commit runs nor a run of broken scans can
 * push out the scan the open set reads. What
 * refers to a scan, per the schema (migrations 001–005), and what happens to
 * it:
 *
 *   - `baselines.scan_id`   → the scan is NEVER deleted (it is the baseline).
 *   - an orchestrated run around a baseline → NEVER deleted either: the
 *     children a baselined `security_full` parent is compared through
 *     (`meta.child_scans`, `meta.parent_scan_id`), the parent of a
 *     baselined child, and the sub-scans a baselined `audit` row links in
 *     `meta.sub_scan_ids`.
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
 * but nothing writes it (a cache hit returns the original scan's own row). An
 * audit scan's `meta.sub_scan_ids` is read by `history/runCompare.ts`, which
 * falls back to the audit's own per-tool entries when a sub-scan is gone —
 * so only a BASELINED audit's sub-scans are held back (above); an ordinary
 * audit's go with their own partitions. A
 * future table that references `scans(id)` must be added to the list above,
 * indexed, and deleted in `deleteRows`.
 */

import { spellingOnlyCanonical } from '../platform/pathSpelling.js';
import type { DB } from './db.js';
import { openSetForProject } from '../history/openSet.js';
import type { Storage } from './index.js';
import { STACK_SNAPSHOTS_KEPT } from './stackRepo.js';

export const DEFAULT_RETENTION_SCANS = 50;

/**
 * Scans deleted per write transaction, at most. With every referencing column
 * indexed a batch this size holds the write lock for milliseconds, not
 * seconds — when its scans are small ({@link PRUNE_BATCH_ROWS}).
 */
export const PRUNE_BATCH = 50;

/**
 * Finding and CVE rows deleted per write transaction, at most: the scans of a
 * batch are taken while their rows add up to no more than this. Fifty scans
 * of ~360 findings (~18k rows) held the write lock 1.7–2.6 s in the retention
 * review — beyond the 1 s budget, and with bigger scans on the way to another
 * process's 5 s busy timeout. A single scan larger than this is deleted alone:
 * splitting ONE scan's rows over several transactions would let a reader, or
 * a baseline set in between, see it half deleted.
 */
export const PRUNE_BATCH_ROWS = 5000;

/**
 * Takes the next batch off the front of `pending` — oldest first — and
 * returns it: at most `maxScans` scans whose finding and `scan_cves` rows add
 * up to at most `maxRows`, and always at least one. The counts are plain,
 * indexed reads (`findings.scan_id`, `scan_cves.scan_id`), outside the write
 * transaction.
 */
export function takePruneBatch(db: DB, pending: string[], maxScans: number, maxRows = PRUNE_BATCH_ROWS): string[] {
  const head = pending.slice(0, Math.max(1, maxScans));
  if (head.length <= 1) return pending.splice(0, head.length);
  const list = head.map(() => '?').join(', ');
  const rows = new Map<string, number>();
  for (const table of ['findings', 'scan_cves']) {
    for (const r of db
      .prepare<string[], { id: string; n: number }>(
        `SELECT scan_id AS id, COUNT(*) AS n FROM ${table} WHERE scan_id IN (${list}) GROUP BY scan_id`,
      )
      .all(...head)) {
      rows.set(r.id, (rows.get(r.id) ?? 0) + r.n);
    }
  }
  let total = 0;
  let take = 0;
  for (const id of head) {
    const n = rows.get(id) ?? 0;
    if (take > 0 && total + n > maxRows) break;
    total += n;
    take += 1;
  }
  return pending.splice(0, take);
}

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

// A scoped row — a diff or partial run (`meta.scope`), or a single-plugin
// `wp_vuln_check` (`meta.slug`) — decided exactly as
// `history/scanRoles.ts#isScopedScan` decides it. CASE, not AND: SQLite does
// not promise to evaluate json_valid first, and json_extract throws on the
// malformed JSON `rowToRecord` tolerates (such a row reads as unscoped there
// too).
const SCOPED_SQL = `(CASE WHEN json_valid(meta) THEN
    json_extract(meta, '$.scope') IS NOT NULL
    OR (scan_type = 'wp_vuln_check' AND json_type(meta, '$.slug') IS NOT NULL)
  ELSE 0 END)`;

// A tools_run / missing_tools column as a JSON array to walk: '[]' for
// anything else, as `scansRepo.ts#parseJsonArray` reads it in JS (json_each
// throws on malformed JSON; CASE, not AND, for the same reason as above).
const jsonArrayOr = (column: string): string =>
  `(CASE WHEN json_valid(${column}) AND json_type(${column}) = 'array' THEN ${column} ELSE '[]' END)`;

// A row the open set can read — `history/openSet.ts`'s "usable": completed,
// with coverage (`tools/scanCoverage.ts#computeCoverage`) not `none`. None is
// "some scanner failed or is missing, and none ran ok". A failed, cancelled
// or coverage-none scan measured nothing; the open set passes over it to the
// one before.
const USABLE_SQL = `(CASE
    WHEN status <> 'completed' THEN 0
    WHEN (
      json_array_length(${jsonArrayOr('missing_tools')}) > 0
      OR EXISTS (SELECT 1 FROM json_each(${jsonArrayOr('tools_run')}) AS t
                  WHERE t.type = 'object' AND json_extract(t.value, '$.status') = 'failed')
    ) AND NOT EXISTS (SELECT 1 FROM json_each(${jsonArrayOr('tools_run')}) AS t
                       WHERE t.type = 'object' AND json_extract(t.value, '$.status') = 'ok')
    THEN 0
    ELSE 1
  END)`;

// The scans an orchestrated run's baseline stands on besides its own row:
// the children a baselined parent lists in `meta.child_scans` (what
// `history/runCompare.ts` reads), the parent a baselined child names in
// `meta.parent_scan_id`, and the sub-scans a baselined `audit` row links in
// `meta.sub_scan_ids` — an object `{ tool: scan_id | null }` whose sub-scans
// `runCompare.ts#auditBookkeeping` reads the audit's per-scanner bookkeeping
// through. Only an OBJECT is followed there: `json_each` over a bare string
// or an array would yield its elements as if they were ids. NULLs are
// filtered out: `x NOT IN (… NULL …)` is NULL, which would silently keep
// every row.
const BASELINED_RUN_MEMBERS_SQL = `
  SELECT member FROM (
    SELECT CASE WHEN c.type = 'object' THEN json_extract(c.value, '$.scan_id') END AS member
      FROM baselines b
      JOIN scans p ON p.id = b.scan_id,
           json_each(CASE WHEN json_valid(p.meta) THEN p.meta ELSE '{}' END, '$.child_scans') AS c
    UNION
    SELECT CASE WHEN json_valid(s.meta) THEN json_extract(s.meta, '$.parent_scan_id') END
      FROM baselines b
      JOIN scans s ON s.id = b.scan_id
    UNION
    SELECT u.value
      FROM baselines b
      JOIN scans a ON a.id = b.scan_id,
           json_each(
             CASE WHEN a.scan_type = 'audit' AND json_valid(a.meta)
                       AND json_type(a.meta, '$.sub_scan_ids') = 'object'
                  THEN json_extract(a.meta, '$.sub_scan_ids') ELSE '{}' END
           ) AS u
  )
  WHERE typeof(member) = 'text'
`;

// A row retention must keep whatever its rank: still being written, a
// baseline, or part of a baselined orchestrated run — a child of a baselined
// parent (by its own `meta.parent_scan_id` or by the parent's list), the
// parent of a baselined child, or a sub-scan a baselined audit links. Pruning
// a baselined parent's `sast` child made
// every later SAST finding read "not previously measured": `regression_alert`
// went quiet and `diff_scans from:'baseline'` reported nothing new.
const PROTECTED_SQL = `(
  status = 'running'
  OR id IN (SELECT scan_id FROM baselines)
  OR EXISTS (
    SELECT 1 FROM baselines b
     WHERE b.scan_id = (CASE WHEN json_valid(meta) THEN json_extract(meta, '$.parent_scan_id') END)
  )
  OR id IN (${BASELINED_RUN_MEMBERS_SQL})
)`;

/**
 * Ranked newest-first within each (project, scan type, scoped?) — the same
 * `started_at DESC, rowid DESC` order every history query in scansRepo uses —
 * and returned OLDEST first, so a run the budget cuts short has removed the
 * oldest history and left the most recent.
 *
 * Scoped and whole-project rows are ranked APART. A scoped scan never
 * describes the project's state, so it must never cost a whole-project scan
 * its place: ranked together, fifty `--staged` pre-commit runs pushed out the
 * last whole-project `scan_sast`, and the open set — which skips scoped rows —
 * lost every SAST finding while still reading coverage `full`.
 *
 * Usable and unusable rows ({@link USABLE_SQL}) are ranked apart for the same
 * reason, so the newest usable scan of every (project, type, scope) is always
 * kept: fifty newer runs that measured nothing (a broken Semgrep rule, a
 * `local_only` run with no rules) pushed out the last scan that did, and its
 * findings left every reader — risk_score 18 (medium) → 8 (low), open 1 → 0.
 *
 * `candidates` restricts the ranking to the partitions of that many ids (the
 * `?` placeholders come right after `keep`'s, as `id IN (…)`), for the
 * re-check {@link deleteScans} makes under the write lock.
 */
function prunableSql(candidates: number): string {
  const only =
    candidates > 0
      ? (() => {
          const list = Array.from({ length: candidates }, () => '?').join(', ');
          return {
            partitions: `WHERE (project_path, scan_type) IN
                           (SELECT project_path, scan_type FROM scans WHERE id IN (${list}))`,
            ids: `AND id IN (${list})`,
          };
        })()
      : { partitions: '', ids: '' };
  return `
    SELECT id FROM (
      SELECT id, status, meta, started_at, rowid AS rid,
             ROW_NUMBER() OVER (
               PARTITION BY project_path, scan_type, ${SCOPED_SQL}, ${USABLE_SQL}
               ORDER BY started_at DESC, rowid DESC
             ) AS rn
      FROM scans
      ${only.partitions}
    )
    WHERE rn > ?
      ${only.ids}
      AND NOT ${PROTECTED_SQL}
    ORDER BY started_at ASC, rid ASC
  `;
}

const PRUNABLE_SQL = prunableSql(0);

/**
 * Every scan beyond the newest `keep` per (project, scan type), scoped and
 * whole-project rows counted apart, except the protected ones: still
 * running, a baseline, or part of a baselined orchestrated run. A plain read
 * — no write lock. {@link deletePrunableScans} re-evaluates the very same
 * rule under the lock before it deletes anything.
 */
export function listPrunableScans(db: DB, keep: number): string[] {
  if (!(keep > 0)) return [];
  return db.prepare<[number], { id: string }>(PRUNABLE_SQL).all(keep).map((r) => r.id);
}

/**
 * Retention's delete: those of `ids` that are STILL prunable under `keep`,
 * and every row that points at them, in ONE short write transaction. The
 * whole rule is re-evaluated under the lock — rank, scope and every
 * exclusion — over the partitions the ids belong to, so whatever changed
 * since the ids were listed is honoured: a baseline set by another process
 * (on the scan itself, or on the orchestrated run it belongs to), or a newer
 * row gone. Returns how many scans were deleted.
 */
export function deletePrunableScans(
  db: DB,
  ids: readonly string[],
  keep: number,
  protect: ReadonlySet<string> = NOTHING_PROTECTED,
): number {
  if (ids.length === 0 || !(keep > 0)) return 0;
  return db.transaction((): number => {
    const eligible = db
      .prepare<(string | number)[], { id: string }>(prunableSql(ids.length))
      .all(...ids, keep, ...ids)
      .map((r) => r.id)
      .filter((id) => !protect.has(id));
    return deleteRows(db, eligible);
  })();
}

const NOTHING_PROTECTED: ReadonlySet<string> = new Set();

/**
 * Deletes `ids` — whatever their rank — and every row that points at them,
 * in ONE short write transaction; for a caller that removes a scan it wrote
 * itself (`create_fix_pr`'s worktree re-scan). Re-checks, under the lock,
 * that each is not protected: still running, a baseline, or part of a
 * baselined orchestrated run. Returns how many scans were deleted.
 */
export function deleteScans(db: DB, ids: readonly string[]): number {
  if (ids.length === 0) return 0;
  return db.transaction((): number => {
    const list = ids.map(() => '?').join(', ');
    const eligible = db
      .prepare<string[], { id: string }>(`SELECT id FROM scans WHERE id IN (${list}) AND NOT ${PROTECTED_SQL}`)
      .all(...ids)
      .map((r) => r.id);
    return deleteRows(db, eligible);
  })();
}

/** The deletes themselves; the caller holds the transaction. */
function deleteRows(db: DB, eligible: readonly string[]): number {
  if (eligible.length === 0) return 0;
  const del = eligible.map(() => '?').join(', ');
  db.prepare<string[]>(`DELETE FROM findings WHERE scan_id IN (${del})`).run(...eligible);
  db.prepare<string[]>(`DELETE FROM scan_cves WHERE scan_id IN (${del})`).run(...eligible);
  db.prepare<string[]>(`DELETE FROM tree_cache WHERE scan_id IN (${del})`).run(...eligible);
  db.prepare<string[]>(
    `DELETE FROM cves WHERE first_seen_scan_id IN (${del}) OR last_seen_scan_id IN (${del})`,
  ).run(...eligible, ...eligible);
  return db.prepare<string[]>(`DELETE FROM scans WHERE id IN (${del})`).run(...eligible).changes;
}

export interface PruneBudget {
  /** Scans per write transaction, at most. Default {@link PRUNE_BATCH}; rows are capped at {@link PRUNE_BATCH_ROWS} too. */
  batchSize?: number;
  /** Stop after this many batches. Default: no limit. */
  maxBatches?: number;
  /** Stop starting new batches once this much work time has passed. Default: no limit. */
  budgetMs?: number;
  /** Clock, for tests. Default `performance.now()`. */
  now?: () => number;
  /** Scans never to delete, whatever their rank ({@link openSetSourceIds}). */
  protect?: ReadonlySet<string>;
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
  const protect = budget.protect ?? NOTHING_PROTECTED;
  const pending = listPrunableScans(db, keep).filter((id) => !protect.has(id));
  const batchSize = budget.batchSize ?? PRUNE_BATCH;
  let deleted = 0;
  let batches = 0;
  while (pending.length > 0) {
    if (budget.maxBatches !== undefined && batches >= budget.maxBatches) break;
    if (budget.budgetMs !== undefined && now() - started >= budget.budgetMs) break;
    deleted += deletePrunableScans(db, takePruneBatch(db, pending, batchSize), keep, protect);
    batches += 1;
  }
  return { deleted, remaining: pending.length, complete: pending.length === 0 };
}

/** Stack snapshots {@link pruneStackSnapshots} deletes per call. */
export const STACK_PRUNE_BATCH = 500;

/**
 * Deletes up to `limit` stack snapshots beyond the newest
 * {@link STACK_SNAPSHOTS_KEPT} per project, in one short write transaction,
 * and says how many such rows are left. New rows are pruned on insert
 * (`stackRepo.ts`); this clears what was written before that, a batch per
 * server start.
 */
export function pruneStackSnapshots(db: DB, limit = STACK_PRUNE_BATCH): { deleted: number; remaining: number } {
  return db.transaction(() => {
    const excess = db
      .prepare<[number], { id: number }>(
        `SELECT id FROM (
           SELECT id, ROW_NUMBER() OVER (PARTITION BY project_path ORDER BY captured_at DESC, id DESC) AS rn
           FROM stack_snapshots
         ) WHERE rn > ? ORDER BY id`,
      )
      .all(STACK_SNAPSHOTS_KEPT)
      .map((r) => r.id);
    const batch = excess.slice(0, Math.max(0, limit));
    let deleted = 0;
    for (let i = 0; i < batch.length; i += 400) {
      const chunk = batch.slice(i, i + 400);
      deleted += db
        .prepare<number[]>(`DELETE FROM stack_snapshots WHERE id IN (${chunk.map(() => '?').join(', ')})`)
        .run(...chunk).changes;
    }
    return { deleted, remaining: excess.length - deleted };
  })();
}

/**
 * The scans each project's CURRENT open set reads from (`history/openSet.ts`
 * `sources`: every slot's source and every older scan it carries findings
 * forward from), and the orchestrated parent of each — for the projects of
 * `candidates` only, the prunable scans, so a start with nothing prunable
 * reads no open set at all.
 *
 * Why: ranking alone cannot see a carry. A newer scan that ran PARTLY
 * (Semgrep failed beside an ok Bandit; Trivy broken beside an ok npm audit;
 * a security_scan_full whose sast child did) is usable and ranks like any
 * other, while the open set still reads the older scan for the findings the
 * newer ones did not measure again. Fifty such runs evicted the only scan
 * holding them — risk 18 -> 8, open 1 -> 0. Measured cost: see the commit
 * that added this and CHANGELOG (the open set per candidate project, once
 * per start, inside retention's work budget).
 */
export function openSetSourceIds(storage: Storage, candidates: readonly string[]): Set<string> {
  const protect = new Set<string>();
  if (candidates.length === 0) return protect;
  const db = storage.rawHandle();
  const projects = new Set<string>();
  for (let i = 0; i < candidates.length; i += 400) {
    const chunk = candidates.slice(i, i + 400);
    for (const row of db
      .prepare<string[], { p: string }>(`SELECT DISTINCT project_path AS p FROM scans WHERE id IN (${chunk.map(() => '?').join(', ')})`)
      .all(...chunk)) {
      projects.add(row.p);
    }
  }
  for (const project of projects) {
    for (const source of openSetForProject(storage, project).sources) {
      protect.add(source.scan_id);
      const parent = storage.scans.getById(source.scan_id)?.meta?.['parent_scan_id'];
      if (typeof parent === 'string') protect.add(parent);
    }
  }
  return protect;
}

/**
 * {@link pruneScans} for a whole `Storage`: never deletes a scan the open
 * set of its project reads from ({@link openSetSourceIds}).
 */
export function pruneScansFor(storage: Storage, keep: number, budget: PruneBudget = {}): PruneResult {
  const db = storage.rawHandle();
  const protect = openSetSourceIds(storage, listPrunableScans(db, keep));
  return pruneScans(db, keep, { ...budget, protect });
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
  storage: Storage,
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
  let protect: ReadonlySet<string> = NOTHING_PROTECTED;
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
      if (pending === undefined) {
        // Once per start, in the first tick: the stack snapshots written
        // before they were pruned on insert, one bounded batch.
        const stack = pruneStackSnapshots(db);
        if (stack.deleted > 0) {
          log(
            `pruned ${stack.deleted} stack snapshot(s) beyond the newest ${STACK_SNAPSHOTS_KEPT} per project` +
              (stack.remaining > 0 ? `; ${stack.remaining} left for the next start` : ''),
          );
        }
      }
      if (pending === undefined) {
        // Once per start: what each candidate's project's open set reads
        // from is never deleted (openSetSourceIds). Re-read per start — a
        // scan the set stops reading goes at the next one.
        const listed = listPrunableScans(db, limit.keep);
        protect = openSetSourceIds(storage, listed);
        pending = listed.filter((id) => !protect.has(id));
      }
      deleted += deletePrunableScans(db, takePruneBatch(db, pending, batchSize), limit.keep, protect);
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

// ---- Stored project paths in their canonical spelling ---------------------

/**
 * Rewrites `suppressions.project_path` and `baselines.project_path` to the
 * canonical spelling of the directory they name (`platform/projectPath.ts
 * #canonicalPath`) — the spelling every scan has been stored under since
 * 3.0.0. Returns how many rows changed. Idempotent: a second run finds
 * nothing to do.
 *
 * 2.0.0 stored `resolve(input)`: `c:\Users\…`, with the drive letter as the
 * host typed it. Migration 011 scoped each legacy suppression to the path of
 * the scan that reported its finding, and 008 each baseline to its scan's:
 * both got that spelling. Every reader compares a project exactly, so after
 * the upgrade those suppressions stopped applying and those baselines were
 * never found (reproduced with the v2.0.0 tag's own storage code seeding
 * the database).
 *
 * A row is rewritten only when its path names an existing directory, the
 * canonical spelling differs, and NO component of the path is a symbolic
 * link or junction: case, the drive letter, an 8.3 short name, separators —
 * spellings of one directory entry that cannot come to mean another. A link
 * can: `~/work/current` repointed from project A to project B would move A's
 * suppressions onto B. So no row is ever merged into a different project; a
 * path that no longer exists, or goes through a link, is left as it is.
 * Scan rows are not touched (history keeps the spelling it was measured
 * under), and neither is anything else keyed by project.
 */
export function canonicalizeStoredProjectPaths(db: DB): number {
  const stored = db
    .prepare<[], { p: string }>(
      `SELECT project_path AS p FROM suppressions WHERE project_path IS NOT NULL
       UNION
       SELECT project_path AS p FROM baselines WHERE project_path IS NOT NULL`,
    )
    .all()
    .map((r) => r.p);
  const renames: Array<[string, string]> = [];
  for (const path of stored) {
    const canonical = spellingOnlyCanonical(path);
    if (canonical !== null) renames.push([path, canonical]);
  }
  if (renames.length === 0) return 0;
  return db.transaction((): number => {
    let changed = 0;
    for (const [from, to] of renames) {
      changed += db.prepare<[string, string]>('UPDATE suppressions SET project_path = ? WHERE project_path = ?').run(to, from).changes;
      changed += db.prepare<[string, string]>('UPDATE baselines SET project_path = ? WHERE project_path = ?').run(to, from).changes;
    }
    return changed;
  })();
}

/** Runs {@link canonicalizeStoredProjectPaths} at startup; logs, never throws. */
export function canonicalizeProjectPathsAtStartup(storage: MaintenanceTarget, log: (line: string) => void): void {
  try {
    const changed = canonicalizeStoredProjectPaths(storage.rawHandle());
    if (changed > 0) log(`rewrote ${changed} suppression/baseline row(s) to the canonical project path spelling`);
  } catch (error) {
    log(`project path spelling step failed (continuing): ${describe(error)}`);
  }
}
