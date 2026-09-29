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
 * `wp_vuln_check`) are counted apart from whole-project ones: N of each, so
 * pre-commit runs can never push out the scan the open set reads. What
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
import { lstatSync, statSync } from 'node:fs';
import { isAbsolute, join, parse, resolve, sep } from 'node:path';
import { canonicalPath } from '../platform/projectPath.js';
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
/** Reads `GUARDIAN_RETENTION_SCANS`: a non-negative integer, or the default. */
export function resolveRetentionLimit(raw) {
    const value = raw?.trim() ?? '';
    if (value === '')
        return { keep: DEFAULT_RETENTION_SCANS };
    if (/^\d+$/.test(value))
        return { keep: Number.parseInt(value, 10) };
    return {
        keep: DEFAULT_RETENTION_SCANS,
        warning: `GUARDIAN_RETENTION_SCANS='${raw}' is not a non-negative integer; ` +
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
 * `candidates` restricts the ranking to the partitions of that many ids (the
 * `?` placeholders come right after `keep`'s, as `id IN (…)`), for the
 * re-check {@link deleteScans} makes under the write lock.
 */
function prunableSql(candidates) {
    const only = candidates > 0
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
               PARTITION BY project_path, scan_type, ${SCOPED_SQL}
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
export function listPrunableScans(db, keep) {
    if (!(keep > 0))
        return [];
    return db.prepare(PRUNABLE_SQL).all(keep).map((r) => r.id);
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
export function deletePrunableScans(db, ids, keep) {
    if (ids.length === 0 || !(keep > 0))
        return 0;
    return db.transaction(() => {
        const eligible = db
            .prepare(prunableSql(ids.length))
            .all(...ids, keep, ...ids)
            .map((r) => r.id);
        return deleteRows(db, eligible);
    })();
}
/**
 * Deletes `ids` — whatever their rank — and every row that points at them,
 * in ONE short write transaction; for a caller that removes a scan it wrote
 * itself (`create_fix_pr`'s worktree re-scan). Re-checks, under the lock,
 * that each is not protected: still running, a baseline, or part of a
 * baselined orchestrated run. Returns how many scans were deleted.
 */
export function deleteScans(db, ids) {
    if (ids.length === 0)
        return 0;
    return db.transaction(() => {
        const list = ids.map(() => '?').join(', ');
        const eligible = db
            .prepare(`SELECT id FROM scans WHERE id IN (${list}) AND NOT ${PROTECTED_SQL}`)
            .all(...ids)
            .map((r) => r.id);
        return deleteRows(db, eligible);
    })();
}
/** The deletes themselves; the caller holds the transaction. */
function deleteRows(db, eligible) {
    if (eligible.length === 0)
        return 0;
    const del = eligible.map(() => '?').join(', ');
    db.prepare(`DELETE FROM findings WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare(`DELETE FROM scan_cves WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare(`DELETE FROM tree_cache WHERE scan_id IN (${del})`).run(...eligible);
    db.prepare(`DELETE FROM cves WHERE first_seen_scan_id IN (${del}) OR last_seen_scan_id IN (${del})`).run(...eligible, ...eligible);
    return db.prepare(`DELETE FROM scans WHERE id IN (${del})`).run(...eligible).changes;
}
/**
 * Synchronous retention within a budget: lists the prunable scans once, then
 * deletes them batch by batch, each batch its own short write transaction,
 * until none are left or the budget is spent. The server does not call this
 * directly — it uses {@link scheduleRetention}, which spreads the same batches
 * over timer ticks.
 */
export function pruneScans(db, keep, budget = {}) {
    const now = budget.now ?? (() => performance.now());
    const started = now();
    const pending = listPrunableScans(db, keep);
    const batchSize = budget.batchSize ?? PRUNE_BATCH;
    let deleted = 0;
    let batches = 0;
    while (pending.length > 0) {
        if (budget.maxBatches !== undefined && batches >= budget.maxBatches)
            break;
        if (budget.budgetMs !== undefined && now() - started >= budget.budgetMs)
            break;
        deleted += deletePrunableScans(db, pending.splice(0, batchSize), keep);
        batches += 1;
    }
    return { deleted, remaining: pending.length, complete: pending.length === 0 };
}
/**
 * Fails scans whose owning process died (see `ScansRepo.reapRunning`). Runs
 * before the server connects; never throws.
 */
export function reapOrphanedScans(storage, log) {
    try {
        const reaped = storage.scans.reapRunning();
        if (reaped > 0)
            log(`reaped ${reaped} orphaned scan(s)`);
    }
    catch (error) {
        log(`reaper failed (continuing): ${describe(error)}`);
    }
}
const defaultDefer = (fn, ms) => {
    const timer = setTimeout(fn, ms);
    // Retention alone must never keep a process alive.
    timer.unref();
    return () => clearTimeout(timer);
};
/**
 * Starts retention in the background: after {@link RETENTION_START_DELAY_MS},
 * one batch per timer tick ({@link RETENTION_BATCH_GAP_MS} apart), until
 * nothing prunable is left or {@link RETENTION_BUDGET_MS} of work has been
 * spent — the rest waits for the next start. Logs what it did; logs and stops
 * on any error; never throws. Returns a function that cancels whatever has
 * not run yet (the server calls it on shutdown, before closing the database).
 */
export function scheduleRetention(storage, log, options = {}) {
    const limit = resolveRetentionLimit((options.env ?? process.env)['GUARDIAN_RETENTION_SCANS']);
    if (limit.warning !== undefined)
        log(limit.warning);
    if (limit.keep === 0)
        return () => { };
    const defer = options.defer ?? defaultDefer;
    const now = options.now ?? (() => performance.now());
    const budgetMs = options.budgetMs ?? RETENTION_BUDGET_MS;
    const batchSize = options.batchSize ?? PRUNE_BATCH;
    let cancelled = false;
    let cancelNext = () => { };
    let pending;
    let spent = 0;
    let deleted = 0;
    const finish = (left) => {
        if (deleted === 0 && left === 0)
            return;
        log(`pruned ${deleted} scan(s) beyond the newest ${limit.keep} per project and scan type` +
            (left > 0 ? `; ${left} left for the next start (retention budget ${budgetMs} ms)` : ''));
    };
    const tick = () => {
        if (cancelled)
            return;
        const t0 = now();
        let left;
        try {
            const db = storage.rawHandle();
            pending ??= listPrunableScans(db, limit.keep);
            deleted += deletePrunableScans(db, pending.splice(0, batchSize), limit.keep);
            left = pending.length;
        }
        catch (error) {
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
function describe(error) {
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
export function canonicalizeStoredProjectPaths(db) {
    const stored = db
        .prepare(`SELECT project_path AS p FROM suppressions WHERE project_path IS NOT NULL
       UNION
       SELECT project_path AS p FROM baselines WHERE project_path IS NOT NULL`)
        .all()
        .map((r) => r.p);
    const renames = [];
    for (const path of stored) {
        const canonical = spellingOnlyCanonical(path);
        if (canonical !== null)
            renames.push([path, canonical]);
    }
    if (renames.length === 0)
        return 0;
    return db.transaction(() => {
        let changed = 0;
        for (const [from, to] of renames) {
            changed += db.prepare('UPDATE suppressions SET project_path = ? WHERE project_path = ?').run(to, from).changes;
            changed += db.prepare('UPDATE baselines SET project_path = ? WHERE project_path = ?').run(to, from).changes;
        }
        return changed;
    })();
}
/**
 * The canonical spelling of `path` when it names an existing directory,
 * differs from it, and reaches it through no link; null otherwise.
 */
function spellingOnlyCanonical(path) {
    if (!isAbsolute(path))
        return null;
    try {
        if (!statSync(path).isDirectory())
            return null;
    }
    catch {
        return null;
    }
    const canonical = canonicalPath(path);
    if (canonical === path)
        return null;
    // Every component, from the root down, must be a real directory entry.
    const resolved = resolve(path);
    const root = parse(resolved).root;
    let current = root;
    for (const part of resolved.slice(root.length).split(sep).filter((s) => s !== '')) {
        current = join(current, part);
        try {
            if (lstatSync(current).isSymbolicLink())
                return null;
        }
        catch {
            return null;
        }
    }
    return canonical;
}
/** Runs {@link canonicalizeStoredProjectPaths} at startup; logs, never throws. */
export function canonicalizeProjectPathsAtStartup(storage, log) {
    try {
        const changed = canonicalizeStoredProjectPaths(storage.rawHandle());
        if (changed > 0)
            log(`rewrote ${changed} suppression/baseline row(s) to the canonical project path spelling`);
    }
    catch (error) {
        log(`project path spelling step failed (continuing): ${describe(error)}`);
    }
}
//# sourceMappingURL=maintenance.js.map