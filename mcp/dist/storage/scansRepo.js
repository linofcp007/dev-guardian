/**
 * Scans repository — one row per scan invocation.
 *
 * Responsibilities live strictly at the persistence layer: every method here
 * maps directly to a SQL operation. Cache lookup, transition logic, and the
 * tree-hash freshness window all belong to the scan-tool factory upstream
 * (see [.specs/dev-guardian-mcp/design.md] → "Tool invocation flow").
 *
 * **`getLatestStmt` and `listHistoryStmt` (the UNSCOPED "any project" queries)
 * exclude `create_fix_pr`'s own verification re-scans** — see
 * `findingsRepo.ts`'s own module comment (task-7-review.md I3) for the full
 * reasoning; the same contamination, the same fix, the same reason
 * `WORKTREE_PATH_EXCLUSION` is inlined here as a literal rather than
 * imported from `fixpr/worktree.ts` — see `findingsRepo.ts`'s own module
 * comment for why it is wrapped in `%` on both sides, not just trailing.
 * **`listHistoryStmt` missed this exclusion when I3 first landed** — only
 * `getLatestStmt` here was covered, and `listHistoryStmt` shipped with no
 * `WHERE` clause at all. `risk_score` does not read `getLatest()`; it finds
 * its CVE source via `listHistory(50).find(...)`
 * (`tools/riskScore.ts#findLatestOfType`), so a dry run's own verification
 * re-scan could still win that unscoped search and silently zero out the
 * project's real CVE count — measured: a real score of 44 (high) read as 31
 * (medium), `active_cves` 5 read as 0, and it did not self-correct, because
 * the contaminating row is never deleted. `diff_scans` (`previous` scan
 * lookup) and `regression_alert` (fallback baseline) reach the exact same
 * unscoped list through this same method and are fixed by this same
 * statement — see the final review, 2026-08-16-create-fix-pr, finding C1.
 * `getLatestForProject` / `listHistoryForProject` need no such exclusion:
 * they are already scoped to an exact `project_path`, which a worktree's
 * path can never equal.
 */
import { nowIso, parseJsonArray } from './repoUtil.js';
/** See the module comment. Wraps `fixpr/worktree.ts`'s `WORKTREE_DIR_PREFIX`. */
const WORKTREE_PATH_EXCLUSION = '%guardian-fixpr-wt-%';
export class ScansRepo {
    insertStmt;
    finalizeStmt;
    markCancelledStmt;
    reapRunningStmt;
    getByIdStmt;
    getLatestStmt;
    getLatestForProjectStmt;
    listHistoryStmt;
    listHistoryForProjectStmt;
    findCacheStmt;
    attachCacheStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO scans (
        id, scan_type, project_path, tree_hash,
        started_at, status, tools_run, missing_tools, report_dir, meta
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
        this.finalizeStmt = db.prepare(`
      UPDATE scans
      SET status = ?, finished_at = ?, tools_run = ?, missing_tools = ?,
          report_dir = COALESCE(?, report_dir), error = ?,
          meta = COALESCE(?, meta)
      WHERE id = ?
    `);
        this.markCancelledStmt = db.prepare(`
      UPDATE scans
      SET status = 'cancelled', finished_at = ?
      WHERE id = ? AND status = 'running'
    `);
        this.reapRunningStmt = db.prepare(`
      UPDATE scans
      SET status = 'failed', finished_at = ?, error = 'reaped on startup'
      WHERE status = 'running'
    `);
        this.getByIdStmt = db.prepare(`SELECT * FROM scans WHERE id = ?`);
        // rowid DESC is a tiebreaker for scans inserted in the same millisecond
        // (real risk on fast CI). It also guarantees "later insert wins" even if
        // a future migration drops millisecond resolution. `project_path NOT
        // LIKE …`: see this file's own module comment (task-7-review.md I3).
        this.getLatestStmt = db.prepare(`
      SELECT * FROM scans
      WHERE status = 'completed' AND project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);
        // Identical predicate to getLatestStmt above, plus `project_path = ?` on
        // the WHERE clause — same relationship as surfaceRepo's / findingsRepo's
        // getLatestForProject / listOpenForProject siblings.
        this.getLatestForProjectStmt = db.prepare(`
      SELECT * FROM scans
      WHERE status = 'completed' AND project_path = ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);
        // No `status` filter — listHistory's contract is "any status" (a caller
        // that needs only completed scans filters that in JS; see
        // listHistoryForProjectStmt's own comment below). `project_path NOT
        // LIKE …` excludes create_fix_pr's own verification re-scans, the same
        // exclusion and the same reason as getLatestStmt above — see this file's
        // own module comment (task-7-review.md I3; this statement's own gap was
        // finding C1 of the final review, 2026-08-16-create-fix-pr).
        this.listHistoryStmt = db.prepare(`
      SELECT * FROM scans
      WHERE project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
      ORDER BY started_at DESC, rowid DESC
      LIMIT ?
    `);
        // Scoped to one project via `project_path = ?` — no `NOT LIKE` exclusion
        // needed, same reasoning as getLatestForProjectStmt's own relationship to
        // getLatestStmt above: an exact `project_path` match can never equal a
        // worktree's path, so the exclusion would be redundant. No `status`
        // filter either, matching listHistory's own "any status" contract
        // exactly: callers that need only completed scans (e.g. the dashboard
        // snapshot's "previous scan of the same type") filter that in JS, the
        // same way listHistory's own callers already do.
        this.listHistoryForProjectStmt = db.prepare(`
      SELECT * FROM scans
      WHERE project_path = ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT ?
    `);
        this.findCacheStmt = db.prepare(`
      SELECT * FROM scans
      WHERE tree_hash = ? AND scan_type = ? AND status = 'completed' AND started_at >= ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);
        this.attachCacheStmt = db.prepare(`
      INSERT OR REPLACE INTO tree_cache (tree_hash, scan_id, scan_type, computed_at)
      VALUES (?, ?, ?, ?)
    `);
    }
    insert(input) {
        const started = nowIso();
        this.insertStmt.run(input.scan_id, input.scan_type, input.project_path, input.tree_hash, started, 'running', '[]', '[]', input.report_dir ?? null, JSON.stringify(input.meta ?? {}));
        return {
            scan_id: input.scan_id,
            scan_type: input.scan_type,
            project_path: input.project_path,
            tree_hash: input.tree_hash,
            started_at: started,
            finished_at: null,
            status: 'running',
            tools_run: [],
            missing_tools: [],
            report_paths: input.report_dir ? [input.report_dir] : [],
        };
    }
    finalize(input) {
        this.finalizeStmt.run(input.status, nowIso(), JSON.stringify(input.tools_run), JSON.stringify(input.missing_tools), input.report_dir ?? null, input.error ?? null, input.meta !== undefined ? JSON.stringify(input.meta) : null, input.scan_id);
    }
    markCancelled(scanId) {
        this.markCancelledStmt.run(nowIso(), scanId);
    }
    /**
     * Sweeps any scan left in `running` state by a previous server lifetime
     * (crash, kill -9). Called once on startup.
     */
    reapRunning() {
        const info = this.reapRunningStmt.run(nowIso());
        return info.changes;
    }
    getById(scanId) {
        const row = this.getByIdStmt.get(scanId);
        return row ? rowToRecord(row) : null;
    }
    /**
     * The latest completed scan in the WHOLE database, from ANY project — no
     * `project_path` filter. Correct for a caller with no project in scope
     * (most resources and tools here take no `project_path` input at all and
     * report on "whatever this server last scanned"). A caller that DID
     * resolve a `project_path` and attributes something to the scan it names
     * (e.g. `validate_finding`'s `findings_from_scan`) must use
     * `getLatestForProject` instead — see that method and
     * `findingsRepo.ts`'s `listOpen`/`listOpenForProject` for the identical
     * split.
     */
    getLatest() {
        const row = this.getLatestStmt.get();
        return row ? rowToRecord(row) : null;
    }
    /** The latest completed scan FOR ONE project. Mirrors `surfaceRepo.ts`'s
     *  `getLatestForProject` and `findingsRepo.ts`'s `listOpenForProject`. */
    getLatestForProject(projectPath) {
        const row = this.getLatestForProjectStmt.get(projectPath);
        return row ? rowToRecord(row) : null;
    }
    /**
     * Scan history across the WHOLE database, from ANY project — no
     * `project_path` filter and no `status` filter (unlike `getLatest`, every
     * status is included; see `listHistoryStmt`'s own comment). Excludes
     * `create_fix_pr`'s own verification re-scans, the same as `getLatest` —
     * see this file's own module comment. A caller that DID resolve a
     * `project_path` must use `listHistoryForProject` instead, for the same
     * reason `getLatest`'s own doc comment gives.
     */
    listHistory(limit = 50) {
        return this.listHistoryStmt.all(limit).map(rowToRecord);
    }
    /**
     * `listHistory`, scoped to one project — never all scans filtered in JS,
     * which would silently truncate at whatever `limit` the caller used before
     * the JS-side filter even ran. Mirrors `getLatestForProject`'s relationship
     * to `getLatest`: same "this project" vs. "any project" split, for a
     * history list instead of a single latest row.
     */
    listHistoryForProject(projectPath, limit = 50) {
        return this.listHistoryForProjectStmt.all(projectPath, limit).map(rowToRecord);
    }
    /**
     * Returns the most recent completed scan of the given type whose tree_hash
     * matches and which started no earlier than `freshThreshold`. The factory
     * uses this to honour US-8 AC-2 (5-minute cache window).
     */
    findCacheHit(args) {
        const row = this.findCacheStmt.get(args.tree_hash, args.scan_type, args.freshThreshold);
        return row ? rowToRecord(row) : null;
    }
    attachTreeCache(args) {
        this.attachCacheStmt.run(args.tree_hash, args.scan_id, args.scan_type, nowIso());
    }
}
function rowToRecord(row) {
    const record = {
        scan_id: row.id,
        scan_type: row.scan_type,
        project_path: row.project_path,
        tree_hash: row.tree_hash,
        started_at: row.started_at,
        finished_at: row.finished_at,
        status: row.status,
        tools_run: parseJsonArray(row.tools_run),
        missing_tools: parseJsonArray(row.missing_tools),
        report_paths: row.report_dir ? [row.report_dir] : [],
    };
    if (row.cached_from)
        record.cached_from = row.cached_from;
    if (row.meta && row.meta !== '{}') {
        try {
            record.meta = JSON.parse(row.meta);
        }
        catch {
            /* ignore malformed meta */
        }
    }
    return record;
}
//# sourceMappingURL=scansRepo.js.map