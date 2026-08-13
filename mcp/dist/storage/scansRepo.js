/**
 * Scans repository — one row per scan invocation.
 *
 * Responsibilities live strictly at the persistence layer: every method here
 * maps directly to a SQL operation. Cache lookup, transition logic, and the
 * tree-hash freshness window all belong to the scan-tool factory upstream
 * (see [.specs/dev-guardian-mcp/design.md] → "Tool invocation flow").
 */
import { nowIso, parseJsonArray } from './repoUtil.js';
export class ScansRepo {
    insertStmt;
    finalizeStmt;
    markCancelledStmt;
    reapRunningStmt;
    getByIdStmt;
    getLatestStmt;
    getLatestForProjectStmt;
    listHistoryStmt;
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
        // a future migration drops millisecond resolution.
        this.getLatestStmt = db.prepare(`
      SELECT * FROM scans
      WHERE status = 'completed'
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
        this.listHistoryStmt = db.prepare(`
      SELECT * FROM scans
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
    listHistory(limit = 50) {
        return this.listHistoryStmt.all(limit).map(rowToRecord);
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