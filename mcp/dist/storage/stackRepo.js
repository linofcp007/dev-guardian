/**
 * Stack-snapshots repository.
 *
 * Each invocation of the `detect_stack` tool persists one row here. The
 * resource `guardian://stack` returns the latest snapshot; the diff over
 * time is exposed via `listRecent()` should a future tool want to surface
 * "your stack changed on date X".
 */
import { nowIso, parseJsonObject } from './repoUtil.js';
/**
 * Snapshots kept per project — every reader asks for the newest one of ONE
 * project (`getLatestForProject`). The table grew with every `detect_stack`
 * run; a few are kept so "the stack changed on date X" stays answerable.
 * Pruned on insert, as `surface_snapshots` is, and a backlog written before
 * this existed by `maintenance.ts#pruneStackSnapshots` in the background.
 */
export const STACK_SNAPSHOTS_KEPT = 10;
export class StackRepo {
    db;
    insertStmt;
    getLatestStmt;
    listRecentStmt;
    getLatestForProjectStmt;
    pruneStmt;
    constructor(db) {
        this.db = db;
        this.insertStmt = db.prepare(`
      INSERT INTO stack_snapshots (project_path, captured_at, json)
      VALUES (?, ?, ?)
    `);
        this.pruneStmt = db.prepare(`
      DELETE FROM stack_snapshots
      WHERE project_path = ?
        AND id NOT IN (
          SELECT id FROM stack_snapshots WHERE project_path = ?
          ORDER BY captured_at DESC, id DESC LIMIT ?
        )
    `);
        this.getLatestStmt = db.prepare(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT 1
    `);
        this.getLatestForProjectStmt = db.prepare(`
      SELECT * FROM stack_snapshots WHERE project_path = ? ORDER BY captured_at DESC, id DESC LIMIT 1
    `);
        this.listRecentStmt = db.prepare(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT ?
    `);
    }
    insert(input) {
        const capturedAt = nowIso();
        const json = JSON.stringify(input.snapshot);
        // One transaction: the new row and its project's prune (after the
        // insert, so the new row always survives its own prune).
        const info = this.db.transaction(() => {
            const inserted = this.insertStmt.run(input.project_path, capturedAt, json);
            this.pruneStmt.run(input.project_path, input.project_path, STACK_SNAPSHOTS_KEPT);
            return inserted;
        })();
        return {
            id: Number(info.lastInsertRowid),
            project_path: input.project_path,
            captured_at: capturedAt,
            snapshot: input.snapshot,
        };
    }
    /**
     * The newest snapshot of ANY project. No production caller since Task 24:
     * `bug_hunt`, `audit_executive`, `init_project`, `map_attack_surface` and
     * `observability_setup` each took ANOTHER project's languages from it
     * whenever that project was detected last. Use `getLatestForProject`.
     */
    getLatest() {
        const row = this.getLatestStmt.get();
        return row ? rowToSnapshot(row) : null;
    }
    /** The newest snapshot of ONE project — what `guardian://stack` serves. */
    getLatestForProject(projectPath) {
        const row = this.getLatestForProjectStmt.get(projectPath);
        return row ? rowToSnapshot(row) : null;
    }
    listRecent(limit = 10) {
        return this.listRecentStmt.all(limit).map(rowToSnapshot);
    }
}
function rowToSnapshot(row) {
    return {
        id: row.id,
        project_path: row.project_path,
        captured_at: row.captured_at,
        snapshot: parseJsonObject(row.json, {}),
    };
}
//# sourceMappingURL=stackRepo.js.map