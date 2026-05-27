/**
 * Stack-snapshots repository.
 *
 * Each invocation of the `detect_stack` tool persists one row here. The
 * resource `guardian://stack` returns the latest snapshot; the diff over
 * time is exposed via `listRecent()` should a future tool want to surface
 * "your stack changed on date X".
 */
import { nowIso, parseJsonObject } from './repoUtil.js';
export class StackRepo {
    insertStmt;
    getLatestStmt;
    listRecentStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO stack_snapshots (project_path, captured_at, json)
      VALUES (?, ?, ?)
    `);
        this.getLatestStmt = db.prepare(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT 1
    `);
        this.listRecentStmt = db.prepare(`
      SELECT * FROM stack_snapshots ORDER BY captured_at DESC LIMIT ?
    `);
    }
    insert(input) {
        const capturedAt = nowIso();
        const json = JSON.stringify(input.snapshot);
        const info = this.insertStmt.run(input.project_path, capturedAt, json);
        return {
            id: Number(info.lastInsertRowid),
            project_path: input.project_path,
            captured_at: capturedAt,
            snapshot: input.snapshot,
        };
    }
    getLatest() {
        const row = this.getLatestStmt.get();
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