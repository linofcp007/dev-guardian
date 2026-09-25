/**
 * Baselines repository.
 *
 * A baseline belongs to one project and one scan type (migration 008): the
 * active baseline of a project is its most recently inserted row, and a
 * reader that compares scans asks for the active baseline OF A TYPE, so a
 * SAST scan is never measured against a secrets baseline. Older rows are
 * kept for audit/history.
 *
 * `getActive()` — the newest row in the whole database, any project — is
 * kept only for callers that have no project in scope; every reader that
 * has one uses `getActiveForProject`.
 *
 * Rows an older build inserts without the two columns are read through the
 * baseline's scan (`COALESCE` over the join), so they still belong to their
 * project.
 */
import { nowIso } from './repoUtil.js';
const SELECT_SCOPED = `
  SELECT b.id, b.scan_id, b.set_at, b.note,
         COALESCE(b.project_path, s.project_path) AS project_path,
         COALESCE(b.scan_type, s.scan_type) AS scan_type
  FROM baselines b LEFT JOIN scans s ON s.id = b.scan_id
`;
export class BaselinesRepo {
    scanScopeStmt;
    insertStmt;
    getActiveStmt;
    getActiveForProjectStmt;
    getActiveForProjectTypeStmt;
    listAllStmt;
    constructor(db) {
        this.scanScopeStmt = db.prepare(`SELECT project_path, scan_type FROM scans WHERE id = ?`);
        this.insertStmt = db.prepare(`
      INSERT INTO baselines (scan_id, set_at, note, project_path, scan_type) VALUES (?, ?, ?, ?, ?)
    `);
        this.getActiveStmt = db.prepare(`${SELECT_SCOPED} ORDER BY b.id DESC LIMIT 1`);
        this.getActiveForProjectStmt = db.prepare(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ?
      ORDER BY b.id DESC LIMIT 1
    `);
        this.getActiveForProjectTypeStmt = db.prepare(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND COALESCE(b.scan_type, s.scan_type) = ?
      ORDER BY b.id DESC LIMIT 1
    `);
        this.listAllStmt = db.prepare(`${SELECT_SCOPED} ORDER BY b.id DESC`);
    }
    /** Records the scan's own project and type beside it. */
    set(input) {
        const setAt = nowIso();
        const scope = this.scanScopeStmt.get(input.scan_id);
        // An unknown scan_id still reaches the INSERT, where the foreign key
        // rejects it — the same error this method always raised.
        const info = this.insertStmt.run(input.scan_id, setAt, input.note ?? null, scope?.project_path ?? null, scope?.scan_type ?? null);
        const b = {
            id: Number(info.lastInsertRowid),
            scan_id: input.scan_id,
            set_at: setAt,
            project_path: scope?.project_path ?? null,
            scan_type: (scope?.scan_type ?? null),
        };
        if (input.note !== undefined)
            b.note = input.note;
        return b;
    }
    /** The newest baseline in the database, from ANY project — see the module comment. */
    getActive() {
        const row = this.getActiveStmt.get();
        return row ? rowToBaseline(row) : null;
    }
    /** The newest baseline of one project — of one scan type, when given. */
    getActiveForProject(projectPath, scanType) {
        const row = scanType === undefined
            ? this.getActiveForProjectStmt.get(projectPath)
            : this.getActiveForProjectTypeStmt.get(projectPath, scanType);
        return row ? rowToBaseline(row) : null;
    }
    listAll() {
        return this.listAllStmt.all().map(rowToBaseline);
    }
}
function rowToBaseline(row) {
    const b = {
        id: row.id,
        scan_id: row.scan_id,
        set_at: row.set_at,
        project_path: row.project_path,
        scan_type: row.scan_type,
    };
    if (row.note !== null)
        b.note = row.note;
    return b;
}
//# sourceMappingURL=baselinesRepo.js.map