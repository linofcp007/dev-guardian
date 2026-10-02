/**
 * Baselines repository.
 *
 * A baseline belongs to one project and one scan type (migration 008): the
 * active baseline of a project is its most recently inserted row, and a
 * reader that compares scans asks for the active baseline OF A TYPE, so a
 * SAST scan is never measured against a secrets baseline. Older rows are
 * kept for audit/history.
 *
 * Asked for no type, `getActive` and `getActiveForProject` answer with native
 * baselines only (`slot IS NULL`): an imported log's baseline is read by
 * asking for its type and slot, so baselining an import never changes what
 * the readers that name no type (risk score, dashboard, resources) see.
 *
 * `getActive()` — the newest row in the whole database, any project — is
 * kept only for callers that have no project in scope; every reader that
 * has one uses `getActiveForProject`.
 *
 * An imported SARIF log adds a third coordinate (migration 016): `slot`, the
 * open-set slot of the baseline's scan — `sarif_import:<source tool>` — so a
 * baseline of CodeQL's import is not replaced by Snyk's. Every other scan
 * type leaves it NULL and keeps its per-(project, type) baseline.
 *
 * Rows an older build inserts without the two columns are read through the
 * baseline's scan (`COALESCE` over the join), so they still belong to their
 * project.
 */
import { sarifSlotOfMeta } from './slots.js';
import { nowIso } from './repoUtil.js';
const SELECT_SCOPED = `
  SELECT b.id, b.scan_id, b.set_at, b.note,
         COALESCE(b.project_path, s.project_path) AS project_path,
         COALESCE(b.scan_type, s.scan_type) AS scan_type,
         b.slot AS slot
  FROM baselines b LEFT JOIN scans s ON s.id = b.scan_id
`;
export class BaselinesRepo {
    scanScopeStmt;
    insertStmt;
    getActiveStmt;
    getActiveForProjectStmt;
    getActiveForProjectTypeStmt;
    getActiveForProjectSlotStmt;
    listAllStmt;
    constructor(db) {
        this.scanScopeStmt = db.prepare(`SELECT project_path, scan_type, meta FROM scans WHERE id = ?`);
        this.insertStmt = db.prepare(`
      INSERT INTO baselines (scan_id, set_at, note, project_path, scan_type, slot) VALUES (?, ?, ?, ?, ?, ?)
    `);
        this.getActiveStmt = db.prepare(`${SELECT_SCOPED} WHERE b.slot IS NULL ORDER BY b.id DESC LIMIT 1`);
        this.getActiveForProjectStmt = db.prepare(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND b.slot IS NULL
      ORDER BY b.id DESC LIMIT 1
    `);
        this.getActiveForProjectTypeStmt = db.prepare(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND COALESCE(b.scan_type, s.scan_type) = ?
      ORDER BY b.id DESC LIMIT 1
    `);
        this.getActiveForProjectSlotStmt = db.prepare(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND COALESCE(b.scan_type, s.scan_type) = ? AND b.slot = ?
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
        const slot = scope?.scan_type === 'sarif_import' ? sarifSlotOfMeta(parseMeta(scope.meta)) : null;
        const info = this.insertStmt.run(input.scan_id, setAt, input.note ?? null, scope?.project_path ?? null, scope?.scan_type ?? null, slot);
        const b = {
            id: Number(info.lastInsertRowid),
            scan_id: input.scan_id,
            set_at: setAt,
            project_path: scope?.project_path ?? null,
            scan_type: (scope?.scan_type ?? null),
        };
        if (input.note !== undefined)
            b.note = input.note;
        if (slot !== null)
            b.slot = slot;
        return b;
    }
    /** The newest baseline in the database, from ANY project — see the module comment. */
    getActive() {
        const row = this.getActiveStmt.get();
        return row ? rowToBaseline(row) : null;
    }
    /**
     * The newest baseline of one project — of one scan type, when given; of one
     * slot of that type (an import's source tool, `sarif_import:<tool>`), when given too.
     */
    getActiveForProject(projectPath, scanType, slot) {
        const row = scanType === undefined
            ? this.getActiveForProjectStmt.get(projectPath)
            : slot === undefined
                ? this.getActiveForProjectTypeStmt.get(projectPath, scanType)
                : this.getActiveForProjectSlotStmt.get(projectPath, scanType, slot);
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
    if (row.slot !== null)
        b.slot = row.slot;
    return b;
}
function parseMeta(text) {
    try {
        const v = JSON.parse(text);
        return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : undefined;
    }
    catch {
        return undefined; // a scan whose meta is unreadable has no source tool: the empty-name slot
    }
}
//# sourceMappingURL=baselinesRepo.js.map