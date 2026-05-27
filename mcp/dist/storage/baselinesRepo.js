/**
 * Baselines repository.
 *
 * Only one baseline is "active" at any time — the most recently inserted row.
 * Older rows are kept for audit/history; the resource layer reads the latest
 * via `getActive()`.
 */
import { nowIso } from './repoUtil.js';
export class BaselinesRepo {
    insertStmt;
    getActiveStmt;
    listAllStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO baselines (scan_id, set_at, note) VALUES (?, ?, ?)
    `);
        this.getActiveStmt = db.prepare(`
      SELECT * FROM baselines ORDER BY id DESC LIMIT 1
    `);
        this.listAllStmt = db.prepare(`
      SELECT * FROM baselines ORDER BY id DESC
    `);
    }
    set(input) {
        const setAt = nowIso();
        const info = this.insertStmt.run(input.scan_id, setAt, input.note ?? null);
        const b = {
            id: Number(info.lastInsertRowid),
            scan_id: input.scan_id,
            set_at: setAt,
        };
        if (input.note !== undefined)
            b.note = input.note;
        return b;
    }
    getActive() {
        const row = this.getActiveStmt.get();
        return row ? rowToBaseline(row) : null;
    }
    listAll() {
        return this.listAllStmt.all().map(rowToBaseline);
    }
}
function rowToBaseline(row) {
    const b = { id: row.id, scan_id: row.scan_id, set_at: row.set_at };
    if (row.note !== null)
        b.note = row.note;
    return b;
}
//# sourceMappingURL=baselinesRepo.js.map