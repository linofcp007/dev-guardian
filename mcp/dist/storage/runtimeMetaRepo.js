/**
 * Runtime-meta repository — small key-value store for things the server
 * decided once and wants to reuse on the next boot.
 *
 * Current users: shell choice (probed once on Windows, then cached).
 */
import { nowIso } from './repoUtil.js';
export class RuntimeMetaRepo {
    upsertStmt;
    getStmt;
    deleteStmt;
    constructor(db) {
        this.upsertStmt = db.prepare(`
      INSERT INTO runtime_meta (key, value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `);
        this.getStmt = db.prepare(`SELECT * FROM runtime_meta WHERE key = ?`);
        this.deleteStmt = db.prepare(`DELETE FROM runtime_meta WHERE key = ?`);
    }
    set(key, value) {
        this.upsertStmt.run(key, value, nowIso());
    }
    setJson(key, value) {
        this.set(key, JSON.stringify(value));
    }
    get(key) {
        const row = this.getStmt.get(key);
        return row?.value ?? null;
    }
    getJson(key) {
        const raw = this.get(key);
        if (raw === null)
            return null;
        try {
            return JSON.parse(raw);
        }
        catch {
            return null;
        }
    }
    delete(key) {
        this.deleteStmt.run(key);
    }
}
//# sourceMappingURL=runtimeMetaRepo.js.map