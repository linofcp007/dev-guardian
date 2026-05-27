/**
 * Suppressions repository — user-marked false positives.
 *
 * A suppression scopes to a finding fingerprint. While active (NULL
 * expires_at, or expires_at > now), the matching finding is hidden from the
 * `findings/open` and `findings/by-severity/*` resources. The findings table
 * itself remains untouched so historical scans stay intact and the
 * suppression can be lifted later by deleting (or letting expire) the row.
 */
import { nowIso } from './repoUtil.js';
export class SuppressionsRepo {
    insertStmt;
    listActiveStmt;
    isSuppressedStmt;
    listForFingerprintStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO suppressions (
        finding_fingerprint, reason, created_at, expires_at, created_by
      )
      VALUES (?, ?, ?, ?, ?)
    `);
        this.listActiveStmt = db.prepare(`
      SELECT * FROM suppressions
      WHERE expires_at IS NULL OR expires_at > ?
      ORDER BY created_at DESC
    `);
        this.isSuppressedStmt = db.prepare(`
      SELECT COUNT(*) AS n FROM suppressions
      WHERE finding_fingerprint = ?
        AND (expires_at IS NULL OR expires_at > ?)
    `);
        this.listForFingerprintStmt = db.prepare(`
      SELECT * FROM suppressions WHERE finding_fingerprint = ?
      ORDER BY created_at DESC
    `);
    }
    insert(input) {
        const info = this.insertStmt.run(input.finding_fingerprint, input.reason, nowIso(), input.expires_at ?? null, input.created_by ?? null);
        return Number(info.lastInsertRowid);
    }
    listActive() {
        return this.listActiveStmt.all(nowIso()).map(rowToSuppression);
    }
    isSuppressed(fingerprint) {
        const row = this.isSuppressedStmt.get(fingerprint, nowIso());
        return (row?.n ?? 0) > 0;
    }
    listForFingerprint(fingerprint) {
        return this.listForFingerprintStmt.all(fingerprint).map(rowToSuppression);
    }
}
function rowToSuppression(row) {
    const s = {
        id: row.id,
        finding_fingerprint: row.finding_fingerprint,
        reason: row.reason,
        created_at: row.created_at,
    };
    if (row.expires_at !== null)
        s.expires_at = row.expires_at;
    if (row.created_by !== null)
        s.created_by = row.created_by;
    return s;
}
//# sourceMappingURL=suppressionsRepo.js.map