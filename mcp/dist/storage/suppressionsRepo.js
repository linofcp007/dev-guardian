/**
 * Suppressions repository — user-marked false positives.
 *
 * A suppression names a finding by its fingerprint and, since schema 7, by
 * its line-independent identity too (`fingerprint/findingIdentity.ts`). While
 * active (NULL expires_at, or expires_at > now), a finding that matches it on
 * EITHER key is hidden from the `findings/open` and `findings/by-severity/*`
 * resources. The fingerprint alone lapsed the moment a line was inserted above
 * the finding; the identity does not. The findings table itself remains
 * untouched so historical scans stay intact and the suppression can be lifted
 * later by deleting (or letting expire) the row.
 *
 * Since migration 011, a suppression also carries the `project_path` it
 * belongs to — the caller's own resolved project, at the moment
 * `suppress_finding` looked the target up. NULL means "matches every
 * project" (every row written before this column existed, and any row an
 * older build still inserts without it), never "no project": every method
 * here that reads or writes MORE than one suppression at a time by
 * fingerprint/identity applies `project_path IS NULL OR project_path = ?`
 * (`listActiveForRule`, `adoptIdentities`) — the same rule the readers that
 * actually hide findings apply (`findingsRepo.ts`'s `SUPPRESSION_MATCHES_F`,
 * `history/openSet.ts`'s `suppressionMatcher`). `isSuppressed` alone is
 * unscoped: it has no production caller left (its SQL predicate is the
 * pre-011 fingerprint/identity match, kept for what it is — a yes/no lookup,
 * not a listing), so there is no project in scope to filter by.
 *
 * Since migration 014 a suppression may also be a VEX `not_affected`
 * statement (`vex_status`, `vex_justification`, `vex_impact_statement`),
 * which `export_vex` publishes. It hides the finding exactly like any other
 * suppression; the VEX columns only add what it says to a VEX consumer.
 */
import { OPENVEX_JUSTIFICATIONS, } from '../types.js';
import { nowIso } from './repoUtil.js';
export class SuppressionsRepo {
    insertStmt;
    listActiveStmt;
    listAllStmt;
    isSuppressedStmt;
    listForFingerprintStmt;
    adoptIdentitiesStmt;
    listActiveForRuleStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO suppressions (
        finding_fingerprint, finding_identity, reason, created_at, expires_at, created_by, project_path,
        vex_status, vex_justification, vex_impact_statement
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
        this.listActiveStmt = db.prepare(`
      SELECT * FROM suppressions
      WHERE expires_at IS NULL OR expires_at > ?
      ORDER BY created_at DESC
    `);
        // Same rows as listActiveStmt, with NO expires_at filter at all — so no
        // dependency on the real wall clock. listActive() filters against
        // nowIso() deliberately, for its own live callers (compliance_evidence,
        // among others, reporting "what's suppressed right now"); a caller
        // working from an injected clock needs the unfiltered set so it can
        // apply its own "active as of `now`" test instead of the ambient one.
        this.listAllStmt = db.prepare(`
      SELECT * FROM suppressions
      ORDER BY created_at DESC
    `);
        // Either key, like findingsRepo's SUPPRESSION_MATCHES_F. A NULL identity
        // argument compares unequal to everything, so it matches by fingerprint only.
        this.isSuppressedStmt = db.prepare(`
      SELECT COUNT(*) AS n FROM suppressions
      WHERE (finding_fingerprint = ? OR finding_identity = ?)
        AND (expires_at IS NULL OR expires_at > ?)
    `);
        this.listForFingerprintStmt = db.prepare(`
      SELECT * FROM suppressions WHERE finding_fingerprint = ?
      ORDER BY created_at DESC
    `);
        this.listActiveForRuleStmt = db.prepare(`
      SELECT s.* FROM suppressions s
      WHERE (s.expires_at IS NULL OR s.expires_at > ?)
        AND (s.project_path IS NULL OR s.project_path = ?)
        AND EXISTS (
          SELECT 1 FROM findings f
          WHERE (f.fingerprint = s.finding_fingerprint OR f.identity = s.finding_identity)
            AND f.tool = ? AND f.rule_id = ?
        )
      ORDER BY s.created_at DESC, s.id DESC
      LIMIT ?
    `);
        // A suppression written before schema 7 knows only a fingerprint. When a
        // scan reports that fingerprint again, its row carries the identity: copy
        // it onto the suppression, once, so the next line shift does not lapse it.
        // Restricted to a suppression scoped to no project (NULL) or to THIS
        // scan's own project — otherwise a scan in project A could adopt an
        // identity computed in A onto a suppression that names project B, purely
        // because both happen to share a fingerprint.
        this.adoptIdentitiesStmt = db.prepare(`
      UPDATE suppressions
      SET finding_identity = (
        SELECT f.identity FROM findings f
        WHERE f.scan_id = ? AND f.fingerprint = suppressions.finding_fingerprint
          AND f.identity IS NOT NULL
        LIMIT 1
      )
      WHERE finding_identity IS NULL
        AND finding_fingerprint IN (
          SELECT fingerprint FROM findings WHERE scan_id = ? AND identity IS NOT NULL
        )
        AND (project_path IS NULL OR project_path = (SELECT project_path FROM scans WHERE id = ?))
    `);
    }
    insert(input) {
        const info = this.insertStmt.run(input.finding_fingerprint, input.finding_identity ?? null, input.reason, nowIso(), input.expires_at ?? null, input.created_by ?? null, input.project_path ?? null, input.vex_status ?? null, input.vex_justification ?? null, input.vex_impact_statement ?? null);
        return Number(info.lastInsertRowid);
    }
    listActive() {
        return this.listActiveStmt.all(nowIso()).map(rowToSuppression);
    }
    /** Every suppression row, active or not, unfiltered by expiry. See
     *  listAllStmt's own comment for why this exists beside listActive(). */
    listAll() {
        return this.listAllStmt.all().map(rowToSuppression);
    }
    /** Whether an active suppression names this finding by fingerprint or identity. */
    isSuppressed(fingerprint, identity) {
        const row = this.isSuppressedStmt.get(fingerprint, identity ?? null, nowIso());
        return (row?.n ?? 0) > 0;
    }
    listForFingerprint(fingerprint) {
        return this.listForFingerprintStmt.all(fingerprint).map(rowToSuppression);
    }
    /**
     * Active suppressions of findings reported by `tool` under `ruleId`,
     * scoped to `projectPath` (or to no project at all) — matched through the
     * findings table on either key, since a suppression stores only the
     * finding's fingerprint/identity. Newest first.
     */
    listActiveForRule(tool, ruleId, limit, projectPath) {
        return this.listActiveForRuleStmt
            .all(nowIso(), projectPath, tool, ruleId, limit)
            .map(rowToSuppression);
    }
    /**
     * Give every identity-less suppression whose fingerprint `scanId` reported
     * that finding's identity — restricted to a suppression scoped to no
     * project or to `scanId`'s own project. Returns how many were upgraded.
     */
    adoptIdentities(scanId) {
        return Number(this.adoptIdentitiesStmt.run(scanId, scanId, scanId).changes);
    }
}
function rowToSuppression(row) {
    const s = {
        id: row.id,
        finding_fingerprint: row.finding_fingerprint,
        reason: row.reason,
        created_at: row.created_at,
    };
    if (row.finding_identity !== null)
        s.finding_identity = row.finding_identity;
    if (row.expires_at !== null)
        s.expires_at = row.expires_at;
    if (row.created_by !== null)
        s.created_by = row.created_by;
    if (row.project_path !== null)
        s.project_path = row.project_path;
    // Only the values suppress_finding writes are read back as VEX: anything
    // else in the column (a hand edit, a future build's status) states nothing
    // this build can export, so it reads as an ordinary suppression.
    if (row.vex_status === 'not_affected' && isJustification(row.vex_justification)) {
        s.vex_status = 'not_affected';
        s.vex_justification = row.vex_justification;
        if (row.vex_impact_statement !== null)
            s.vex_impact_statement = row.vex_impact_statement;
    }
    return s;
}
function isJustification(value) {
    return OPENVEX_JUSTIFICATIONS.includes(value);
}
//# sourceMappingURL=suppressionsRepo.js.map