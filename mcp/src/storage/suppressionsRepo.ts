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
 */

import type { DB, Statement } from './db.js';
import type { Suppression } from '../types.js';
import { nowIso } from './repoUtil.js';

interface SuppressionRow {
  id: number;
  finding_fingerprint: string;
  finding_identity: string | null;
  reason: string;
  created_at: string;
  expires_at: string | null;
  created_by: string | null;
}

export interface InsertSuppressionInput {
  finding_fingerprint: string;
  /** The finding's identity, when known — lets the suppression follow it across line shifts. */
  finding_identity?: string;
  reason: string;
  expires_at?: string;
  created_by?: string;
}

export class SuppressionsRepo {
  private readonly insertStmt: Statement<
    [string, string | null, string, string, string | null, string | null]
  >;
  private readonly listActiveStmt: Statement<[string], SuppressionRow>;
  private readonly listAllStmt: Statement<[], SuppressionRow>;
  private readonly isSuppressedStmt: Statement<[string, string | null, string], { n: number }>;
  private readonly listForFingerprintStmt: Statement<[string], SuppressionRow>;
  private readonly adoptIdentitiesStmt: Statement<[string, string]>;
  private readonly listActiveForRuleStmt: Statement<[string, string, string, number], SuppressionRow>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO suppressions (
        finding_fingerprint, finding_identity, reason, created_at, expires_at, created_by
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    this.listActiveStmt = db.prepare<[string], SuppressionRow>(`
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
    this.listAllStmt = db.prepare<[], SuppressionRow>(`
      SELECT * FROM suppressions
      ORDER BY created_at DESC
    `);

    // Either key, like findingsRepo's SUPPRESSION_MATCHES_F. A NULL identity
    // argument compares unequal to everything, so it matches by fingerprint only.
    this.isSuppressedStmt = db.prepare<[string, string | null, string], { n: number }>(`
      SELECT COUNT(*) AS n FROM suppressions
      WHERE (finding_fingerprint = ? OR finding_identity = ?)
        AND (expires_at IS NULL OR expires_at > ?)
    `);

    this.listForFingerprintStmt = db.prepare<[string], SuppressionRow>(`
      SELECT * FROM suppressions WHERE finding_fingerprint = ?
      ORDER BY created_at DESC
    `);

    this.listActiveForRuleStmt = db.prepare<[string, string, string, number], SuppressionRow>(`
      SELECT s.* FROM suppressions s
      WHERE (s.expires_at IS NULL OR s.expires_at > ?)
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
    this.adoptIdentitiesStmt = db.prepare<[string, string]>(`
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
    `);
  }

  insert(input: InsertSuppressionInput): number {
    const info = this.insertStmt.run(
      input.finding_fingerprint,
      input.finding_identity ?? null,
      input.reason,
      nowIso(),
      input.expires_at ?? null,
      input.created_by ?? null,
    );
    return Number(info.lastInsertRowid);
  }

  listActive(): Suppression[] {
    return this.listActiveStmt.all(nowIso()).map(rowToSuppression);
  }

  /** Every suppression row, active or not, unfiltered by expiry. See
   *  listAllStmt's own comment for why this exists beside listActive(). */
  listAll(): Suppression[] {
    return this.listAllStmt.all().map(rowToSuppression);
  }

  /** Whether an active suppression names this finding by fingerprint or identity. */
  isSuppressed(fingerprint: string, identity?: string): boolean {
    const row = this.isSuppressedStmt.get(fingerprint, identity ?? null, nowIso());
    return (row?.n ?? 0) > 0;
  }

  listForFingerprint(fingerprint: string): Suppression[] {
    return this.listForFingerprintStmt.all(fingerprint).map(rowToSuppression);
  }

  /**
   * Active suppressions of findings reported by `tool` under `ruleId` —
   * matched through the findings table on either key, since a suppression
   * stores only the finding's fingerprint/identity. Newest first.
   */
  listActiveForRule(tool: string, ruleId: string, limit: number): Suppression[] {
    return this.listActiveForRuleStmt.all(nowIso(), tool, ruleId, limit).map(rowToSuppression);
  }

  /**
   * Give every identity-less suppression whose fingerprint `scanId` reported
   * that finding's identity. Returns how many suppressions were upgraded.
   */
  adoptIdentities(scanId: string): number {
    return Number(this.adoptIdentitiesStmt.run(scanId, scanId).changes);
  }
}

function rowToSuppression(row: SuppressionRow): Suppression {
  const s: Suppression = {
    id: row.id,
    finding_fingerprint: row.finding_fingerprint,
    reason: row.reason,
    created_at: row.created_at,
  };
  if (row.finding_identity !== null) s.finding_identity = row.finding_identity;
  if (row.expires_at !== null) s.expires_at = row.expires_at;
  if (row.created_by !== null) s.created_by = row.created_by;
  return s;
}
