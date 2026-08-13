/**
 * Finding-validations repository.
 *
 * Persists the verdicts `validate_finding` produces (see `../validate/types.ts`
 * for the envelope). Mirrors `cvesRepo.ts`'s upsert-by-composite-key shape:
 * `(project_path, fingerprint, provider)` is the table's PRIMARY KEY, so an
 * `INSERT ... ON CONFLICT ... DO UPDATE` replaces a stale verdict in place
 * rather than accumulating a second row beside it — recomputing a verdict
 * for code that moved must not leave the old answer readable next to the
 * new one.
 *
 * `evidence` and `coverage_gaps` are stored as JSON text and parsed back into
 * arrays on read via `parseJsonArray`, which — like every JSON column in this
 * codebase (see `surfaceRepo.ts`) — tolerates malformed or truncated stored
 * JSON by falling back to `[]` instead of throwing. A caller never receives a
 * raw JSON string typed as `ValidationEvidence[]`.
 */
import { parseJsonArray } from './repoUtil.js';
export class ValidationsRepo {
    db;
    upsertStmt;
    listByProjectStmt;
    getByFingerprintStmt;
    constructor(db) {
        this.db = db;
        this.upsertStmt = db.prepare(`
      INSERT INTO finding_validations (
        project_path, fingerprint, provider, verdict, confidence,
        evidence, coverage_gaps, snapshot_id, tree_hash, computed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_path, fingerprint, provider) DO UPDATE SET
        verdict       = excluded.verdict,
        confidence    = excluded.confidence,
        evidence      = excluded.evidence,
        coverage_gaps = excluded.coverage_gaps,
        snapshot_id   = excluded.snapshot_id,
        tree_hash     = excluded.tree_hash,
        computed_at   = excluded.computed_at
    `);
        this.listByProjectStmt = db.prepare(`
      SELECT * FROM finding_validations
      WHERE project_path = ?
      ORDER BY fingerprint ASC, provider ASC
    `);
        // (project_path, fingerprint) alone is not unique once more than one
        // provider has a verdict for the same finding — the PRIMARY KEY also
        // includes provider. This picks the most recently computed row so "the"
        // verdict for a finding stays well-defined without a provider argument.
        // listByProject is the method that returns every provider's row.
        this.getByFingerprintStmt = db.prepare(`
      SELECT * FROM finding_validations
      WHERE project_path = ? AND fingerprint = ?
      ORDER BY computed_at DESC
      LIMIT 1
    `);
    }
    /**
     * Replaces (never accumulates) the verdict for each row's
     * `(projectPath, fingerprint, provider)`. `projectPath` is a parameter
     * rather than a field on `FindingValidation` because a validation's
     * identity is the finding plus the provider; the project only scopes
     * the query.
     */
    upsert(projectPath, rows) {
        if (rows.length === 0)
            return;
        const tx = this.db.transaction((items) => {
            for (const r of items) {
                this.upsertStmt.run(projectPath, r.fingerprint, r.provider, r.verdict, r.confidence, JSON.stringify(r.evidence), JSON.stringify(r.coverage_gaps), r.snapshot_id, r.tree_hash, r.computed_at);
            }
        });
        tx(rows);
    }
    listByProject(projectPath) {
        return this.listByProjectStmt.all(projectPath).map(rowToValidation);
    }
    getByFingerprint(projectPath, fingerprint) {
        const row = this.getByFingerprintStmt.get(projectPath, fingerprint);
        return row ? rowToValidation(row) : null;
    }
}
function rowToValidation(row) {
    return {
        fingerprint: row.fingerprint,
        verdict: row.verdict,
        confidence: row.confidence,
        provider: row.provider,
        evidence: parseJsonArray(row.evidence, []),
        coverage_gaps: parseJsonArray(row.coverage_gaps, []),
        snapshot_id: row.snapshot_id,
        tree_hash: row.tree_hash,
        computed_at: row.computed_at,
    };
}
//# sourceMappingURL=validationsRepo.js.map