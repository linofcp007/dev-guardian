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
 * `evidence` and `coverage_gaps` are stored as JSON text. They are deliberately
 * NOT parsed with the shared `parseJsonArray` (`repoUtil.ts`), whose fallback
 * on a parse failure is `[]` — right for most JSON columns in this codebase,
 * wrong for this table specifically: `coverage_gaps: []` means "nothing was
 * missing" (see `FindingValidation`'s doc comment), so silently falling back
 * to it would make a damaged row read as the single most reassuring verdict
 * this feature can produce, which is exactly the "absence of evidence became
 * a confident answer" failure `validate_finding` exists to prevent. Instead,
 * a row whose `evidence` or `coverage_gaps` fails to parse still comes back
 * (never dropped, never thrown) but downgraded to `verdict: 'unknown'`,
 * `confidence: 'low'`, with `coverage_gaps` naming which column broke — see
 * `rowToValidation`.
 */
export class ValidationsRepo {
    db;
    upsertStmt;
    listByProjectStmt;
    listByProviderStmt;
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
        this.listByProviderStmt = db.prepare(`
      SELECT * FROM finding_validations
      WHERE project_path = ? AND provider = ?
      ORDER BY fingerprint ASC
    `);
        // The full primary key: at most one row, no tie to break.
        this.getByFingerprintStmt = db.prepare(`
      SELECT * FROM finding_validations
      WHERE project_path = ? AND fingerprint = ? AND provider = ?
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
    /** One provider's verdicts on a project's findings — the open set reads `llm` on every call. */
    listByProvider(projectPath, provider) {
        return this.listByProviderStmt.all(projectPath, provider).map(rowToValidation);
    }
    /**
     * One provider's verdict for a finding, or `null` if it has none.
     *
     * The table's key is `(project_path, fingerprint, provider)`, and a
     * dependency finding carries a `static` AND a `dependency` verdict — two
     * different questions. This used to take no provider and return "the newest
     * row", which `validate_finding` made arbitrary: it mints one `computed_at`
     * per batch, so both rows tie on it (review of the 3.0 additions, M5). The
     * provider is the caller's to name.
     */
    getByFingerprint(projectPath, fingerprint, provider) {
        const row = this.getByFingerprintStmt.get(projectPath, fingerprint, provider);
        return row ? rowToValidation(row) : null;
    }
}
/**
 * Parses a JSON-array column, distinguishing "genuinely empty" from "failed
 * to parse, or parsed to the wrong shape" — unlike the shared `parseJsonArray`
 * (`repoUtil.ts`), which collapses both to `[]`. `rowToValidation` needs that
 * distinction to avoid presenting a damaged column as an empty, fully-trusted
 * one. Returns `null` on failure.
 */
function tryParseJsonArray(raw) {
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
}
function rowToValidation(row) {
    const evidence = tryParseJsonArray(row.evidence);
    const coverageGaps = tryParseJsonArray(row.coverage_gaps);
    if (evidence === null || coverageGaps === null) {
        // The row survives — never dropped, never thrown — but its stored
        // verdict/confidence cannot be trusted once the record justifying it is
        // damaged, and a successfully-parsed sibling array is discarded too
        // rather than presented as if it still corroborates a verdict we no
        // longer trust. A caller asking about this finding needs to learn its
        // verdict is unreadable, not that the finding has no verdict at all.
        const brokenColumns = [];
        if (evidence === null)
            brokenColumns.push('evidence');
        if (coverageGaps === null)
            brokenColumns.push('coverage_gaps');
        return {
            fingerprint: row.fingerprint,
            verdict: 'unknown',
            confidence: 'low',
            provider: row.provider,
            evidence: [],
            coverage_gaps: brokenColumns.map((column) => `stored verdict could not be read: ${column} was not valid JSON`),
            snapshot_id: row.snapshot_id,
            tree_hash: row.tree_hash,
            computed_at: row.computed_at,
        };
    }
    return {
        fingerprint: row.fingerprint,
        verdict: row.verdict,
        confidence: row.confidence,
        provider: row.provider,
        evidence,
        coverage_gaps: coverageGaps,
        snapshot_id: row.snapshot_id,
        tree_hash: row.tree_hash,
        computed_at: row.computed_at,
    };
}
//# sourceMappingURL=validationsRepo.js.map