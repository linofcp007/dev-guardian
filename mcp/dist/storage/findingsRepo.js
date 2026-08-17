/**
 * Findings repository.
 *
 * Findings are stored per-scan but share a stable `fingerprint` across scans
 * (see [src/fingerprint/findingFingerprint.ts]), which is what lets us:
 *   - dedupe inside a scan,
 *   - compute diffs across scans,
 *   - apply suppressions across all future scans.
 *
 * The `open` list is the canonical "what's wrong right now" view: it joins
 * the latest completed scan with the suppressions table.
 *
 * **The UNSCOPED "latest scan" queries (`listOpen`, `listBySeverity`)
 * exclude `create_fix_pr`'s own verification re-scans (task-7-review.md
 * I3).** `create_fix_pr` re-runs a scanner inside a disposable worktree to
 * prove a fix, with `project_path` set to that worktree — a real, if
 * short-lived, row in `scans`. Measured without this exclusion: one
 * `create_fix_pr` call (even a dry run — the re-scan is not gated by
 * `apply`) repoints `listOpen()`/`getLatest()` at that worktree, so
 * `guardian://findings/open`, `triage_findings`, `prioritize_findings`,
 * `risk_score` and `dotnet_describe_setup` all report a false all-clear for
 * a directory that no longer exists, while the real project's own findings
 * sit untouched under the project-SCOPED queries (`listOpenForProject`,
 * `getLatestForProject`), which never needed this — they filter on an exact
 * `project_path`, which a worktree's path can never equal.
 *
 * `WORKTREE_PATH_EXCLUSION` wraps `fixpr/worktree.ts`'s own
 * `WORKTREE_DIR_PREFIX` ('guardian-fixpr-wt-') in `%` on BOTH sides for
 * `LIKE`: `createWorktree` builds the path via `mkdtempSync(join(tmpdir(),
 * WORKTREE_DIR_PREFIX))`, so the prefix names the LAST path segment
 * (`/tmp/guardian-fixpr-wt-Ab12Cd`, `C:\…\Temp\guardian-fixpr-wt-Ab12Cd`) —
 * never the start of the whole path string, which a leading-wildcard-only
 * pattern would require. Inlined as a literal, not imported: this is core
 * storage, several layers below any single feature, and importing a
 * feature-specific constant here would invert that. If `WORKTREE_DIR_PREFIX`
 * ever changes, this must change with it — there is no compiler check tying
 * the two together.
 */
import { SEVERITIES, SEVERITY_ORDER } from '../types.js';
import { boolToInt, intToBool } from './repoUtil.js';
/** See the module comment. Wraps `fixpr/worktree.ts`'s `WORKTREE_DIR_PREFIX`. */
const WORKTREE_PATH_EXCLUSION = '%guardian-fixpr-wt-%';
export class FindingsRepo {
    db;
    insertStmt;
    listByScanStmt;
    listOpenLatestScanStmt;
    listOpenForProjectStmt;
    listBySeverityLatestStmt;
    countBySeverityStmt;
    constructor(db) {
        this.db = db;
        this.insertStmt = db.prepare(`
      INSERT OR IGNORE INTO findings (
        fingerprint, scan_id, tool, rule_id, severity, category, subcategory,
        title, message, file_path, line_start, line_end,
        snippet, fix_available, fix_applied, raw
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
        this.listByScanStmt = db.prepare(`
      SELECT * FROM findings WHERE scan_id = ?
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        fingerprint ASC
    `);
        // "Open" = findings in the latest completed scan, with suppressions
        // (that are not expired) filtered out. `project_path NOT LIKE
        // 'guardian-fixpr-wt-%'` excludes create_fix_pr's own verification
        // re-scans (task-7-review.md I3) — see this file's own module comment
        // for why this lives here as a literal rather than an import.
        this.listOpenLatestScanStmt = db.prepare(`
      WITH latest AS (
        SELECT id FROM scans
        WHERE status = 'completed' AND project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
        ORDER BY started_at DESC, rowid DESC LIMIT 1
      )
      SELECT f.* FROM findings f
      JOIN latest l ON l.id = f.scan_id
      WHERE NOT EXISTS (
        SELECT 1 FROM suppressions s
        WHERE s.finding_fingerprint = f.fingerprint
          AND (s.expires_at IS NULL OR s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
      ORDER BY
        CASE f.severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        f.fingerprint ASC
    `);
        // Same predicate as listOpenLatestScanStmt above, with one addition:
        // `AND project_path = ?` on the `latest` CTE, so "latest completed scan"
        // means latest FOR THIS PROJECT rather than latest in the whole table.
        this.listOpenForProjectStmt = db.prepare(`
      WITH latest AS (
        SELECT id FROM scans WHERE status = 'completed' AND project_path = ?
        ORDER BY started_at DESC, rowid DESC LIMIT 1
      )
      SELECT f.* FROM findings f
      JOIN latest l ON l.id = f.scan_id
      WHERE NOT EXISTS (
        SELECT 1 FROM suppressions s
        WHERE s.finding_fingerprint = f.fingerprint
          AND (s.expires_at IS NULL OR s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
      ORDER BY
        CASE f.severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        f.fingerprint ASC
    `);
        // Same exclusion as listOpenLatestScanStmt above, and for the same
        // reason — this is ALSO an unscoped "latest scan" query.
        this.listBySeverityLatestStmt = db.prepare(`
      WITH latest AS (
        SELECT id FROM scans
        WHERE status = 'completed' AND project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
        ORDER BY started_at DESC, rowid DESC LIMIT 1
      )
      SELECT f.* FROM findings f
      JOIN latest l ON l.id = f.scan_id
      WHERE f.severity = ?
        AND NOT EXISTS (
          SELECT 1 FROM suppressions s
          WHERE s.finding_fingerprint = f.fingerprint
            AND (s.expires_at IS NULL OR s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
      ORDER BY f.fingerprint ASC
    `);
        this.countBySeverityStmt = db.prepare(`
      SELECT severity, COUNT(*) AS n FROM findings
      WHERE scan_id = ?
      GROUP BY severity
    `);
    }
    bulkInsert(findings) {
        if (findings.length === 0)
            return 0;
        const tx = this.db.transaction((rows) => {
            let inserted = 0;
            for (const f of rows) {
                const info = this.insertStmt.run(f.fingerprint, f.scan_id, f.tool, f.rule_id ?? null, f.severity, f.category, f.subcategory ?? null, f.title, f.message ?? null, f.file_path ?? null, f.line_start ?? null, f.line_end ?? null, f.snippet ?? null, boolToInt(f.fix_available), boolToInt(f.fix_applied), f.raw === undefined ? null : JSON.stringify(f.raw));
                inserted += info.changes;
            }
            return inserted;
        });
        return tx(findings);
    }
    listByScan(scanId) {
        return this.listByScanStmt.all(scanId).map(rowToFinding);
    }
    /**
     * Open findings from the latest completed scan IN THE WHOLE DATABASE, from
     * ANY project — no `project_path` filter.
     *
     * Correct for a caller that has no project in scope at all: an aggregate
     * tool like `risk_score` or `prioritize_findings` takes no `project_path`
     * input and reports on "whatever this server last scanned", the same
     * contract `scans.getLatest()` already has.
     *
     * A caller that DID resolve a `project_path` — and relativizes paths
     * against it, or persists something keyed by it — must use
     * `listOpenForProject` instead: this method would hand it another
     * project's findings whenever that project's scan happened to complete
     * more recently, silently, since the result is never empty and nothing
     * about it looks wrong. `validate_finding` (tools/validateFinding.ts) made
     * exactly that mistake before being fixed alongside `listOpenForProject`'s
     * addition.
     */
    listOpen() {
        return this.listOpenLatestScanStmt.all().map(rowToFinding);
    }
    /**
     * Open findings from the latest completed scan FOR ONE project.
     * `project_path` is matched exactly, against the same
     * `resolveProjectPath()` output every scan persists and every caller of
     * this method resolves its own argument through — see `surfaceRepo.ts`'s
     * `getLatestForProject`, which this mirrors.
     */
    listOpenForProject(projectPath) {
        return this.listOpenForProjectStmt.all(projectPath).map(rowToFinding);
    }
    listBySeverity(severity) {
        return this.listBySeverityLatestStmt.all(severity).map(rowToFinding);
    }
    /**
     * Counts findings per severity for one scan, returning the full record
     * even for severities with zero findings (so consumers don't need null
     * checks).
     */
    countBySeverity(scanId) {
        const counts = this.countBySeverityStmt.all(scanId);
        const out = {
            info: 0,
            low: 0,
            medium: 0,
            high: 0,
            critical: 0,
        };
        for (const row of counts) {
            if (SEVERITIES.includes(row.severity)) {
                out[row.severity] = row.n;
            }
        }
        return out;
    }
    /**
     * Returns the top-N findings of a scan, severity-desc then fingerprint-asc.
     * Used by the scan result to give the model a quick highlight reel.
     */
    topFindings(scanId, limit = 10) {
        const all = this.listByScan(scanId);
        return all
            .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
            a.fingerprint.localeCompare(b.fingerprint))
            .slice(0, limit);
    }
}
function rowToFinding(row) {
    const finding = {
        fingerprint: row.fingerprint,
        tool: row.tool,
        severity: row.severity,
        category: row.category,
        title: row.title,
        fix_available: intToBool(row.fix_available),
        fix_applied: intToBool(row.fix_applied),
    };
    if (row.rule_id !== null)
        finding.rule_id = row.rule_id;
    if (row.subcategory !== null)
        finding.subcategory = row.subcategory;
    if (row.message !== null)
        finding.message = row.message;
    if (row.file_path !== null)
        finding.file_path = row.file_path;
    if (row.line_start !== null)
        finding.line_start = row.line_start;
    if (row.line_end !== null)
        finding.line_end = row.line_end;
    if (row.snippet !== null)
        finding.snippet = row.snippet;
    return finding;
}
//# sourceMappingURL=findingsRepo.js.map