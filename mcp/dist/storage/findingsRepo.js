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
 */
import { SEVERITIES, SEVERITY_ORDER } from '../types.js';
import { boolToInt, intToBool } from './repoUtil.js';
export class FindingsRepo {
    db;
    insertStmt;
    listByScanStmt;
    listOpenLatestScanStmt;
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
        // (that are not expired) filtered out.
        this.listOpenLatestScanStmt = db.prepare(`
      WITH latest AS (
        SELECT id FROM scans WHERE status = 'completed'
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
        this.listBySeverityLatestStmt = db.prepare(`
      WITH latest AS (
        SELECT id FROM scans WHERE status = 'completed'
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
    listOpen() {
        return this.listOpenLatestScanStmt.all().map(rowToFinding);
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