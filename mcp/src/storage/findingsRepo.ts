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

import type { DB, Statement } from './db.js';
import type { Category, Finding, Severity } from '../types.js';
import { SEVERITIES, SEVERITY_ORDER } from '../types.js';
import { boolToInt, intToBool } from './repoUtil.js';

interface FindingRow {
  fingerprint: string;
  scan_id: string;
  tool: string;
  rule_id: string | null;
  severity: string;
  category: string;
  subcategory: string | null;
  title: string;
  message: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string | null;
  fix_available: number;
  fix_applied: number;
  raw: string | null;
}

export interface InsertFindingInput extends Finding {
  scan_id: string;
  raw?: unknown;
}

export class FindingsRepo {
  private readonly insertStmt: Statement<[
    string, string, string, string | null, string, string, string | null,
    string, string | null, string | null, number | null, number | null,
    string | null, 0 | 1, 0 | 1, string | null,
  ]>;
  private readonly listByScanStmt: Statement<[string], FindingRow>;
  private readonly listOpenLatestScanStmt: Statement<[], FindingRow>;
  private readonly listBySeverityLatestStmt: Statement<[string], FindingRow>;
  private readonly countBySeverityStmt: Statement<[string], { severity: string; n: number }>;

  constructor(private readonly db: DB) {
    this.insertStmt = db.prepare(`
      INSERT OR IGNORE INTO findings (
        fingerprint, scan_id, tool, rule_id, severity, category, subcategory,
        title, message, file_path, line_start, line_end,
        snippet, fix_available, fix_applied, raw
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.listByScanStmt = db.prepare<[string], FindingRow>(`
      SELECT * FROM findings WHERE scan_id = ?
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        fingerprint ASC
    `);

    // "Open" = findings in the latest completed scan, with suppressions
    // (that are not expired) filtered out.
    this.listOpenLatestScanStmt = db.prepare<[], FindingRow>(`
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

    this.listBySeverityLatestStmt = db.prepare<[string], FindingRow>(`
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

    this.countBySeverityStmt = db.prepare<[string], { severity: string; n: number }>(`
      SELECT severity, COUNT(*) AS n FROM findings
      WHERE scan_id = ?
      GROUP BY severity
    `);
  }

  bulkInsert(findings: InsertFindingInput[]): number {
    if (findings.length === 0) return 0;
    const tx = this.db.transaction((rows: InsertFindingInput[]) => {
      let inserted = 0;
      for (const f of rows) {
        const info = this.insertStmt.run(
          f.fingerprint,
          f.scan_id,
          f.tool,
          f.rule_id ?? null,
          f.severity,
          f.category,
          f.subcategory ?? null,
          f.title,
          f.message ?? null,
          f.file_path ?? null,
          f.line_start ?? null,
          f.line_end ?? null,
          f.snippet ?? null,
          boolToInt(f.fix_available),
          boolToInt(f.fix_applied),
          f.raw === undefined ? null : JSON.stringify(f.raw),
        );
        inserted += info.changes;
      }
      return inserted;
    });
    return tx(findings);
  }

  listByScan(scanId: string): Finding[] {
    return this.listByScanStmt.all(scanId).map(rowToFinding);
  }

  listOpen(): Finding[] {
    return this.listOpenLatestScanStmt.all().map(rowToFinding);
  }

  listBySeverity(severity: Severity): Finding[] {
    return this.listBySeverityLatestStmt.all(severity).map(rowToFinding);
  }

  /**
   * Counts findings per severity for one scan, returning the full record
   * even for severities with zero findings (so consumers don't need null
   * checks).
   */
  countBySeverity(scanId: string): Record<Severity, number> {
    const counts = this.countBySeverityStmt.all(scanId);
    const out: Record<Severity, number> = {
      info: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    for (const row of counts) {
      if (SEVERITIES.includes(row.severity as Severity)) {
        out[row.severity as Severity] = row.n;
      }
    }
    return out;
  }

  /**
   * Returns the top-N findings of a scan, severity-desc then fingerprint-asc.
   * Used by the scan result to give the model a quick highlight reel.
   */
  topFindings(scanId: string, limit = 10): Finding[] {
    const all = this.listByScan(scanId);
    return all
      .sort(
        (a, b) =>
          SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
          a.fingerprint.localeCompare(b.fingerprint),
      )
      .slice(0, limit);
  }
}

function rowToFinding(row: FindingRow): Finding {
  const finding: Finding = {
    fingerprint: row.fingerprint,
    tool: row.tool,
    severity: row.severity as Severity,
    category: row.category as Category,
    title: row.title,
    fix_available: intToBool(row.fix_available),
    fix_applied: intToBool(row.fix_applied),
  };
  if (row.rule_id !== null) finding.rule_id = row.rule_id;
  if (row.subcategory !== null) finding.subcategory = row.subcategory;
  if (row.message !== null) finding.message = row.message;
  if (row.file_path !== null) finding.file_path = row.file_path;
  if (row.line_start !== null) finding.line_start = row.line_start;
  if (row.line_end !== null) finding.line_end = row.line_end;
  if (row.snippet !== null) finding.snippet = row.snippet;
  return finding;
}
