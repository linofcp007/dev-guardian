/**
 * CVEs repository — deduped across scans by (cve_id, package_name, installed_version).
 *
 * Trivy emits the same CVE record on every scan run; the repo keeps one row
 * per unique tuple and tracks first/last `scan_id` so resources can surface
 * "active" (last_seen = latest deps scan) vs. historical.
 */

import type { Database as DB, Statement } from 'better-sqlite3';
import type { Cve, Severity } from '../types.js';

interface CveRow {
  cve_id: string;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  severity: string;
  first_seen_scan_id: string;
  last_seen_scan_id: string;
}

export interface UpsertCveInput {
  cve_id: string;
  package_name: string;
  installed_version?: string;
  fixed_version?: string;
  severity: Severity;
  scan_id: string;
}

export class CvesRepo {
  private readonly upsertStmt: Statement<[
    string, string, string | null, string | null, string, string, string,
  ]>;
  private readonly listActiveStmt: Statement<[string], CveRow>;

  constructor(private readonly db: DB) {
    this.upsertStmt = db.prepare(`
      INSERT INTO cves (
        cve_id, package_name, installed_version, fixed_version, severity,
        first_seen_scan_id, last_seen_scan_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(cve_id, package_name, installed_version) DO UPDATE SET
        fixed_version    = excluded.fixed_version,
        severity         = excluded.severity,
        last_seen_scan_id = excluded.last_seen_scan_id
    `);

    this.listActiveStmt = db.prepare<[string], CveRow>(`
      SELECT * FROM cves WHERE last_seen_scan_id = ?
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        cve_id ASC
    `);
  }

  upsert(input: UpsertCveInput): void {
    this.upsertStmt.run(
      input.cve_id,
      input.package_name,
      input.installed_version ?? null,
      input.fixed_version ?? null,
      input.severity,
      input.scan_id,
      input.scan_id,
    );
  }

  bulkUpsert(rows: UpsertCveInput[]): void {
    if (rows.length === 0) return;
    const tx = this.db.transaction((items: UpsertCveInput[]) => {
      for (const r of items) this.upsert(r);
    });
    tx(rows);
  }

  /**
   * Returns CVEs whose `last_seen_scan_id` matches the given scan. Resources
   * usually pass the latest completed deps scan id here.
   */
  listActive(latestScanId: string): Cve[] {
    return this.listActiveStmt.all(latestScanId).map(rowToCve);
  }
}

function rowToCve(row: CveRow): Cve {
  const cve: Cve = {
    cve_id: row.cve_id,
    package_name: row.package_name,
    severity: row.severity as Severity,
    first_seen_scan_id: row.first_seen_scan_id,
    last_seen_scan_id: row.last_seen_scan_id,
  };
  if (row.installed_version !== null) cve.installed_version = row.installed_version;
  if (row.fixed_version !== null) cve.fixed_version = row.fixed_version;
  return cve;
}
