/**
 * CVEs repository — which CVEs each scan saw.
 *
 * One `scan_cves` row per (scan, cve_id, package_name, installed_version),
 * with an unknown installed version stored as `''` so it still takes part in
 * the key: re-reporting the same CVE within one scan updates that row instead
 * of adding another. `listActive(scanId)` returns exactly that scan's CVEs.
 *
 * The 2.0.0 `cves` table kept one row per CVE with a single global
 * `last_seen_scan_id`, which the next scan of any other project overwrote —
 * `listActive(scanA)` lost every CVE scanA shared with a later scan — and its
 * NULL-version rows never deduplicated. See `migrations/005_scan_cves.sql`;
 * that table is no longer written or read here.
 */
/**
 * The first or last scan OF THE SAME PROJECT that saw the same CVE in the same
 * package version — never another project's scan, which is what made the old
 * global `last_seen_scan_id` wrong. Falls back to the scan itself.
 */
function seenIn(direction) {
    return `COALESCE((
      SELECT o.scan_id FROM scan_cves o JOIN scans os ON os.id = o.scan_id
      WHERE o.cve_id = sc.cve_id AND o.package_name = sc.package_name
        AND o.installed_version = sc.installed_version
        AND os.project_path = s.project_path
      ORDER BY os.started_at ${direction}, os.rowid ${direction}
      LIMIT 1
    ), sc.scan_id)`;
}
export class CvesRepo {
    db;
    upsertStmt;
    listActiveStmt;
    constructor(db) {
        this.db = db;
        this.upsertStmt = db.prepare(`
      INSERT INTO scan_cves (
        scan_id, cve_id, package_name, installed_version, fixed_version, severity
      )
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(scan_id, cve_id, package_name, installed_version) DO UPDATE SET
        fixed_version = excluded.fixed_version,
        severity      = excluded.severity
    `);
        this.listActiveStmt = db.prepare(`
      SELECT sc.cve_id, sc.package_name, sc.installed_version, sc.fixed_version, sc.severity,
             ${seenIn('ASC')} AS first_seen_scan_id,
             ${seenIn('DESC')} AS last_seen_scan_id
      FROM scan_cves sc
      LEFT JOIN scans s ON s.id = sc.scan_id
      WHERE sc.scan_id = ?
      ORDER BY
        CASE sc.severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        sc.cve_id ASC, sc.package_name ASC, sc.installed_version ASC
    `);
    }
    upsert(input) {
        this.upsertStmt.run(input.scan_id, input.cve_id, input.package_name, input.installed_version ?? '', input.fixed_version ?? null, input.severity);
    }
    bulkUpsert(rows) {
        if (rows.length === 0)
            return;
        const tx = this.db.transaction((items) => {
            for (const r of items)
                this.upsert(r);
        });
        tx(rows);
    }
    /**
     * Exactly the CVEs the given scan saw, one per (cve, package, installed
     * version), most severe first. Resources usually pass the latest completed
     * deps scan id here.
     */
    listActive(scanId) {
        return this.listActiveStmt.all(scanId).map(rowToCve);
    }
}
function rowToCve(row) {
    const cve = {
        cve_id: row.cve_id,
        package_name: row.package_name,
        severity: row.severity,
        first_seen_scan_id: row.first_seen_scan_id,
        last_seen_scan_id: row.last_seen_scan_id,
    };
    if (row.installed_version !== '')
        cve.installed_version = row.installed_version;
    if (row.fixed_version !== null)
        cve.fixed_version = row.fixed_version;
    return cve;
}
//# sourceMappingURL=cvesRepo.js.map