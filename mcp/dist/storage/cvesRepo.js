/**
 * CVEs repository — deduped across scans by (cve_id, package_name, installed_version).
 *
 * Trivy emits the same CVE record on every scan run; the repo keeps one row
 * per unique tuple and tracks first/last `scan_id` so resources can surface
 * "active" (last_seen = latest deps scan) vs. historical.
 */
export class CvesRepo {
    db;
    upsertStmt;
    listActiveStmt;
    constructor(db) {
        this.db = db;
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
        this.listActiveStmt = db.prepare(`
      SELECT * FROM cves WHERE last_seen_scan_id = ?
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
          WHEN 'low' THEN 1 ELSE 0 END DESC,
        cve_id ASC
    `);
    }
    upsert(input) {
        this.upsertStmt.run(input.cve_id, input.package_name, input.installed_version ?? null, input.fixed_version ?? null, input.severity, input.scan_id, input.scan_id);
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
     * Returns CVEs whose `last_seen_scan_id` matches the given scan. Resources
     * usually pass the latest completed deps scan id here.
     */
    listActive(latestScanId) {
        return this.listActiveStmt.all(latestScanId).map(rowToCve);
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
    if (row.installed_version !== null)
        cve.installed_version = row.installed_version;
    if (row.fixed_version !== null)
        cve.fixed_version = row.fixed_version;
    return cve;
}
//# sourceMappingURL=cvesRepo.js.map