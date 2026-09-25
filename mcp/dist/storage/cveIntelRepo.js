/**
 * `cve_intel` repository — the 24h-refresh cache of CISA KEV membership and
 * FIRST EPSS score, keyed by `cve_id` alone (migration 010; see that file's
 * own comment for why no scan or project scopes it).
 *
 * `getMany` returns a genuine cache MISS (no map entry) for a `cve_id` this
 * table has never successfully cached — never a fabricated `kev: false` row
 * — so `intel/enrich.ts` can tell "never fetched" apart from "fetched, not
 * listed". Mirrors `cvesRepo.ts` / `validationsRepo.ts`'s upsert-by-key
 * shape: one row per `cve_id`, replaced in place, never accumulated.
 */
export class CveIntelRepo {
    db;
    upsertStmt;
    constructor(db) {
        this.db = db;
        this.upsertStmt = db.prepare(`
      INSERT INTO cve_intel (cve_id, epss_score, epss_percentile, kev, kev_date_added, fetched_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(cve_id) DO UPDATE SET
        epss_score      = excluded.epss_score,
        epss_percentile = excluded.epss_percentile,
        kev             = excluded.kev,
        kev_date_added  = excluded.kev_date_added,
        fetched_at      = excluded.fetched_at
    `);
    }
    upsertMany(rows) {
        if (rows.length === 0)
            return;
        const tx = this.db.transaction((items) => {
            for (const r of items) {
                this.upsertStmt.run(r.cve_id, r.epss_score ?? null, r.epss_percentile ?? null, r.kev ? 1 : 0, r.kev_date_added ?? null, r.fetched_at);
            }
        });
        tx(rows);
    }
    /** Exactly the requested `cveIds` that have a cached row — a `cve_id` this
     *  table has never cached is simply absent from the returned map. */
    getMany(cveIds) {
        const ids = [...new Set(cveIds)];
        if (ids.length === 0)
            return new Map();
        const placeholders = ids.map(() => '?').join(', ');
        const rows = this.db
            .prepare(`SELECT * FROM cve_intel WHERE cve_id IN (${placeholders})`)
            .all(...ids);
        return new Map(rows.map((r) => [r.cve_id, rowToIntel(r)]));
    }
}
function rowToIntel(row) {
    return {
        cve_id: row.cve_id,
        epss_score: row.epss_score,
        epss_percentile: row.epss_percentile,
        kev: row.kev !== 0,
        kev_date_added: row.kev_date_added,
        fetched_at: row.fetched_at,
    };
}
//# sourceMappingURL=cveIntelRepo.js.map