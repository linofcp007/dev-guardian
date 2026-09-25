/**
 * `enrichCveIntel` — the one entry point `tools/prioritizeFindings.ts`,
 * `tools/riskScore.ts` and `resources/misc.ts` use to learn a CVE's CISA KEV
 * membership and FIRST EPSS score, cached 24h in `cve_intel` (migration 010).
 *
 * Cache-first: a `cve_id` cached within {@link INTEL_TTL_MS} is served
 * straight from `storage.cveIntel` with NO network call at all — most calls,
 * for most projects, touch the network for zero CVEs. Only stale-or-never-
 * cached ids reach the network, and only those ids (never the whole batch).
 *
 * `GUARDIAN_OFFLINE=1` (env, or `opts.offline` to override it directly, e.g.
 * from a tool's own input) skips the network step entirely for whatever is
 * stale or missing — those ids come back `status: 'unavailable'` unless a
 * STALE cached row exists, in which case that last-known value is served
 * with `stale: true` rather than discarded (still real data, just possibly
 * outdated by less than one refresh cycle).
 *
 * The KEV catalog fetch and the EPSS batch query are treated as ONE combined
 * refresh: both must succeed for a stale id to come back as a genuinely
 * fresh `status: 'ok'` row (and be written back to the cache). If EITHER
 * fails, nothing is written, and every affected id falls back to its stale
 * cached value (if any) or comes back `unavailable` (if never cached) — see
 * this module's own tests for why: a partial success that persisted only
 * half a row would make the NEXT call's freshness check believe the other
 * half was checked today too, when it was not.
 */
import { fetchKevCatalog } from './kev.js';
import { queryEpss } from './epss.js';
/** How long a cached row is served without attempting a refresh. */
export const INTEL_TTL_MS = 24 * 60 * 60 * 1000;
export async function enrichCveIntel(storage, cveIds, opts = {}) {
    const ids = [...new Set(cveIds)];
    const result = new Map();
    if (ids.length === 0)
        return result;
    const now = opts.now ?? Date.now();
    const cached = storage.cveIntel.getMany(ids);
    const staleIds = [];
    for (const id of ids) {
        const row = cached.get(id);
        if (row !== undefined && now - Date.parse(row.fetched_at) < INTEL_TTL_MS) {
            result.set(id, freshResult(row));
        }
        else {
            staleIds.push(id);
        }
    }
    if (staleIds.length === 0)
        return result;
    const offline = opts.offline ?? (opts.env ?? process.env)['GUARDIAN_OFFLINE'] === '1';
    if (offline) {
        for (const id of staleIds) {
            result.set(id, fallbackResult(id, cached.get(id), 'network disabled (GUARDIAN_OFFLINE=1)'));
        }
        return result;
    }
    const netOpts = { fetchImpl: opts.fetchImpl, timeoutMs: opts.timeoutMs, signal: opts.signal };
    const queryEpssImpl = opts.queryEpssImpl ?? queryEpss;
    const fetchKevCatalogImpl = opts.fetchKevCatalogImpl ?? fetchKevCatalog;
    const [epssResult, kevResult] = await Promise.all([
        queryEpssImpl(staleIds, netOpts),
        fetchKevCatalogImpl(netOpts),
    ]);
    if (epssResult.ok && kevResult.ok) {
        const nowIso = new Date(now).toISOString();
        const toUpsert = [];
        for (const id of staleIds) {
            const kev = kevResult.entries.has(id);
            const kevDate = kevResult.entries.get(id);
            const epss = epssResult.scores.get(id);
            const entry = { cve_id: id, status: 'ok', kev, fetched_at: nowIso };
            if (kevDate !== undefined)
                entry.kev_date_added = kevDate;
            if (epss !== undefined) {
                entry.epss_score = epss.score;
                entry.epss_percentile = epss.percentile;
            }
            result.set(id, entry);
            const row = { cve_id: id, kev, fetched_at: nowIso };
            if (kevDate !== undefined)
                row.kev_date_added = kevDate;
            if (epss !== undefined) {
                row.epss_score = epss.score;
                row.epss_percentile = epss.percentile;
            }
            toUpsert.push(row);
        }
        storage.cveIntel.upsertMany(toUpsert);
        return result;
    }
    const reasonParts = [];
    if (!kevResult.ok)
        reasonParts.push(`kev: ${kevResult.reason}`);
    if (!epssResult.ok)
        reasonParts.push(`epss: ${epssResult.reason}`);
    const reason = reasonParts.join('; ');
    for (const id of staleIds) {
        result.set(id, fallbackResult(id, cached.get(id), reason));
    }
    return result;
}
function freshResult(row) {
    const entry = { cve_id: row.cve_id, status: 'ok', kev: row.kev, fetched_at: row.fetched_at };
    if (row.kev_date_added !== null)
        entry.kev_date_added = row.kev_date_added;
    if (row.epss_score !== null)
        entry.epss_score = row.epss_score;
    if (row.epss_percentile !== null)
        entry.epss_percentile = row.epss_percentile;
    return entry;
}
/** A stale/missing id after a refresh could not be attempted or did not
 *  fully succeed: the last cached value (flagged `stale`) when one exists,
 *  else a plain `unavailable` — never a fabricated `kev: false` presented as
 *  a measured negative. */
function fallbackResult(id, row, reason) {
    if (row === undefined)
        return { cve_id: id, status: 'unavailable', kev: false, reason };
    const entry = { cve_id: id, status: 'ok', stale: true, kev: row.kev, fetched_at: row.fetched_at, reason };
    if (row.kev_date_added !== null)
        entry.kev_date_added = row.kev_date_added;
    if (row.epss_score !== null)
        entry.epss_score = row.epss_score;
    if (row.epss_percentile !== null)
        entry.epss_percentile = row.epss_percentile;
    return entry;
}
//# sourceMappingURL=enrich.js.map