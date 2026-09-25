/**
 * CISA Known Exploited Vulnerabilities (KEV) catalog client —
 * `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
 * Verified live 2026-09-25: a single JSON object,
 * `{ title, catalogVersion, dateReleased, count, vulnerabilities: [{ cveID,
 * dateAdded, ... }] }`, ~1700 entries (a few hundred KB) — small enough to
 * fetch whole and index in memory rather than queried per CVE the way EPSS
 * is; CISA publishes no per-CVE lookup endpoint.
 *
 * Network is optional, never required: every failure path (no `fetch`,
 * non-2xx, timeout/abort, malformed JSON, a request that throws) degrades to
 * `{ ok: false, reason }`. Callers (`intel/enrich.ts`) must treat that as
 * "unknown", never as "not in KEV" for every CVE in the batch.
 */
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const DEFAULT_TIMEOUT_MS = 8000;
/** `entries` maps `cveID` -> `dateAdded` (ISO date, CISA's own format `YYYY-MM-DD`). */
export async function fetchKevCatalog(opts = {}) {
    const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
    if (fetchImpl === undefined)
        return { ok: false, reason: 'no fetch implementation available' };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    if (opts.signal) {
        if (opts.signal.aborted)
            controller.abort();
        else
            opts.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }
    try {
        const res = await fetchImpl(KEV_URL, { signal: controller.signal });
        if (!res.ok)
            return { ok: false, reason: `CISA KEV feed returned http ${res.status}` };
        const json = (await res.json());
        if (!Array.isArray(json.vulnerabilities)) {
            return { ok: false, reason: 'CISA KEV feed response had no `vulnerabilities` array' };
        }
        return { ok: true, entries: parseEntries(json.vulnerabilities) };
    }
    catch (e) {
        return { ok: false, reason: describeFetchError(e) };
    }
    finally {
        clearTimeout(timeout);
    }
}
function parseEntries(vulnerabilities) {
    const entries = new Map();
    for (const raw of vulnerabilities) {
        if (raw === null || typeof raw !== 'object')
            continue;
        const rec = raw;
        const cveId = typeof rec['cveID'] === 'string' ? rec['cveID'] : undefined;
        const dateAdded = typeof rec['dateAdded'] === 'string' ? rec['dateAdded'] : undefined;
        if (cveId === undefined || dateAdded === undefined)
            continue;
        entries.set(cveId, dateAdded);
    }
    return entries;
}
function describeFetchError(e) {
    if (e instanceof Error) {
        if (e.name === 'AbortError')
            return 'CISA KEV feed request timed out';
        return e.message;
    }
    return 'CISA KEV feed request failed';
}
//# sourceMappingURL=kev.js.map