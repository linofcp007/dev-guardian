/**
 * wp.org plugin directory health, per slug: closed/removed, or not updated
 * in over two years — signals the Wordfence feed does not carry at all (a
 * closed plugin is not necessarily a KNOWN vulnerability, just unmaintained
 * or pulled for a reason wp.org itself states).
 *
 * `GET https://api.wordpress.org/plugins/info/1.2/?action=plugin_information
 * &request[slug]=<slug>` — no key, no auth, verified LIVE 2026-09-25:
 *
 *   - a plugin currently in the directory: `{ slug, version, last_updated:
 *     "2026-08-18 11:42pm GMT", ... }`, HTTP 200;
 *   - a plugin closed by wp.org: `{ error: "closed", name, slug,
 *     description, closed: true, closed_date: "2021-01-30", reason:
 *     "security-issue", reason_text: "Security Issue" }`, HTTP **404**;
 *   - a slug wp.org has never heard of: `{ error: "Plugin not found." }`,
 *     also HTTP **404**.
 *
 * Both error cases share the status code, so the body's `error` field is
 * what tells "closed" (a real, actionable signal) apart from "not found"
 * (commonly a premium/private plugin never listed on wp.org at all — not
 * evidence of anything). Any `error` value other than exactly `"closed"` is
 * read as "not found" rather than matched against wp.org's exact wording,
 * so a future rewording of that one string does not silently misclassify a
 * real closure as absence.
 *
 * Cached per slug in `runtime_meta` (Task 19's `intel/kevCache.ts` pattern:
 * small values, shared across projects, its own TTL) — unlike the Wordfence
 * feed itself, these responses are tiny, so there is no reason to keep them
 * off SQLite the way `vulnFeed.ts`'s ~100 MB blob is kept off it.
 */
export const WP_ORG_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const TWO_YEARS_MS = 2 * 365 * 24 * 60 * 60 * 1000;
/** Written to `findings.tool` for a closed/stale-plugin finding. */
export const WP_ORG_TOOL_NAME = 'wp-plugin-api';
const WP_ORG_URL = 'https://api.wordpress.org/plugins/info/1.2/';
const DEFAULT_TIMEOUT_MS = 8000;
const CACHE_KEY_PREFIX = 'intel:wporg_plugin:';
/**
 * One plugin's wp.org health, cache-first. Mirrors
 * `intel/kevCache.ts#getKevCatalog` and `intel/enrich.ts`'s `GUARDIAN_OFFLINE`
 * handling: offline (or a network failure) serves a stale cached value when
 * one exists, else `status: 'unavailable'` with a `reason` — never a
 * fabricated `plugin_status: 'found'`.
 */
export async function checkWpOrgPlugin(storage, slug, opts = {}) {
    const now = opts.now ?? Date.now();
    const cacheKey = `${CACHE_KEY_PREFIX}${slug}`;
    const cached = parseCachedEntry(storage.runtimeMeta.getJson(cacheKey));
    const cachedFresh = cached !== null && now - Date.parse(cached.fetched_at) < WP_ORG_CACHE_TTL_MS;
    if (cachedFresh && cached !== null) {
        return { slug, status: 'ok', ...toResultFields(cached) };
    }
    const offline = opts.offline ?? (opts.env ?? process.env)['GUARDIAN_OFFLINE'] === '1';
    if (offline) {
        if (cached !== null)
            return { slug, status: 'ok', stale: true, reason: 'network disabled (GUARDIAN_OFFLINE=1)', ...toResultFields(cached) };
        return { slug, status: 'unavailable', reason: 'network disabled (GUARDIAN_OFFLINE=1)' };
    }
    const fetched = await fetchWpOrgPluginInfo(slug, opts);
    if (fetched.ok) {
        const entry = { fetched_at: new Date(now).toISOString(), plugin_status: fetched.plugin_status };
        if (fetched.last_updated !== undefined)
            entry.last_updated = fetched.last_updated;
        if (fetched.closed_date !== undefined)
            entry.closed_date = fetched.closed_date;
        if (fetched.closure_reason !== undefined)
            entry.closure_reason = fetched.closure_reason;
        if (fetched.closure_reason_text !== undefined)
            entry.closure_reason_text = fetched.closure_reason_text;
        storage.runtimeMeta.setJson(cacheKey, entry);
        return { slug, status: 'ok', ...toResultFields(entry) };
    }
    if (cached !== null)
        return { slug, status: 'ok', stale: true, reason: fetched.reason, ...toResultFields(cached) };
    return { slug, status: 'unavailable', reason: fetched.reason };
}
function toResultFields(entry) {
    const out = {
        plugin_status: entry.plugin_status,
        fetched_at: entry.fetched_at,
    };
    if (entry.last_updated !== undefined)
        out.last_updated = entry.last_updated;
    if (entry.closed_date !== undefined)
        out.closed_date = entry.closed_date;
    if (entry.closure_reason !== undefined)
        out.closure_reason = entry.closure_reason;
    if (entry.closure_reason_text !== undefined)
        out.closure_reason_text = entry.closure_reason_text;
    return out;
}
function parseCachedEntry(raw) {
    if (raw === null || typeof raw !== 'object')
        return null;
    const rec = raw;
    if (typeof rec['fetched_at'] !== 'string')
        return null;
    const status = rec['plugin_status'];
    if (status !== 'found' && status !== 'closed' && status !== 'not_found')
        return null;
    const entry = { fetched_at: rec['fetched_at'], plugin_status: status };
    if (typeof rec['last_updated'] === 'string')
        entry.last_updated = rec['last_updated'];
    if (typeof rec['closed_date'] === 'string')
        entry.closed_date = rec['closed_date'];
    if (typeof rec['closure_reason'] === 'string')
        entry.closure_reason = rec['closure_reason'];
    if (typeof rec['closure_reason_text'] === 'string')
        entry.closure_reason_text = rec['closure_reason_text'];
    return entry;
}
async function fetchWpOrgPluginInfo(slug, opts) {
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
        const url = `${WP_ORG_URL}?action=plugin_information&request%5Bslug%5D=${encodeURIComponent(slug)}`;
        const res = await fetchImpl(url, { signal: controller.signal });
        let json;
        try {
            json = await res.json();
        }
        catch {
            return { ok: false, reason: `wp.org plugin API returned unparsable JSON (http ${res.status})` };
        }
        const errorField = getStringProp(json, 'error');
        if (errorField === 'closed') {
            const result = { ok: true, plugin_status: 'closed' };
            const closedDate = getStringProp(json, 'closed_date');
            const reason = getStringProp(json, 'reason');
            const reasonText = getStringProp(json, 'reason_text');
            if (closedDate !== undefined)
                result.closed_date = closedDate;
            if (reason !== undefined)
                result.closure_reason = reason;
            if (reasonText !== undefined)
                result.closure_reason_text = reasonText;
            return result;
        }
        if (errorField !== undefined)
            return { ok: true, plugin_status: 'not_found' };
        if (!res.ok)
            return { ok: false, reason: `wp.org plugin API returned http ${res.status}` };
        const lastUpdatedRaw = getStringProp(json, 'last_updated');
        const result = { ok: true, plugin_status: 'found' };
        const lastUpdatedIso = lastUpdatedRaw !== undefined ? parseWpOrgDate(lastUpdatedRaw) : null;
        if (lastUpdatedIso !== null)
            result.last_updated = lastUpdatedIso;
        return result;
    }
    catch (e) {
        return { ok: false, reason: describeFetchError(e) };
    }
    finally {
        clearTimeout(timeout);
    }
}
function getStringProp(obj, key) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj))
        return undefined;
    const v = obj[key];
    return typeof v === 'string' ? v : undefined;
}
/** wp.org's own date format: `"2026-08-18 11:42pm GMT"` — 12-hour, no
 *  leading zero on the hour, always GMT. Parsed explicitly rather than via
 *  `Date.parse`, which does not reliably accept this shape. */
const WP_ORG_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})\s+(\d{1,2}):(\d{2})(am|pm)\s+GMT$/i;
function parseWpOrgDate(raw) {
    const m = WP_ORG_DATE_RE.exec(raw.trim());
    if (!m)
        return null;
    const [, y, mo, d, hRaw, mi, ampm] = m;
    let hour = parseInt(hRaw, 10) % 12;
    if (ampm.toLowerCase() === 'pm')
        hour += 12;
    const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), hour, Number(mi));
    return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}
function describeFetchError(e) {
    if (e instanceof Error) {
        if (e.name === 'AbortError')
            return 'wp.org plugin API request timed out';
        return e.message;
    }
    return 'wp.org plugin API request failed';
}
/** Whether an ISO `last_updated` is more than two years before `now`. An
 *  approximation (365-day years, no leap-year precision) — plenty for a
 *  "abandoned plugin" signal. */
export function isStalePlugin(lastUpdatedIso, now) {
    const parsed = Date.parse(lastUpdatedIso);
    if (!Number.isFinite(parsed))
        return false;
    return now - parsed > TWO_YEARS_MS;
}
//# sourceMappingURL=wpOrgHealth.js.map