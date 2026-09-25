/**
 * The CISA KEV catalog, cached as ONE shared blob — never per CVE.
 *
 * `intel/enrich.ts`'s per-CVE `cve_intel` cache is keyed by `cve_id`, so its
 * own 24h freshness check answers "does THIS CVE need a refresh" — which,
 * for the KEV half of that refresh, is the wrong question: the catalog is
 * ONE ~1700-entry download that answers for every CVE at once, and the
 * first version of `enrich.ts` called {@link fetchKevCatalog} again every
 * time ANY CVE was stale or new. Measured impact: a CI pipeline calling
 * `risk_score` once per commit re-downloaded the whole feed on every commit
 * that introduced a new dependency's CVE — many downloads a day for one
 * feed that changes at most a few times a day.
 *
 * This module gives the catalog its OWN cache, in `runtime_meta`
 * (`storage/runtimeMetaRepo.ts` — a plain key/value store, already global
 * rather than project-scoped, which is exactly what one shared feed needs)
 * under `KEV_CATALOG_KEY`, with its own `fetched_at` and its own
 * {@link KEV_CATALOG_TTL_MS}. `intel/enrich.ts` calls {@link getKevCatalog}
 * once per `enrichCveIntel` call (never per CVE); a CVE that is individually
 * stale/new but arrives while the CATALOG is still within its TTL is
 * answered from that cache with no network call at all — which is the
 * point: the two staleness clocks are now independent, and only the
 * catalog's clock gates a download.
 */

import { fetchKevCatalog, type KevCatalogOptions, type KevCatalogResult } from './kev.js';

/** How often the catalog itself may be re-downloaded, regardless of how many
 *  distinct CVEs ask about it in the meantime. Same value as
 *  `enrich.ts#INTEL_TTL_MS` (both 24h) by policy, not by necessity — kept as
 *  its own named constant since the two caches are otherwise independent. */
export const KEV_CATALOG_TTL_MS = 24 * 60 * 60 * 1000;

const KEV_CATALOG_KEY = 'intel:kev_catalog';

interface StoredKevCatalog {
  fetched_at: string;
  /** `cveID -> dateAdded`, `Map` serialised as a plain object for JSON. */
  entries: Record<string, string>;
}

export interface KevCatalogStorage {
  runtimeMeta: {
    // Non-generic on purpose: `RuntimeMetaRepo#getJson<T>` (the real
    // implementation) still satisfies this — a generic method is always
    // assignable to the type it produces when instantiated at `unknown` —
    // but a plain test fake's `(key: string) => unknown` does not need to
    // reproduce genericity it will never be asked for. This module casts the
    // result itself (see `getKevCatalog` below).
    getJson(key: string): unknown;
    setJson(key: string, value: unknown): void;
  };
}

export type CachedKevCatalogResult =
  | { ok: true; entries: Map<string, string>; stale: boolean; fetched_at: string }
  | { ok: false; reason: string };

export interface GetKevCatalogOptions {
  /** Injected clock — never call `Date.now()` here directly. */
  now?: number;
  /** Skips the network step; serves a cached catalog (even stale) if one
   *  exists, else `unavailable`. Callers pass their own already-resolved
   *  offline decision — this module does not itself read `GUARDIAN_OFFLINE`,
   *  so there is exactly one place (`enrich.ts`) that decides it. */
  offline?: boolean;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Test-only injection point; defaults to the real {@link fetchKevCatalog}. */
  fetchKevCatalogImpl?: (opts: KevCatalogOptions) => Promise<KevCatalogResult>;
}

/**
 * The CISA KEV catalog: served from the shared cache when it is within
 * {@link KEV_CATALOG_TTL_MS}; otherwise refreshed (unless `offline`) and
 * re-cached. A refresh that fails falls back to a stale cached catalog
 * (`stale: true` — still real data) when one exists, else `{ ok: false }` —
 * never a fabricated empty-but-ok catalog, which would read as "no CVE is
 * KEV-listed" instead of "KEV status is unmeasured".
 */
export async function getKevCatalog(
  storage: KevCatalogStorage,
  opts: GetKevCatalogOptions = {},
): Promise<CachedKevCatalogResult> {
  const now = opts.now ?? Date.now();
  const cached = parseStoredCatalog(storage.runtimeMeta.getJson(KEV_CATALOG_KEY));
  const cachedFresh = cached !== null && now - Date.parse(cached.fetched_at) < KEV_CATALOG_TTL_MS;
  if (cachedFresh && cached !== null) {
    return { ok: true, entries: toMap(cached.entries), stale: false, fetched_at: cached.fetched_at };
  }

  if (opts.offline === true) {
    if (cached !== null) return { ok: true, entries: toMap(cached.entries), stale: true, fetched_at: cached.fetched_at };
    return { ok: false, reason: 'network disabled (GUARDIAN_OFFLINE=1)' };
  }

  const fetchKevCatalogImpl = opts.fetchKevCatalogImpl ?? fetchKevCatalog;
  const netOpts: KevCatalogOptions = {};
  if (opts.fetchImpl !== undefined) netOpts.fetchImpl = opts.fetchImpl;
  if (opts.timeoutMs !== undefined) netOpts.timeoutMs = opts.timeoutMs;
  if (opts.signal !== undefined) netOpts.signal = opts.signal;
  const fetched = await fetchKevCatalogImpl(netOpts);

  if (fetched.ok) {
    const fetchedAt = new Date(now).toISOString();
    const stored: StoredKevCatalog = { fetched_at: fetchedAt, entries: Object.fromEntries(fetched.entries) };
    storage.runtimeMeta.setJson(KEV_CATALOG_KEY, stored);
    return { ok: true, entries: fetched.entries, stale: false, fetched_at: fetchedAt };
  }
  if (cached !== null) return { ok: true, entries: toMap(cached.entries), stale: true, fetched_at: cached.fetched_at };
  return { ok: false, reason: fetched.reason };
}

function toMap(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

/** A damaged/foreign value under `KEV_CATALOG_KEY` (or none at all) reads as
 *  "never cached", never as a crash — the same "survives a broken row"
 *  discipline `validationsRepo.ts#rowToValidation` uses for `cve_intel`'s
 *  own JSON columns. */
function parseStoredCatalog(raw: unknown): StoredKevCatalog | null {
  if (raw === null || typeof raw !== 'object') return null;
  const rec = raw as Record<string, unknown>;
  if (typeof rec['fetched_at'] !== 'string') return null;
  if (rec['entries'] === null || typeof rec['entries'] !== 'object' || Array.isArray(rec['entries'])) return null;
  const entries: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec['entries'] as Record<string, unknown>)) {
    if (typeof v === 'string') entries[k] = v;
  }
  return { fetched_at: rec['fetched_at'], entries };
}
