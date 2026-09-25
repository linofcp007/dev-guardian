import { describe, expect, it, vi } from 'vitest';
import { getKevCatalog, KEV_CATALOG_TTL_MS } from '../../../src/intel/kevCache.js';

const NOW = Date.parse('2026-09-25T12:00:00.000Z');

/** A runtimeMeta fake that actually persists state across calls, in memory —
 *  needed to prove the catalog survives a SECOND `getKevCatalog` call. */
function fakeRuntimeMeta() {
  const store = new Map<string, string>();
  return {
    getJson: vi.fn((key: string): unknown => {
      const raw = store.get(key);
      return raw === undefined ? null : (JSON.parse(raw) as unknown);
    }),
    setJson: vi.fn((key: string, value: unknown): void => {
      store.set(key, JSON.stringify(value));
    }),
  };
}

function ok(entries: Array<[string, string]>) {
  return { ok: true as const, entries: new Map(entries) };
}

describe('getKevCatalog', () => {
  it('fetches and caches the catalog on a cold cache', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const fetchKevCatalogImpl = vi.fn().mockResolvedValue(ok([['CVE-A', '2026-01-01']]));
    const res = await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl });
    expect(fetchKevCatalogImpl).toHaveBeenCalledTimes(1);
    expect(res).toEqual({ ok: true, entries: new Map([['CVE-A', '2026-01-01']]), stale: false, fetched_at: new Date(NOW).toISOString() });
    expect(storage.runtimeMeta.setJson).toHaveBeenCalledTimes(1);
  });

  it('a SECOND call within the TTL is served from the cache, with NO fetch at all', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const fetchKevCatalogImpl = vi.fn().mockResolvedValue(ok([['CVE-A', '2026-01-01']]));
    await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl });
    const res = await getKevCatalog(storage, { now: NOW + 1000, fetchKevCatalogImpl });
    expect(fetchKevCatalogImpl).toHaveBeenCalledTimes(1); // still just the first call
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.entries.get('CVE-A')).toBe('2026-01-01');
    expect(res.stale).toBe(false);
  });

  it('a call past the TTL refreshes again', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const fetchKevCatalogImpl = vi.fn().mockResolvedValue(ok([['CVE-A', '2026-01-01']]));
    await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl });
    await getKevCatalog(storage, { now: NOW + KEV_CATALOG_TTL_MS + 1000, fetchKevCatalogImpl });
    expect(fetchKevCatalogImpl).toHaveBeenCalledTimes(2);
  });

  it('a stale cache whose refresh fails falls back to the stale value, flagged', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const first = vi.fn().mockResolvedValue(ok([['CVE-A', '2026-01-01']]));
    await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl: first });
    const failing = vi.fn().mockResolvedValue({ ok: false, reason: 'CISA KEV feed returned http 503' });
    const res = await getKevCatalog(storage, { now: NOW + KEV_CATALOG_TTL_MS + 1000, fetchKevCatalogImpl: failing });
    expect(res).toMatchObject({ ok: true, stale: true });
    if (!res.ok) return;
    expect(res.entries.get('CVE-A')).toBe('2026-01-01');
  });

  it('no cache and a failed fetch is reported unavailable, never an empty-but-ok catalog', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const failing = vi.fn().mockResolvedValue({ ok: false, reason: 'no fetch implementation available' });
    const res = await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl: failing });
    expect(res).toEqual({ ok: false, reason: 'no fetch implementation available' });
  });

  it('offline with a cached (even stale) catalog serves it, flagged stale, no fetch attempted', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const fetchKevCatalogImpl = vi.fn().mockResolvedValue(ok([['CVE-A', '2026-01-01']]));
    await getKevCatalog(storage, { now: NOW, fetchKevCatalogImpl });
    const res = await getKevCatalog(storage, { now: NOW + KEV_CATALOG_TTL_MS + 1000, offline: true, fetchKevCatalogImpl });
    expect(fetchKevCatalogImpl).toHaveBeenCalledTimes(1); // only the first (online) call
    expect(res).toMatchObject({ ok: true, stale: true });
  });

  it('offline with no cache at all is unavailable, never a fabricated empty catalog', async () => {
    const storage = { runtimeMeta: fakeRuntimeMeta() };
    const fetchKevCatalogImpl = vi.fn();
    const res = await getKevCatalog(storage, { now: NOW, offline: true, fetchKevCatalogImpl });
    expect(fetchKevCatalogImpl).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });
});
