import { describe, expect, it, vi } from 'vitest';
import { enrichCveIntel, INTEL_TTL_MS } from '../../../src/intel/enrich.js';
import type { CveIntelRow } from '../../../src/storage/cveIntelRepo.js';

const NOW = Date.parse('2026-09-25T12:00:00.000Z');

function fakeStorage(rows: CveIntelRow[] = []) {
  const byId = new Map(rows.map((r) => [r.cve_id, r]));
  const getMany = vi.fn((ids: readonly string[]) => {
    const out = new Map<string, CveIntelRow>();
    for (const id of ids) {
      const row = byId.get(id);
      if (row) out.set(id, row);
    }
    return out;
  });
  const upsertMany = vi.fn();
  return { cveIntel: { getMany, upsertMany } };
}

function freshRow(over: Partial<CveIntelRow> = {}): CveIntelRow {
  return {
    cve_id: 'CVE-FRESH',
    epss_score: 0.5,
    epss_percentile: 0.6,
    kev: false,
    kev_date_added: null,
    fetched_at: new Date(NOW - 1000).toISOString(), // 1s old — well within TTL
    ...over,
  };
}

describe('enrichCveIntel', () => {
  it('returns an empty map and never touches storage for no CVE ids', async () => {
    const storage = fakeStorage();
    const result = await enrichCveIntel(storage, []);
    expect(result).toEqual(new Map());
    expect(storage.cveIntel.getMany).not.toHaveBeenCalled();
  });

  it('serves a fresh cached row from the cache alone, with no network call', async () => {
    const storage = fakeStorage([freshRow({ cve_id: 'CVE-FRESH', kev: true, kev_date_added: '2026-01-01' })]);
    const queryEpss = vi.fn();
    const fetchKevCatalog = vi.fn();
    const result = await enrichCveIntel(storage, ['CVE-FRESH'], { now: NOW, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog });
    expect(queryEpss).not.toHaveBeenCalled();
    expect(fetchKevCatalog).not.toHaveBeenCalled();
    expect(result.get('CVE-FRESH')).toEqual({
      cve_id: 'CVE-FRESH', status: 'ok', kev: true, kev_date_added: '2026-01-01',
      epss_score: 0.5, epss_percentile: 0.6, fetched_at: freshRow().fetched_at,
    });
  });

  it('a cached row older than the TTL is treated as stale and refreshed', async () => {
    const staleRow = freshRow({ cve_id: 'CVE-STALE', fetched_at: new Date(NOW - INTEL_TTL_MS - 1000).toISOString() });
    const storage = fakeStorage([staleRow]);
    const queryEpss = vi.fn().mockResolvedValue({ ok: true, scores: new Map([['CVE-STALE', { score: 0.9, percentile: 0.95 }]]) });
    const fetchKevCatalog = vi.fn().mockResolvedValue({ ok: true, entries: new Map([['CVE-STALE', '2026-09-20']]) });
    const result = await enrichCveIntel(storage, ['CVE-STALE'], { now: NOW, env: {}, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog });
    expect(queryEpss).toHaveBeenCalledWith(['CVE-STALE'], expect.anything());
    expect(result.get('CVE-STALE')).toMatchObject({ status: 'ok', kev: true, kev_date_added: '2026-09-20', epss_score: 0.9 });
    expect(storage.cveIntel.upsertMany).toHaveBeenCalledWith([
      expect.objectContaining({ cve_id: 'CVE-STALE', kev: true, epss_score: 0.9, fetched_at: new Date(NOW).toISOString() }),
    ]);
  });

  it('only asks the network for the CVEs that actually need refreshing, not the fresh ones too', async () => {
    const storage = fakeStorage([freshRow({ cve_id: 'CVE-FRESH' })]);
    const queryEpss = vi.fn().mockResolvedValue({ ok: true, scores: new Map() });
    const fetchKevCatalog = vi.fn().mockResolvedValue({ ok: true, entries: new Map() });
    await enrichCveIntel(storage, ['CVE-FRESH', 'CVE-NEW'], { now: NOW, env: {}, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog });
    expect(queryEpss).toHaveBeenCalledWith(['CVE-NEW'], expect.anything());
  });

  it('a never-cached CVE that could not be fetched is reported unavailable, never a fabricated clean result', async () => {
    const storage = fakeStorage();
    const queryEpss = vi.fn().mockResolvedValue({ ok: false, reason: 'EPSS http 503' });
    const fetchKevCatalog = vi.fn().mockResolvedValue({ ok: true, entries: new Map() });
    const result = await enrichCveIntel(storage, ['CVE-NEW'], { now: NOW, env: {}, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog });
    expect(result.get('CVE-NEW')).toEqual({
      cve_id: 'CVE-NEW', status: 'unavailable', kev: false,
      reason: expect.stringContaining('EPSS http 503'),
    });
    expect(storage.cveIntel.upsertMany).not.toHaveBeenCalled();
  });

  it('a stale-but-previously-cached CVE falls back to its last known value when refresh fails, flagged stale', async () => {
    const staleRow = freshRow({
      cve_id: 'CVE-STALE', kev: true, kev_date_added: '2020-01-01',
      fetched_at: new Date(NOW - INTEL_TTL_MS - 1000).toISOString(),
    });
    const storage = fakeStorage([staleRow]);
    const queryEpss = vi.fn().mockResolvedValue({ ok: false, reason: 'EPSS timed out' });
    const fetchKevCatalog = vi.fn().mockResolvedValue({ ok: false, reason: 'KEV timed out' });
    const result = await enrichCveIntel(storage, ['CVE-STALE'], { now: NOW, env: {}, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog });
    expect(result.get('CVE-STALE')).toMatchObject({
      status: 'ok', stale: true, kev: true, kev_date_added: '2020-01-01', epss_score: 0.5,
      reason: expect.stringContaining('timed out'),
    });
    expect(storage.cveIntel.upsertMany).not.toHaveBeenCalled();
  });

  it('GUARDIAN_OFFLINE=1 skips the network for stale/missing CVEs and marks them unavailable', async () => {
    const storage = fakeStorage();
    const queryEpss = vi.fn();
    const fetchKevCatalog = vi.fn();
    const result = await enrichCveIntel(storage, ['CVE-NEW'], {
      now: NOW, env: { GUARDIAN_OFFLINE: '1' }, queryEpssImpl: queryEpss, fetchKevCatalogImpl: fetchKevCatalog,
    });
    expect(queryEpss).not.toHaveBeenCalled();
    expect(fetchKevCatalog).not.toHaveBeenCalled();
    expect(result.get('CVE-NEW')).toEqual({
      cve_id: 'CVE-NEW', status: 'unavailable', kev: false,
      reason: expect.stringContaining('GUARDIAN_OFFLINE'),
    });
  });

  it('GUARDIAN_OFFLINE=1 still serves a stale cached value rather than discarding it', async () => {
    const staleRow = freshRow({
      cve_id: 'CVE-STALE', fetched_at: new Date(NOW - INTEL_TTL_MS - 1000).toISOString(),
    });
    const storage = fakeStorage([staleRow]);
    const result = await enrichCveIntel(storage, ['CVE-STALE'], { now: NOW, env: { GUARDIAN_OFFLINE: '1' } });
    expect(result.get('CVE-STALE')).toMatchObject({ status: 'ok', stale: true, epss_score: 0.5 });
  });

  it('explicit opts.offline overrides the environment', async () => {
    const storage = fakeStorage();
    const queryEpss = vi.fn();
    const result = await enrichCveIntel(storage, ['CVE-NEW'], {
      now: NOW, offline: true, env: {}, queryEpssImpl: queryEpss,
    });
    expect(queryEpss).not.toHaveBeenCalled();
    expect(result.get('CVE-NEW')?.status).toBe('unavailable');
  });
});
