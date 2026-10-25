/**
 * KEV and EPSS are bounded in size and in time (review of 3.6.0, finding 12):
 * both read `res.json()` whole, bounded only by a timeout, and EPSS asked its
 * 100-CVE batches one after the other, 6 s each — past ~1000 CVEs a call ran
 * beyond the host's 60 s budget.
 */

import { describe, expect, it, vi } from 'vitest';
import { queryEpss } from '../../../src/intel/epss.js';
import { enrichCveIntel } from '../../../src/intel/enrich.js';
import { fetchKevCatalog } from '../../../src/intel/kev.js';

/** A body that claims to be larger than any cap. */
const huge = (): Response => new Response('{}', { status: 200, headers: { 'content-length': String(512 * 1024 * 1024) } });

describe('size', () => {
  it('a KEV feed over its cap is a failure, not read', async () => {
    const res = await fetchKevCatalog({ fetchImpl: vi.fn(async () => huge()) });
    expect(res).toEqual({ ok: false, reason: expect.stringMatching(/over \d+ MiB/) });
  });

  it('an EPSS answer over its cap is a failure, not read', async () => {
    const res = await queryEpss(['CVE-2026-0001'], { fetchImpl: vi.fn(async () => huge()) });
    expect(res).toEqual({ ok: false, reason: expect.stringMatching(/over \d+ MiB/) });
  });
});

describe('time', () => {
  it('EPSS batches go several at a time, never more than four', async () => {
    let inFlight = 0;
    let peak = 0;
    const fetchImpl = vi.fn(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight -= 1;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    });
    const ids = Array.from({ length: 1000 }, (_, i) => `CVE-2026-${10000 + i}`);
    const res = await queryEpss(ids, { fetchImpl });
    expect(res.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(10);
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(4);
  });

  it('one call refreshes at most 1000 stale CVEs; the rest are unavailable, never "not in KEV"', async () => {
    const storage = {
      cveIntel: { getMany: vi.fn(() => new Map()), upsertMany: vi.fn() },
      runtimeMeta: { getJson: vi.fn(() => null), setJson: vi.fn() },
    };
    const asked: string[] = [];
    const ids = Array.from({ length: 1200 }, (_, i) => `CVE-2026-${20000 + i}`);
    const result = await enrichCveIntel(storage, ids, {
      env: {},
      queryEpssImpl: async (cves) => {
        asked.push(...cves);
        return { ok: true, scores: new Map() };
      },
      fetchKevCatalogImpl: async () => ({ ok: true, entries: new Map() }),
    });
    expect(asked).toHaveLength(1000);
    const left = ids.slice(1000).map((id) => result.get(id));
    expect(left.every((r) => r?.status === 'unavailable')).toBe(true);
    expect(left[0]?.reason).toMatch(/not refreshed in this call/);
    expect(result.get(ids[0] ?? '')?.status).toBe('ok');
  });
});
