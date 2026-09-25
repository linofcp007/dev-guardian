import { describe, expect, it, vi } from 'vitest';
import { fetchKevCatalog } from '../../../src/intel/kev.js';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

function kevBody(entries: Array<{ cveID: string; dateAdded: string }>): unknown {
  return {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    catalogVersion: '2026.09.25',
    dateReleased: '2026-09-25T00:00:00.000Z',
    count: entries.length,
    vulnerabilities: entries,
  };
}

describe('fetchKevCatalog', () => {
  it('fetches the CISA feed exactly once and indexes it by CVE id', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse(
        kevBody([
          { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' },
          { cveID: 'CVE-2026-67279', dateAdded: '2026-09-25' },
        ]),
      ),
    );
    const res = await fetchKevCatalog({ fetchImpl });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(String(fetchImpl.mock.calls[0]?.[0])).toContain('cisa.gov');
    expect(res.entries.get('CVE-2021-44228')).toBe('2021-12-10');
    expect(res.entries.get('CVE-2026-67279')).toBe('2026-09-25');
  });

  it('a CVE absent from the catalog is simply absent from `entries`', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(kevBody([])));
    const res = await fetchKevCatalog({ fetchImpl });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.entries.has('CVE-NOT-LISTED')).toBe(false);
  });

  it('reports a non-2xx response as a failure', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({}, 500));
    const res = await fetchKevCatalog({ fetchImpl });
    expect(res).toEqual({ ok: false, reason: expect.stringContaining('500') });
  });

  it('reports a network error as a failure, never an empty catalog', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('ECONNRESET'));
    const res = await fetchKevCatalog({ fetchImpl });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.reason).toContain('ECONNRESET');
  });

  it('reports malformed JSON (no `vulnerabilities` array) as a failure, not an empty catalog', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ not: 'the expected shape' }));
    const res = await fetchKevCatalog({ fetchImpl });
    expect(res.ok).toBe(false);
  });

  it('aborts and reports a timeout instead of hanging', async () => {
    const fetchImpl: typeof fetch = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    const res = await fetchKevCatalog({ fetchImpl, timeoutMs: 5 });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.reason.toLowerCase()).toMatch(/abort|timed out/);
  });
});
