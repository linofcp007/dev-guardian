import { describe, expect, it, vi } from 'vitest';
import { queryEpss } from '../../../src/intel/epss.js';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

function epssBody(entries: Array<{ cve: string; epss: string; percentile: string }>): unknown {
  return { status: 'OK', 'status-code': 200, total: entries.length, offset: 0, limit: 100, data: entries };
}

describe('queryEpss', () => {
  it('returns an empty, ok result without calling fetch at all for no CVEs', async () => {
    const fetchImpl = vi.fn();
    const res = await queryEpss([], { fetchImpl });
    expect(res).toEqual({ ok: true, scores: new Map() });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('parses scores and percentiles as numbers, keyed by CVE id', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse(epssBody([{ cve: 'CVE-2021-44228', epss: '0.97577', percentile: '0.99997' }])),
    );
    const res = await queryEpss(['CVE-2021-44228'], { fetchImpl });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.scores.get('CVE-2021-44228')).toEqual({ score: 0.97577, percentile: 0.99997 });
  });

  it('requests the comma-joined batch in a single call for <=100 CVEs', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(epssBody([])));
    await queryEpss(['CVE-A', 'CVE-B'], { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const url = String(fetchImpl.mock.calls[0]?.[0]);
    expect(url).toContain('api.first.org/data/v1/epss');
    expect(url).toContain('CVE-A,CVE-B');
  });

  it('splits more than 100 CVEs into multiple batched requests', async () => {
    const many = Array.from({ length: 150 }, (_, i) => `CVE-2026-${1000 + i}`);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(epssBody([])));
    const res = await queryEpss(many, { fetchImpl });
    expect(res.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    const firstUrl = String(fetchImpl.mock.calls[0]?.[0]);
    const secondUrl = String(fetchImpl.mock.calls[1]?.[0]);
    expect(firstUrl.split('cve=')[1]?.split(',')).toHaveLength(100);
    expect(secondUrl.split('cve=')[1]?.split(',')).toHaveLength(50);
  });

  it('CVEs the feed does not mention are simply absent from `scores`', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(epssBody([])));
    const res = await queryEpss(['CVE-UNKNOWN'], { fetchImpl });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.scores.has('CVE-UNKNOWN')).toBe(false);
  });

  it('reports a non-2xx HTTP response as a failure, not an empty success', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({}, 503));
    const res = await queryEpss(['CVE-A'], { fetchImpl });
    expect(res).toEqual({ ok: false, reason: expect.stringContaining('503') });
  });

  it('reports a network error as a failure', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('getaddrinfo ENOTFOUND'));
    const res = await queryEpss(['CVE-A'], { fetchImpl });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.reason).toContain('ENOTFOUND');
  });

  it('aborts and reports a timeout instead of hanging', async () => {
    const fetchImpl: typeof fetch = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    const res = await queryEpss(['CVE-A'], { fetchImpl, timeoutMs: 5 });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.reason.toLowerCase()).toMatch(/abort|timed out/);
  });
});
