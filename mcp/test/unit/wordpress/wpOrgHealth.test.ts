/**
 * `checkWpOrgPlugin` — wp.org's `plugins/info/1.2` API, queried per plugin
 * to flag a closed/removed listing or one not updated in > 2 years.
 *
 * Response shapes below are copied from a LIVE request made while writing
 * this feature (2026-09-25): both "closed" and "genuinely not in the
 * directory" answer HTTP 404, distinguished only by the JSON body's
 * `error` field — `"closed"` vs `"Plugin not found."` — so status code
 * alone cannot tell them apart; the parser must read the body either way.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  checkWpOrgPlugin,
  checkWpOrgPlugins,
  isStalePlugin,
  TWO_YEARS_MS,
  WP_ORG_CACHE_TTL_MS,
  type WpOrgHealthStorage,
} from '../../../src/wordpress/wpOrgHealth.js';

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fakeStorage(): WpOrgHealthStorage & { dump: () => Record<string, unknown> } {
  const store = new Map<string, unknown>();
  return {
    runtimeMeta: {
      getJson: (key: string) => store.get(key) ?? null,
      setJson: (key: string, value: unknown) => {
        store.set(key, value);
      },
    },
    dump: () => Object.fromEntries(store),
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

describe('checkWpOrgPlugin', () => {
  it('reports a found plugin with its parsed last_updated date', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { slug: 'akismet', version: '5.7.2', last_updated: '2026-08-18 11:42pm GMT' }),
    );

    const r = await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl });

    expect(r.status).toBe('ok');
    expect(r.plugin_status).toBe('found');
    expect(r.last_updated).toBe('2026-08-18T23:42:00.000Z');
  });

  it('distinguishes "closed" from "not found" even though both are HTTP 404', async () => {
    const storage = fakeStorage();
    const closedFetch = vi.fn(async () =>
      jsonResponse(404, {
        error: 'closed',
        name: 'Display Widgets',
        slug: 'display-widgets',
        closed: true,
        closed_date: '2021-01-30',
        reason: 'security-issue',
        reason_text: 'Security Issue',
      }),
    );
    const notFoundFetch = vi.fn(async () => jsonResponse(404, { error: 'Plugin not found.' }));

    const closed = await checkWpOrgPlugin(storage, 'display-widgets', { env: {}, fetchImpl: closedFetch });
    const notFound = await checkWpOrgPlugin(storage, 'some-premium-plugin', { env: {}, fetchImpl: notFoundFetch });

    expect(closed.plugin_status).toBe('closed');
    expect(closed.closure_reason).toBe('security-issue');
    expect(closed.closed_date).toBe('2021-01-30');

    expect(notFound.plugin_status).toBe('not_found');
    expect(notFound.closure_reason).toBeUndefined();
  });

  it('caches a result and does not re-fetch within the TTL', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () => jsonResponse(200, { last_updated: '2026-08-18 11:42pm GMT' }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');

    await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, now: t0 });
    await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, now: t0 + 1000 });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('refreshes once the cached entry is older than its TTL', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () => jsonResponse(200, { last_updated: '2026-08-18 11:42pm GMT' }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');

    await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, now: t0 });
    await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, now: t0 + WP_ORG_CACHE_TTL_MS + 1000 });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('honours GUARDIAN_OFFLINE=1 and serves a stale cache rather than nothing', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () => jsonResponse(200, { last_updated: '2026-08-18 11:42pm GMT' }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');
    await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, now: t0 });

    const r = await checkWpOrgPlugin(storage, 'akismet', {
      offline: true,
      fetchImpl,
      now: t0 + WP_ORG_CACHE_TTL_MS + 1000,
    });

    expect(r.status).toBe('ok');
    expect(r.stale).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports unavailable (never a fabricated "found") with no cache under GUARDIAN_OFFLINE=1', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn();

    const r = await checkWpOrgPlugin(storage, 'akismet', { offline: true, fetchImpl });

    expect(r.status).toBe('unavailable');
    expect(r.reason).toMatch(/GUARDIAN_OFFLINE/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('reports unavailable on a network error with no prior cache', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () => {
      throw new Error('boom');
    });

    const r = await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl });

    expect(r.status).toBe('unavailable');
    expect(r.reason).toContain('boom');
  });

  it('a timeout aborts and reports unavailable', async () => {
    const storage = fakeStorage();
    const fetchImpl: typeof fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });

    const r = await checkWpOrgPlugin(storage, 'akismet', { env: {}, fetchImpl, timeoutMs: 5 });

    expect(r.status).toBe('unavailable');
    expect(r.reason).toMatch(/timed out/i);
  });
});

describe('isStalePlugin', () => {
  it('is stale when last_updated is more than two years before now', () => {
    const now = Date.parse('2026-09-25T00:00:00Z');
    expect(isStalePlugin('2024-01-01T00:00:00.000Z', now)).toBe(true);
    expect(isStalePlugin(new Date(now - TWO_YEARS_MS - 1).toISOString(), now)).toBe(true);
  });

  it('is not stale within two years', () => {
    const now = Date.parse('2026-09-25T00:00:00Z');
    expect(isStalePlugin('2026-01-01T00:00:00.000Z', now)).toBe(false);
  });
});

// Fix round 1, item 2: sequential, per-plugin-8s-timeout lookups had no
// OVERALL budget — dozens of plugins against a slow wp.org could run for
// many minutes. checkWpOrgPlugins adds bounded concurrency and a deadline;
// anything not finished in time is reported, never silently dropped.
describe('checkWpOrgPlugins (bounded concurrency + overall deadline)', () => {
  it('never runs more lookups at once than the configured concurrency', async () => {
    const storage = fakeStorage();
    let inFlight = 0;
    let maxInFlight = 0;
    const fetchImpl = vi.fn(async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await delay(15);
      inFlight -= 1;
      return jsonResponse(200, { last_updated: '2026-08-18 11:42pm GMT' });
    });
    const slugs = Array.from({ length: 10 }, (_, i) => `plugin-${i}`);

    const { results, notChecked } = await checkWpOrgPlugins(storage, slugs, {
      env: {},
      fetchImpl,
      concurrency: 3,
      overallTimeoutMs: 10_000,
    });

    expect(maxInFlight).toBeLessThanOrEqual(3);
    expect(results).toHaveLength(10);
    expect(notChecked).toEqual([]);
  });

  it('reports plugins not checked before the overall deadline as a gap, not a silent skip', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn(async () => {
      await delay(15);
      return jsonResponse(200, { last_updated: '2026-08-18 11:42pm GMT' });
    });
    const slugs = Array.from({ length: 6 }, (_, i) => `plugin-${i}`);

    const { results, notChecked } = await checkWpOrgPlugins(storage, slugs, {
      env: {},
      fetchImpl,
      concurrency: 2,
      overallTimeoutMs: 20,
    });

    // Deadline (20ms) is well short of the ~45ms three sequential batches of
    // 2 (each 15ms) would need, and well past the first batch alone — some,
    // but not all, plugins are left unchecked. Exact counts are timing-
    // dependent; the invariants below are not.
    expect(results.length).toBeGreaterThan(0);
    expect(notChecked.length).toBeGreaterThan(0);
    expect(results.length + notChecked.length).toBe(6);
    expect(new Set([...results.map((r) => r.slug), ...notChecked])).toEqual(new Set(slugs));
  }, 10_000);

  it('an empty slug list returns immediately with no calls', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn();

    const { results, notChecked } = await checkWpOrgPlugins(storage, [], { env: {}, fetchImpl });

    expect(results).toEqual([]);
    expect(notChecked).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('honours GUARDIAN_OFFLINE=1 for every plugin, with no network calls at all', async () => {
    const storage = fakeStorage();
    const fetchImpl = vi.fn();

    const { results, notChecked } = await checkWpOrgPlugins(storage, ['a', 'b'], { offline: true, fetchImpl });

    expect(notChecked).toEqual([]);
    expect(results.every((r) => r.status === 'unavailable')).toBe(true);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
