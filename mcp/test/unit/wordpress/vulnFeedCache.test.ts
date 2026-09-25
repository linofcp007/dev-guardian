/**
 * `getWordfenceFeed` — disk cache (24h TTL, shared across every caller),
 * `GUARDIAN_OFFLINE` honoured, no-API-key handled as a real coverage gap
 * (never a fabricated "0 vulnerabilities"), stale-cache fallback on a
 * refresh failure. No real network: `fetchWordfenceFeedImpl` is always
 * injected.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import {
  defaultWordfenceCacheDir,
  getWordfenceFeed,
  type WordfenceFeed,
  type WordfenceFetchResult,
} from '../../../src/wordpress/vulnFeed.js';

afterAll(cleanupTempDirs);

const SAMPLE_FEED: WordfenceFeed = {
  'uuid-1': {
    id: 'uuid-1',
    title: 'Sample Plugin <= 1.0 - Something',
    software: [
      {
        type: 'plugin',
        name: 'Sample Plugin',
        slug: 'sample-plugin',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '1.0', to_inclusive: true } },
        patched: true,
        patched_versions: ['1.0.1'],
      },
    ],
    cve: 'CVE-2024-0001',
  },
};

describe('getWordfenceFeed', () => {
  it('fetches and caches on a cold cache, given an API key', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn(async (): Promise<WordfenceFetchResult> => ({ ok: true, feed: SAMPLE_FEED }));

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      now: Date.parse('2026-09-25T00:00:00Z'),
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.stale).toBe(false);
      expect(r.feed).toEqual(SAMPLE_FEED);
    }
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const cachedRaw = readFileSync(join(cacheDir, 'wordfence-vulnerabilities-production.json'), 'utf8');
    const cached = JSON.parse(cachedRaw) as { feed: WordfenceFeed; fetched_at: string };
    expect(cached.feed).toEqual(SAMPLE_FEED);
  });

  it('serves a fresh cache with no network call', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn(async (): Promise<WordfenceFetchResult> => ({ ok: true, feed: SAMPLE_FEED }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');

    await getWordfenceFeed({ apiKey: 'test-token', cacheDir, env: {}, now: t0, fetchWordfenceFeedImpl: fetchImpl });
    const r2 = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      now: t0 + 60_000, // one minute later, well within the 24h TTL
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(r2.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1); // not called again
  });

  it('refreshes once the cache is older than 24h', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn(async (): Promise<WordfenceFetchResult> => ({ ok: true, feed: SAMPLE_FEED }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');

    await getWordfenceFeed({ apiKey: 'test-token', cacheDir, env: {}, now: t0, fetchWordfenceFeedImpl: fetchImpl });
    await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      now: t0 + 25 * 60 * 60 * 1000, // 25h later
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('reports a coverage gap (never a fabricated empty feed) when no API key is configured', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn();

    const r = await getWordfenceFeed({ cacheDir, env: {}, fetchWordfenceFeedImpl: fetchImpl });

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/WORDFENCE_API_KEY/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('reads the API key from the WORDFENCE_API_KEY env var when not passed directly', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn(async (opts) => {
      expect(opts.apiKey).toBe('from-env');
      return { ok: true, feed: SAMPLE_FEED } as WordfenceFetchResult;
    });

    const r = await getWordfenceFeed({
      cacheDir,
      env: { WORDFENCE_API_KEY: 'from-env' },
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(r.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('honours GUARDIAN_OFFLINE=1 and never calls fetch', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn();

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      offline: true,
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/GUARDIAN_OFFLINE/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('serves a stale cache under GUARDIAN_OFFLINE=1 rather than nothing', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const fetchImpl = vi.fn(async (): Promise<WordfenceFetchResult> => ({ ok: true, feed: SAMPLE_FEED }));
    const t0 = Date.parse('2026-09-25T00:00:00Z');
    await getWordfenceFeed({ apiKey: 'test-token', cacheDir, env: {}, now: t0, fetchWordfenceFeedImpl: fetchImpl });

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      now: t0 + 48 * 60 * 60 * 1000,
      offline: true,
      fetchWordfenceFeedImpl: fetchImpl,
    });

    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.stale).toBe(true);
      expect(r.feed).toEqual(SAMPLE_FEED);
    }
  });

  it('falls back to a stale cache when a refresh attempt fails over the network', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const t0 = Date.parse('2026-09-25T00:00:00Z');
    await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      now: t0,
      fetchWordfenceFeedImpl: async () => ({ ok: true, feed: SAMPLE_FEED }),
    });

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      now: t0 + 25 * 60 * 60 * 1000,
      fetchWordfenceFeedImpl: async () => ({ ok: false, reason: 'http 500' }),
    });

    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.stale).toBe(true);
      expect(r.feed).toEqual(SAMPLE_FEED);
    }
  });

  it('reports failure when there is no cache and the refresh fails', async () => {
    const cacheDir = makeTempDir('wf-cache-');

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      fetchWordfenceFeedImpl: async () => ({ ok: false, reason: 'http 401' }),
    });

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('http 401');
  });

  it('a corrupted cache file reads as never-cached, not as a crash', async () => {
    const cacheDir = makeTempDir('wf-cache-');
    const { mkdirSync, writeFileSync } = await import('node:fs');
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, 'wordfence-vulnerabilities-production.json'), 'not json{{{', 'utf8');

    const r = await getWordfenceFeed({
      apiKey: 'test-token',
      cacheDir,
      env: {},
      fetchWordfenceFeedImpl: async () => ({ ok: true, feed: SAMPLE_FEED }),
    });

    expect(r.ok).toBe(true);
    if (r.ok) expect(r.stale).toBe(false);
  });
});

describe('defaultWordfenceCacheDir', () => {
  it('includes the dev-guardian namespace, regardless of platform', () => {
    const dir = defaultWordfenceCacheDir({});
    expect(dir).toMatch(/dev-guardian/);
  });
});
