/**
 * `queryOsv` (runners/osv.ts) over a stand-in for `fetch` that answers OSV's
 * batch endpoint only: no test in this file reaches the network.
 */

import { describe, expect, it } from 'vitest';

import { queryOsv, type OsvAnswer, type OsvPackageQuery } from '../../../src/runners/osv.js';

const OSV = 'https://api.osv.dev/v1/querybatch';
const MAL = 'MAL-2025-6022';
const GHSA = 'GHSA-35jh-r3h4-6jhm';

/** `n` distinct npm queries, each with an exact version. */
const packages = (n: number, prefix = 'pkg'): OsvPackageQuery[] =>
  Array.from({ length: n }, (_, i) => ({ ecosystem: 'npm', name: `${prefix}-${i}`, version: `1.${i % 10}.0` }));

/** A query as the request body carries it. */
interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

/** What one request is answered with; nothing set is a complete answer, one result per query. */
interface Answer {
  status?: number;
  body?: unknown;
  /** A body sent as it is, not as JSON. */
  text?: string;
}

interface Osv {
  fetchImpl: typeof fetch;
  /** The queries of each request, in the order the requests arrived. */
  requests: OsvQuery[][];
  /** The most requests that were open at the same moment. */
  peak: () => number;
}

/** One spelling for a query given to `queryOsv` and for one read from a request body. */
const keyOf = (q: OsvPackageQuery): string => `${q.ecosystem} ${q.name}@${q.version ?? ''}`;
const said = (q: OsvQuery): string => `${q.package.ecosystem} ${q.package.name}@${q.version ?? ''}`;

/** Too few requests in flight meet this wait once, then fail the assertion on the peak — not the test's timeout. */
const GIVE_UP_MS = 1500;

/**
 * OSV's batch endpoint. `advisories` are the ids of a query (by {@link keyOf}).
 * `answer` overrides the answer of a request (`undefined`: the complete one).
 * With `holdUntil`, every request is held open until that many have arrived
 * and one more turn of the event loop has passed — so the most requests in
 * flight at once can be read, one too many included.
 */
function osv(o: { advisories?: Record<string, string[]>; answer?: (queries: OsvQuery[]) => Answer | undefined; holdUntil?: number } = {}): Osv {
  const requests: OsvQuery[][] = [];
  let open = 0;
  let peak = 0;
  let release: () => void = () => undefined;
  const gate = new Promise<void>((done) => {
    release = done;
  });
  let giveUp: ReturnType<typeof setTimeout> | undefined;
  const complete = (queries: OsvQuery[]): unknown => ({
    results: queries.map((q) => {
      const ids = o.advisories?.[said(q)] ?? [];
      return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
    }),
  });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    if (url !== OSV) throw new Error(`unexpected network call: ${url}`);
    const queries = (JSON.parse(String(init?.body)) as { queries: OsvQuery[] }).queries;
    requests.push(queries);
    open += 1;
    peak = Math.max(peak, open);
    try {
      if (o.holdUntil !== undefined) {
        if (requests.length >= o.holdUntil) {
          setImmediate(() => {
            clearTimeout(giveUp);
            release();
          });
        } else {
          giveUp ??= setTimeout(release, GIVE_UP_MS);
        }
        await gate;
      }
      const a = o.answer?.(queries) ?? {};
      return new Response(a.text ?? JSON.stringify(a.body ?? complete(queries)), { status: a.status ?? 200 });
    } finally {
      open -= 1;
    }
  }) as typeof fetch;
  return { fetchImpl, requests, peak: () => peak };
}

/** The queries a result reports as having no complete answer. */
function unansweredOf(r: OsvAnswer): string[] {
  expect(Array.isArray(r.unanswered), 'queryOsv gave no `unanswered` list').toBe(true);
  return r.unanswered.map(keyOf).sort();
}

describe('install-vet-lockfile-pins', () => {
  // What the callers of today get, and keep: this test passes before the feature.
  it('T-17 without options, as before: 100 queries a request, four requests in flight, 1 000 queries a call and the rest unqueried', async () => {
    const hit: OsvPackageQuery = { ecosystem: 'npm', name: 'eslint-config-prettier', version: '10.1.7' };
    const past: OsvPackageQuery = { ecosystem: 'npm', name: 'past-the-cap', version: '6.6.6' };
    const queries = [hit, ...packages(999), ...packages(249, 'more'), past];
    const o = osv({ advisories: { [keyOf(hit)]: [MAL], [keyOf(past)]: ['MAL-2026-0001'] }, holdUntil: 4 });
    const r = await queryOsv(queries, { fetchImpl: o.fetchImpl });

    expect(o.requests.map((x) => x.length)).toEqual(Array.from({ length: 10 }, () => 100));
    expect(o.peak()).toBe(4);
    expect(o.requests.flat().map(said).sort()).toEqual(queries.slice(0, 1000).map(keyOf).sort());
    expect(r).toMatchObject({ online: true, queried: 1000, unqueried: 250 });
    expect(r.vulnerable_packages).toMatchObject([{ ecosystem: 'npm', name: hit.name, version: hit.version, vuln_ids: [MAL] }]);
  });

  it('T-17 `chunk` and `inFlight`: the queries of a request, and the requests open at once', async () => {
    const five = packages(5);
    const one = osv({ holdUntil: 1 });
    const r = await queryOsv(five, { fetchImpl: one.fetchImpl, chunk: 2, inFlight: 1 });
    expect(one.requests.map((x) => x.length)).toEqual([2, 2, 1]);
    expect(one.peak()).toBe(1);
    expect(r).toMatchObject({ online: true, queried: 5, unqueried: 0 });

    const wide = osv({ holdUntil: 5 });
    await queryOsv(five, { fetchImpl: wide.fetchImpl, chunk: 1, inFlight: 5 });
    expect(wide.requests.map((x) => x.length)).toEqual([1, 1, 1, 1, 1]);
    expect(wide.peak()).toBe(5);
  });

  it('T-17 `maxQueries`: the cap of a call, and the rest unqueried', async () => {
    const five = packages(5);
    const o = osv();
    const r = await queryOsv(five, { fetchImpl: o.fetchImpl, maxQueries: 3 });
    expect(r).toMatchObject({ online: true, queried: 3, unqueried: 2 });
    expect(o.requests.flat().map(said).sort()).toEqual(five.slice(0, 3).map(keyOf).sort());
  });

  it('T-17 the three together, as the pins of a lockfile are asked: 500 a request, 16 in flight, 8 000 a call', async () => {
    const queries = packages(8500);
    const o = osv({ holdUntil: 16 });
    const r = await queryOsv(queries, { fetchImpl: o.fetchImpl, chunk: 500, inFlight: 16, maxQueries: 8000 });
    expect(o.requests.map((x) => x.length)).toEqual(Array.from({ length: 16 }, () => 500));
    expect(o.peak()).toBe(16);
    expect(o.requests.flat().map(said).sort()).toEqual(queries.slice(0, 8000).map(keyOf).sort());
    expect(r).toMatchObject({ online: true, queried: 8000, unqueried: 500 });
  });

  it('T-17 every query answered: nothing is unanswered', async () => {
    const hit: OsvPackageQuery = { ecosystem: 'npm', name: 'eslint-config-prettier', version: '10.1.7' };
    const o = osv({ advisories: { [keyOf(hit)]: [MAL] } });
    const r = await queryOsv([...packages(149), hit], { fetchImpl: o.fetchImpl });
    expect(r.online).toBe(true);
    expect(r.vulnerable_packages).toMatchObject([{ name: hit.name, version: hit.version, vuln_ids: [MAL] }]);
    expect(unansweredOf(r)).toEqual([]);
  });

  const MARK = 'in-the-batch-with-no-complete-answer';
  /**
   * `whole`: every query of the batch is unanswered (a short `results` cannot
   * be matched to its queries); otherwise at least the marked one, and none of
   * another batch. `failed`: the batch failed, so the call was not online.
   */
  const INCOMPLETE: Array<{ name: string; answer: (queries: OsvQuery[]) => Answer; whole: boolean; failed: boolean }> = [
    { name: 'a batch that fails (HTTP 503)', answer: () => ({ status: 503, body: { code: 14, message: 'unavailable' } }), whole: true, failed: true },
    { name: 'a batch whose body is not JSON', answer: () => ({ text: '<html>bad gateway</html>' }), whole: true, failed: true },
    { name: 'an answer without `results`', answer: () => ({ body: {} }), whole: true, failed: false },
    {
      name: 'an answer with fewer results than queries',
      answer: (queries) => ({ body: { results: queries.slice(1).map(() => ({})) } }),
      whole: true,
      failed: false,
    },
    {
      name: 'a result with `next_page_token`',
      // The page that came holds one advisory; the rest are on the page that did not.
      answer: (queries) => ({
        body: { results: queries.map((q) => (q.package.name === MARK ? { vulns: [{ id: GHSA }], next_page_token: 'page-2' } : {})) },
      }),
      whole: false,
      failed: false,
    },
  ];

  it.each(INCOMPLETE)(
    'T-17 $name: the hits of the batches that answered are kept, and the queries left without a complete answer are reported as unanswered',
    async ({ answer, whole, failed }) => {
      const first: OsvPackageQuery = { ecosystem: 'npm', name: 'eslint-config-prettier', version: '10.1.7' };
      const marked: OsvPackageQuery = { ecosystem: 'npm', name: MARK, version: '1.0.0' };
      const last: OsvPackageQuery = { ecosystem: 'npm', name: 'lodash', version: '4.17.20' };
      // 250 queries are three requests: a hit in the first and in the last, the marked query in the middle one.
      const queries = [first, ...packages(119), marked, ...packages(128, 'tail'), last];
      const o = osv({
        advisories: { [keyOf(first)]: [MAL], [keyOf(last)]: [GHSA] },
        answer: (batch) => (batch.some((q) => q.package.name === MARK) ? answer(batch) : undefined),
      });
      const r = await queryOsv(queries, { fetchImpl: o.fetchImpl });

      const incomplete = o.requests.filter((x) => x.some((q) => q.package.name === MARK)).flat().map(said).sort();
      expect(incomplete).toHaveLength(100);
      expect(incomplete).not.toContain(keyOf(first));
      expect(incomplete).not.toContain(keyOf(last));

      expect(r.vulnerable_packages).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: first.name, version: first.version, vuln_ids: [MAL] }),
          expect.objectContaining({ name: last.name, version: last.version, vuln_ids: [GHSA] }),
        ]),
      );
      const unanswered = unansweredOf(r);
      expect(unanswered).toContain(keyOf(marked));
      expect(unanswered.filter((k) => !incomplete.includes(k))).toEqual([]);
      if (whole) expect(unanswered).toEqual(incomplete);
      if (failed) expect(r.online).toBe(false);
    },
  );
});
