/**
 * `vetPins` and `choosePins` (install-vet-lockfile-pins): the pairs a lockfile
 * pins, asked of OSV at their exact version — and which of them are asked when
 * the lockfiles pin more than the cap.
 *
 * Every request goes through `osv()`, a stand-in for `fetch` that answers
 * OSV's batch endpoint only. A request for anything else is recorded and
 * refused, so no test in this file reaches the network.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Pin } from '../../../src/pkgvet/lockfile.js';
import { MAX_PINS, choosePins, vetPins, type PinVerdict } from '../../../src/pkgvet/pins.js';
import type { VetOptions } from '../../../src/pkgvet/vet.js';
import { hangBound } from '../../helpers/timing.js';

const OSV = 'https://api.osv.dev/v1/querybatch';
/** The positive control of the feature's measurements: 10.1.7 has the advisory, 10.1.8 has none. */
const MAL = 'MAL-2025-6022';
const BAD: Pin = { name: 'eslint-config-prettier', version: '10.1.7' };
const GOOD: Pin = { name: 'eslint-config-prettier', version: '10.1.8' };

const key = (p: Pin): string => `${p.name}@${p.version}`;

/** `n` distinct pins: names the registry accepts, exact versions. */
const pins = (n: number, prefix = 'pkg'): Pin[] =>
  Array.from({ length: n }, (_, i) => ({ name: `${prefix}-${i}`, version: `1.${i % 10}.0` }));

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
  /** Never answers: rejects when the request is aborted, as `fetch` does. */
  hang?: boolean;
}

interface Osv {
  fetchImpl: typeof fetch;
  /** The queries of each request, in the order the requests arrived. */
  requests: OsvQuery[][];
  /** Every URL asked for that is not OSV's batch endpoint. */
  strays: string[];
  /** The most requests that were open at the same moment. */
  peak: () => number;
}

/** A sequential implementation meets this wait once, then fails the assertion on the peak — not the test's timeout. */
const GIVE_UP_MS = 1500;

/**
 * OSV's batch endpoint. `advisories` are the ids of a `name@version`.
 * `answer` overrides the answer of a request (`undefined`: the complete one).
 * With `holdUntil`, every request is held open until that many have arrived
 * and one more turn of the event loop has passed — so the most requests in
 * flight at once can be read, one too many included.
 */
function osv(o: { advisories?: Record<string, string[]>; answer?: (queries: OsvQuery[]) => Answer | undefined; holdUntil?: number } = {}): Osv {
  const requests: OsvQuery[][] = [];
  const strays: string[] = [];
  let open = 0;
  let peak = 0;
  let release: () => void = () => undefined;
  const gate = new Promise<void>((done) => {
    release = done;
  });
  let giveUp: ReturnType<typeof setTimeout> | undefined;
  const complete = (queries: OsvQuery[]): unknown => ({
    results: queries.map((q) => {
      const ids = o.advisories?.[`${q.package.name}@${q.version ?? ''}`] ?? [];
      return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
    }),
  });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    if (url !== OSV) {
      strays.push(url);
      throw new Error(`unexpected network call: ${url}`);
    }
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
      if (a.hang === true) {
        return await new Promise<Response>((_resolve, reject) => {
          const abort = (): void => reject(new DOMException('aborted', 'AbortError'));
          if (init?.signal?.aborted === true) abort();
          else init?.signal?.addEventListener('abort', abort, { once: true });
        });
      }
      return new Response(a.text ?? JSON.stringify(a.body ?? complete(queries)), { status: a.status ?? 200 });
    } finally {
      open -= 1;
    }
  }) as typeof fetch;
  return { fetchImpl, requests, strays, peak: () => peak };
}

/** Online whatever the environment says (the suite runs with `GUARDIAN_OFFLINE=1`), with a budget no answering stand-in comes near. */
function online(o: Osv, extra: Partial<VetOptions> = {}): VetOptions {
  return { fetchImpl: o.fetchImpl, offline: false, budgetMs: 5000, ...extra };
}

/** The verdict of a pin — by the pin, not by its place in the answer. */
function verdictsByPin(verdicts: readonly PinVerdict[]): (pin: Pin) => PinVerdict {
  const byKey = new Map(verdicts.map((v) => [key(v.pin), v]));
  return (pin) => {
    const v = byKey.get(key(pin));
    if (v === undefined) throw new Error(`vetPins returned no verdict for ${key(pin)}`);
    return v;
  };
}

/** A query as the ecosystem, the name and the version it asks about. */
const said = (q: OsvQuery): string => `${q.package.ecosystem} ${q.package.name}@${q.version ?? '(no version)'}`;
const asNpm = (p: Pin): string => `npm ${key(p)}`;
/** The pins a set of requests asked about. */
const pinsOf = (requests: readonly OsvQuery[][]): Set<string> => new Set(requests.flat().map((q) => `${q.package.name}@${q.version ?? ''}`));

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('install-vet-lockfile-pins', () => {
  // ─────────────────────────────────────────────────────────────── T-14
  it('T-14 one OSV request per 500 pins, all in flight at once — 16 for 8 000 — each query a name, its exact version and the npm ecosystem', async () => {
    const all = [BAD, GOOD, { name: '@scope/pkg', version: '2.0.0-rc.1' }, ...pins(MAX_PINS - 3)];
    const o = osv({ advisories: { [key(BAD)]: [MAL] }, holdUntil: 16 });
    const verdicts = await vetPins(all, online(o));

    expect(o.requests.map((r) => r.length)).toEqual(Array.from({ length: 16 }, () => 500));
    expect(o.peak()).toBe(16);
    // Every pin once, as itself; and nothing but OSV was asked — no registry document.
    expect(o.requests.flat().map(said).sort()).toEqual(all.map(asNpm).sort());
    expect(o.strays).toEqual([]);

    const verdictOf = verdictsByPin(verdicts);
    expect(verdictOf(BAD)).toEqual({ pin: BAD, malicious: [MAL] });
    for (const pin of all.slice(1)) expect(verdictOf(pin)).toEqual({ pin, malicious: [] });
  });

  it('T-14 fewer pins: one request per started 500, all open together; no pins, no request', async () => {
    const all = pins(1201);
    const o = osv({ holdUntil: 3 });
    const verdicts = await vetPins(all, online(o));
    expect(o.requests.map((r) => r.length).sort((a, b) => b - a)).toEqual([500, 500, 201]);
    expect(o.peak()).toBe(3);
    const verdictOf = verdictsByPin(verdicts);
    for (const pin of all) expect(verdictOf(pin).malicious).toEqual([]);

    const none = osv();
    expect(await vetPins([], online(none))).toEqual([]);
    expect(none.requests).toEqual([]);
  });

  it('T-14 never more than 16 requests in flight, and a pin that was not asked about is never given as verified', async () => {
    const all = pins(MAX_PINS + 500);
    const o = osv({ holdUntil: 16 });
    const verdicts = await vetPins(all, online(o));
    expect(o.peak()).toBeLessThanOrEqual(16);
    expect(o.requests.every((r) => r.length <= 500)).toBe(true);
    const asked = pinsOf(o.requests);
    const verdictOf = verdictsByPin(verdicts);
    for (const pin of all) {
      const v = verdictOf(pin);
      if (asked.has(key(pin))) {
        expect(v.malicious).toEqual([]);
      } else {
        expect(v.malicious, `${key(pin)} was never sent to OSV`).toBeNull();
        expect(v.unknown ?? '').not.toBe('');
      }
    }
  });

  it('T-14 only MAL- advisories end up in a verdict: a known vulnerability of a pinned version gives nothing', async () => {
    const vulnerable: Pin = { name: 'lodash', version: '4.17.20' };
    const both: Pin = { name: 'event-stream', version: '3.3.6' };
    const o = osv({
      advisories: {
        [key(BAD)]: [MAL],
        [key(vulnerable)]: ['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337'],
        [key(both)]: ['GHSA-mh6f-8j2x-4483', 'MAL-2026-0001'],
      },
    });
    const verdicts = await vetPins([vulnerable, BAD, GOOD, both], online(o));
    const verdictOf = verdictsByPin(verdicts);
    expect(verdictOf(BAD)).toEqual({ pin: BAD, malicious: [MAL] });
    expect(verdictOf(GOOD)).toEqual({ pin: GOOD, malicious: [] });
    expect(verdictOf(vulnerable)).toEqual({ pin: vulnerable, malicious: [] });
    expect(verdictOf(both)).toEqual({ pin: both, malicious: ['MAL-2026-0001'] });
    expect(JSON.stringify(verdicts)).not.toMatch(/GHSA-|CVE-/);
  });

  // ─────────────────────────────────────────────────────────────── T-15
  it('T-15 GUARDIAN_OFFLINE=1: no request at all, and every pin comes back unanswered with the reason — never as verified', async () => {
    const o = osv();
    // The option, with the environment saying the opposite…
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    const byOption = await vetPins([BAD, GOOD], online(o, { offline: true }));
    // …and the environment alone, as the hook's process has it.
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    const byEnvironment = await vetPins([BAD, GOOD], { fetchImpl: o.fetchImpl, budgetMs: 5000 });

    expect(o.requests).toEqual([]);
    for (const verdicts of [byOption, byEnvironment]) {
      const verdictOf = verdictsByPin(verdicts);
      for (const pin of [BAD, GOOD]) {
        expect(verdictOf(pin).malicious).toBeNull();
        expect(verdictOf(pin).unknown).toMatch(/GUARDIAN_OFFLINE|offline/i);
      }
    }
  });

  it('T-15 a deadline that has already passed: nothing is asked, and every pin is unanswered — the budget is the reason', async () => {
    const o = osv({ advisories: { [key(BAD)]: [MAL] } });
    const verdicts = await vetPins([BAD, GOOD], online(o, { deadlineAt: Date.now() - 1 }));
    expect(o.requests).toEqual([]);
    const verdictOf = verdictsByPin(verdicts);
    for (const pin of [BAD, GOOD]) {
      expect(verdictOf(pin).malicious).toBeNull();
      expect(verdictOf(pin).unknown).toMatch(/budget|timed out|deadline/i);
    }
  });

  const MARK = 'in-the-batch-with-no-complete-answer';
  const INCOMPLETE: Array<{ name: string; answer: (queries: OsvQuery[]) => Answer; budgetMs: number; reason: RegExp }> = [
    { name: 'an HTTP error', answer: () => ({ status: 503, body: { code: 14, message: 'unavailable' } }), budgetMs: 5000, reason: /./ },
    { name: 'a body that is not JSON', answer: () => ({ text: '<html>bad gateway</html>' }), budgetMs: 5000, reason: /./ },
    { name: 'an answer without `results`', answer: () => ({ body: {} }), budgetMs: 5000, reason: /./ },
    {
      name: 'fewer results than queries',
      answer: (queries) => ({ body: { results: queries.slice(1).map(() => ({})) } }),
      budgetMs: 5000,
      reason: /./,
    },
    { name: 'a request the budget runs out on', answer: () => ({ hang: true }), budgetMs: 400, reason: /budget|timed out|deadline/i },
  ];

  it.each(INCOMPLETE)(
    'T-15 $name, for one batch of two: its pins come back unanswered with a reason, never as verified — and the MAL- advisory of the batch that answered stays',
    async ({ answer, budgetMs, reason }) => {
      // 1 000 pins are two requests: the malicious pin at one end, the marked one at the other.
      const all = [BAD, ...pins(998), { name: MARK, version: '1.0.0' }];
      const o = osv({
        advisories: { [key(BAD)]: [MAL] },
        answer: (queries) => (queries.some((q) => q.package.name === MARK) ? answer(queries) : undefined),
      });
      const t0 = Date.now();
      const verdicts = await vetPins(all, online(o, { budgetMs }));
      expect(Date.now() - t0).toBeLessThan(hangBound(2000));

      const unanswered = pinsOf(o.requests.filter((r) => r.some((q) => q.package.name === MARK)));
      expect(unanswered.has(key(BAD)), 'the malicious pin and the marked one are in different requests').toBe(false);
      const verdictOf = verdictsByPin(verdicts);
      expect(verdictOf(BAD).malicious).toEqual([MAL]);
      for (const pin of all.slice(1)) {
        const v = verdictOf(pin);
        if (unanswered.has(key(pin))) {
          expect(v.malicious, `${key(pin)} was in the batch with no complete answer`).toBeNull();
          expect(v.unknown ?? '').toMatch(reason);
        } else {
          expect(v.malicious).toEqual([]);
        }
      }
    },
  );

  // The request's own timeout used to end with the budget, and which of the two timers fired first decided the
  // reason: the budget's phrase, or the stand-in's bare "aborted" — once in a full run of the suite (2026-11-17).
  it('T-15 a budget that runs out says so EVERY time: the reason is the budget\'s, never the aborted request\'s own word', async () => {
    const reasons = new Set<string>();
    for (let round = 0; round < 40; round += 1) {
      const o = osv({ answer: () => ({ hang: true }) });
      const verdicts = await vetPins([GOOD], online(o, { budgetMs: 15 + (round % 7) }));
      for (const v of verdicts) {
        expect(v.malicious).toBeNull();
        reasons.add(v.unknown ?? '');
      }
    }
    expect([...reasons]).toEqual(['network budget exhausted before OSV answered']);
  });

  it('T-15 a result cut short (`next_page_token`): that pin is unanswered, never verified — and the batch that answered keeps its MAL- advisory', async () => {
    const paged: Pin = { name: 'paged-result', version: '3.1.4' };
    const all = [BAD, ...pins(998), paged];
    const o = osv({
      advisories: { [key(BAD)]: [MAL] },
      // The page that came holds a vulnerability; a MAL- advisory may be on the one that did not.
      answer: (queries) =>
        queries.some((q) => q.package.name === paged.name)
          ? {
              body: {
                results: queries.map((q) => (q.package.name === paged.name ? { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }], next_page_token: 'page-2' } : {})),
              },
            }
          : undefined,
    });
    const verdicts = await vetPins(all, online(o));
    const verdictOf = verdictsByPin(verdicts);
    expect(verdictOf(paged).malicious).toBeNull();
    expect(verdictOf(paged).unknown ?? '').not.toBe('');
    expect(verdictOf(BAD).malicious).toEqual([MAL]);
    const cut = pinsOf(o.requests.filter((r) => r.some((q) => q.package.name === paged.name)));
    for (const pin of all.slice(1)) if (!cut.has(key(pin))) expect(verdictOf(pin).malicious).toEqual([]);
  });

  // ─────────────────────────────────────────────────────────────── T-16
  type Kind = 'direct' | 'unpopular' | 'popular';

  /** 9 000 pins in a lockfile's order, the three kinds mixed; a direct dependency may be popular, and is pinned at two versions. */
  function lockOrder(kindOf: (i: number) => Kind): { file: Pin[]; direct: Set<string>; popular: (name: string) => boolean } {
    const direct = new Set<string>();
    const file: Pin[] = [];
    let d = 0;
    for (let i = 0; i < 9000; i += 1) {
      const kind = kindOf(i);
      if (kind === 'direct') {
        const name = `dep-${Math.floor(d / 2)}`;
        d += 1;
        direct.add(name);
        file.push({ name, version: `1.0.${i}` });
      } else {
        file.push({ name: `${kind === 'popular' ? 'pop' : 'rare'}-${i}`, version: '1.0.0' });
      }
    }
    return { file, direct, popular: (name) => name.startsWith('pop-') || /^dep-\d*[02468]$/.test(name) };
  }

  const CUTS: Array<{ name: string; kindOf: (i: number) => Kind; counts: number[] }> = [
    {
      name: 'the cut falls among the popular names',
      kindOf: (i) => (i % 9 === 0 ? 'direct' : i % 3 === 1 ? 'unpopular' : 'popular'),
      counts: [1000, 3000, 5000],
    },
    {
      name: 'the cut falls among the names that are not popular',
      kindOf: (i) => (i % 9 === 0 ? 'direct' : 'unpopular'),
      counts: [1000, 8000, 0],
    },
  ];

  it.each(CUTS)(
    'T-16 of 9 000 pins 8 000 are kept — the direct dependencies’ first, then the names the popular test rejects, then the rest, file order within each — and 1 000 are left ($name)',
    ({ kindOf, counts }) => {
      expect(MAX_PINS).toBe(8000);
      const { file, direct, popular } = lockOrder(kindOf);
      const first = file.filter((p) => direct.has(p.name));
      const second = file.filter((p) => !direct.has(p.name) && !popular(p.name));
      const third = file.filter((p) => !direct.has(p.name) && popular(p.name));
      expect([first.length, second.length, third.length]).toEqual(counts);

      const { chosen, left } = choosePins(file, { direct, popular });
      expect(left).toBe(1000);
      expect(chosen).toHaveLength(MAX_PINS);
      expect(chosen.map(key)).toEqual([...first, ...second, ...third].slice(0, MAX_PINS).map(key));
    },
  );

  it('T-16 at the cap and under it nothing is left', () => {
    const exact = pins(MAX_PINS);
    const atCap = choosePins(exact, { direct: new Set(), popular: () => false });
    expect(atCap.left).toBe(0);
    expect(atCap.chosen.map(key)).toEqual(exact.map(key));
    const few = choosePins([GOOD, BAD, ...pins(8)], { direct: new Set([BAD.name]), popular: (name: string) => name.startsWith('pkg-') });
    expect(few.left).toBe(0);
    expect(few.chosen.map(key).sort()).toEqual([GOOD, BAD, ...pins(8)].map(key).sort());
  });

  it('T-16 a pin two lockfiles share is asked once — and the same name at another version is another pin', async () => {
    const one = [BAD, ...pins(3)];
    const other = [...pins(3), { name: 'only-in-the-other', version: '1.0.0' }, BAD, GOOD];
    const { chosen, left } = choosePins([...one, ...other], { direct: new Set(), popular: () => false });
    expect(left).toBe(0);

    const o = osv({ advisories: { [key(BAD)]: [MAL] } });
    const verdicts = await vetPins(chosen, online(o));
    expect(o.requests.flat().map(said).sort()).toEqual([...new Set([...one, ...other].map(asNpm))].sort());
    const verdictOf = verdictsByPin(verdicts);
    expect(verdictOf(BAD).malicious).toEqual([MAL]);
    expect(verdictOf(GOOD).malicious).toEqual([]);
  });
  // ─────────────────────────────────────────────────────────────── fix round 2
  it('T-15 a `null` among the `vulns` of one pin: the MAL- advisory read in the same batch denies, and only the malformed pin is unanswered', async () => {
    const other: Pin = { name: 'left-pad', version: '1.3.0' };
    const o = osv({
      answer: (queries) => ({ body: { results: queries.map((q) => (q.package.name === BAD.name ? { vulns: [{ id: MAL }] } : { vulns: [null] })) } }),
    });
    const verdictOf = verdictsByPin(await vetPins([BAD, other], online(o)));
    expect(verdictOf(BAD).malicious).toEqual([MAL]);
    expect(verdictOf(other).malicious).toBeNull();
    expect(verdictOf(other).unknown ?? '').not.toBe('');
    expect(verdictOf(other).unknown ?? '').not.toMatch(/TypeError|Cannot read/);
  });

  it.each([' MAL-2025-6022', 'mal-2025-6022', '\tMal-2025-6022\n'])('T-15 an advisory id written %j is a malicious-package advisory', async (id) => {
    const o = osv({ advisories: { [key(BAD)]: [id] } });
    const verdictOf = verdictsByPin(await vetPins([BAD, GOOD], online(o)));
    expect(verdictOf(BAD).malicious?.length).toBe(1);
    expect(verdictOf(GOOD).malicious).toEqual([]);
  });
});
