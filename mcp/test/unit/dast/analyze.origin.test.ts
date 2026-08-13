import { describe, expect, it } from 'vitest';
import { analyzeOrigin } from '../../../src/dast/analyze.js';
import { input, result, route } from './helpers.js';   // created in Task 4

describe('analyzeOrigin — security headers', () => {
  it('emits ONE finding per origin, not one per route', () => {
    // The wrong implementation emits N identical findings for N routes and
    // buries every other finding in the report.
    const results = ['/a', '/b', '/c'].map((p) =>
      result({ status: 200, request: { path: p, id: `anonymous GET ${p}` } }),
    );
    const f = analyzeOrigin(input({ results }));
    expect(f.filter((x) => x.check === 'security_headers')).toHaveLength(1);
  });

  it('names every missing header in the message', () => {
    const f = analyzeOrigin(input({ results: [result({ status: 200 })] }));
    const hit = f.find((x) => x.check === 'security_headers');
    expect(hit?.message).toMatch(/content-security-policy/i);
    expect(hit?.message).toMatch(/x-content-type-options/i);
  });

  it('does not require HSTS on an http origin', () => {
    // HSTS over plain http is meaningless; demanding it is noise.
    const f = analyzeOrigin(input({
      origin: 'http://localhost:3000',
      results: [result({ status: 200 })],
    }));
    expect(f.find((x) => x.check === 'security_headers')?.message ?? '')
      .not.toMatch(/strict-transport-security/i);
  });

  it('requires HSTS on an https origin', () => {
    const f = analyzeOrigin(input({
      origin: 'https://app.example.com',
      results: [result({ status: 200 })],
    }));
    expect(f.find((x) => x.check === 'security_headers')?.message ?? '')
      .toMatch(/strict-transport-security/i);
  });

  it('emits nothing when every expected header is present', () => {
    const headers = {
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    };
    const f = analyzeOrigin(input({ results: [result({ status: 200, headers })] }));
    expect(f.some((x) => x.check === 'security_headers')).toBe(false);
  });
});

describe('analyzeOrigin — information disclosure', () => {
  it('flags a stack trace in a response body, per signature family', () => {
    const bodies = [
      'Traceback (most recent call last):\n  File "app.py", line 3',
      'java.lang.NullPointerException\n\tat com.example.Main.run(Main.java:12)',
      'Error: boom\n    at Object.<anonymous> (/srv/app/server.js:10:15)',
      'Fatal error: Uncaught Exception in /var/www/html/index.php on line 8',
    ];
    for (const body of bodies) {
      const f = analyzeOrigin(input({ results: [result({ status: 500, body_prefix: body })] }));
      expect(f.some((x) => x.check === 'info_disclosure'), body.slice(0, 20)).toBe(true);
    }
  });

  it('does not flag ordinary prose that merely contains the word error', () => {
    const f = analyzeOrigin(input({
      results: [result({ status: 200, body_prefix: 'An error occurred. Please try again.' })],
    }));
    expect(f.some((x) => x.check === 'info_disclosure')).toBe(false);
  });

  it('flags a version banner in Server or X-Powered-By', () => {
    const f = analyzeOrigin(input({
      results: [result({ status: 200, headers: { 'x-powered-by': 'Express 4.18.2' } })],
    }));
    const hit = f.find((x) => x.check === 'info_disclosure');
    expect(hit?.severity).toBe('low');
    expect(hit?.message).toMatch(/Express 4\.18\.2/);
  });

  // Not part of the brief's 8 pinned tests — added after the implementation
  // revealed a real gap the brief's own tests never exercise (every given
  // test supplies exactly one result). `X-Powered-By` is normally stamped by
  // one global middleware layer, so an un-deduped implementation reports the
  // identical banner once per route: the exact "N routes = N duplicates"
  // failure `security_headers` above is already written to avoid, recurring
  // here for a different check.
  it('dedupes an identical version banner seen on multiple routes', () => {
    const results = ['/a', '/b', '/c'].map((p) =>
      result({
        status: 200,
        headers: { 'x-powered-by': 'Express 4.18.2' },
        request: { path: p, id: `anonymous GET ${p}` },
      }),
    );
    const f = analyzeOrigin(input({ results }));
    expect(f.filter((x) => x.check === 'info_disclosure')).toHaveLength(1);
  });

  it('reports a stack trace ONCE when the same path was probed more than once', () => {
    // `plan.ts` always adds a `cors` GET at every kept path on top of the
    // route's own anonymous request, so ANY GET route leaking a trace is seen
    // twice in one scan. The four route-scoped siblings
    // (`checkAnonymousExposure`, `checkReachability`, `checkOpenRedirect`,
    // `checkMethodSurface`) all filter to `variant === 'anonymous'`; this loop
    // had no filter, so it emitted two findings with a byte-identical
    // fingerprint. SQLite's `INSERT OR IGNORE` hides that in the database, but
    // `payload.findings` and `findings_count_by_severity` are both inflated.
    const body = 'Traceback (most recent call last):\n  File "app.py", line 3';
    const f = analyzeOrigin(input({
      results: [
        result({ status: 500, body_prefix: body, request: { path: '/boom', id: 'anonymous GET /boom' } }),
        result({
          status: 500,
          body_prefix: body,
          request: { path: '/boom', id: 'cors GET /boom', variant: 'cors' },
        }),
      ],
    }));
    expect(f.filter((x) => x.check === 'info_disclosure')).toHaveLength(1);
  });

  it('does not report a trace visible only on a credentialed probe', () => {
    // The deliberate cost of the variant filter, pinned so it is a decision
    // and not an accident: a trace only an authenticated caller can see is
    // MISSED. That is the correct direction for this feature — a missed
    // finding beats a duplicated accusation — and the assertion exists so the
    // next reader knows it was chosen rather than overlooked.
    const f = analyzeOrigin(input({
      hasCredentials: true,
      results: [
        result({
          status: 500,
          body_prefix: 'Traceback (most recent call last):\n  File "app.py", line 3',
          request: { id: 'authenticated GET /boom', path: '/boom', variant: 'authenticated' },
        }),
      ],
    }));
    expect(f.filter((x) => x.check === 'info_disclosure')).toEqual([]);
  });

  it('reports two distinct version banners as two separate findings', () => {
    // Guards the opposite mistake: a dedup keyed on "any banner seen this
    // scan" (rather than on the specific header+value pair) would collapse a
    // second, genuinely different backend behind the same origin into the
    // first finding and hide it.
    const results = [
      result({
        status: 200,
        headers: { 'x-powered-by': 'Express 4.18.2' },
        request: { path: '/a', id: 'anonymous GET /a' },
      }),
      result({
        status: 200,
        headers: { server: 'nginx/1.18.0' },
        request: { path: '/b', id: 'anonymous GET /b' },
      }),
    ];
    const f = analyzeOrigin(input({ results }));
    expect(f.filter((x) => x.check === 'info_disclosure')).toHaveLength(2);
  });
});

/**
 * A version banner comes from ONE global middleware layer, which is why it is
 * deduped globally by `(header, value)`. Its identity has to match that scope:
 * built through the route-scoped `buildFinding` path, the finding inherits
 * both the fingerprint AND the `file_path`/`line_start` of whichever probe
 * happened to win the race to observe it first — pointing the reader at a
 * source line that did not set the header, and rotating the fingerprint when
 * a different probe wins on a later run. That is the exact defect already
 * fixed for `security_headers` (see `originFingerprint`), recurring here.
 */
describe('analyzeOrigin — the version banner is identified by the origin, not by a route', () => {
  // TWO routes, in different files, each with its own `route_index` — the
  // shape a real scan has and the one that makes this suite decisive. With a
  // single shared route (the bare `helpers.ts` default) every probe resolves
  // to the same `path_resolved` and `file`, so a route-derived fingerprint
  // accidentally agrees with an origin-derived one and the bug hides.
  const ROUTES = [
    route({ path_raw: '/a', path_resolved: '/a', file: 'src/routes/a.ts', line: 10 }),
    route({ path_raw: '/b', path_resolved: '/b', file: 'src/routes/b.ts', line: 20 }),
  ];
  const INDEX_OF: Record<string, number> = { '/a': 0, '/b': 1 };

  const banner = (path: string, value: string, header = 'server'): ReturnType<typeof result> =>
    result({
      status: 200,
      headers: { [header]: value },
      request: { path, id: `anonymous GET ${path}`, route_index: INDEX_OF[path] ?? 0 },
    });

  const banners = (rs: ReturnType<typeof result>[]): ReturnType<typeof analyzeOrigin> =>
    analyzeOrigin(input({
      plan: { requests: [], routes: ROUTES, skipped: [], truncated: false },
      inventoryRoutes: ROUTES,
      results: rs,
    })).filter((x) => x.check === 'info_disclosure');

  it('carries no file_path or line_start — no route set this header', () => {
    // The wrong implementation reports `src/users.ts:10` for a header that
    // route never set, because that is simply the route `route_index 0`
    // resolves to.
    const [hit] = banners([banner('/a', 'nginx/1.18.0')]);
    expect(hit).toBeDefined();
    expect(hit?.file_path).toBeUndefined();
    expect(hit?.line_start).toBeUndefined();
  });

  it('fingerprints identically when a different probe wins the race to observe it', () => {
    // Same origin, same banner, same middleware — only which probe completed
    // first differs, which is a race in a live scan and not a property of the
    // target. A (method, path)-derived fingerprint rotates here and silently
    // breaks diff_scans / set_baseline / regression_alert / suppress_finding.
    const runA = banners([banner('/a', 'nginx/1.18.0'), banner('/b', 'nginx/1.18.0')]);
    const runB = banners([banner('/b', 'nginx/1.18.0'), banner('/a', 'nginx/1.18.0')]);
    expect(runA[0]?.fingerprint).toBeDefined();
    expect(runA[0]?.fingerprint).toBe(runB[0]?.fingerprint);
  });

  it('gives two values of the SAME header two identities, not one', () => {
    // Two backends behind one origin. This is the assertion that rules out
    // `originRuleId('info_disclosure', origin)` with nothing else hashed in —
    // which would collapse these into one identity — AND rules out a dedup
    // key of header name alone, which would drop the second finding entirely.
    // Both existing dedup tests above pass under a header-name-only key.
    const f = banners([banner('/a', 'nginx/1.18.0'), banner('/b', 'nginx/1.20.1')]);
    expect(f).toHaveLength(2);
    expect(new Set(f.map((x) => x.fingerprint)).size).toBe(2);
    expect(f.map((x) => x.message).join(' ')).toMatch(/nginx\/1\.20\.1/);
  });

  it('keeps the banner identity distinct from the security_headers identity', () => {
    // Both are origin-scoped; hashing only `(check, origin)` for each is what
    // keeps them apart, and `check` differing is what must carry that.
    const f = analyzeOrigin(input({ results: [banner('/a', 'nginx/1.18.0')] }));
    const fps = f.map((x) => x.fingerprint);
    expect(f).toHaveLength(2);
    expect(new Set(fps).size).toBe(2);
  });
});

describe('analyzeOrigin fingerprints', () => {
  it('security_headers fingerprints identically across runs even when a ' +
    'different probe completes first', () => {
    // The real trigger needs no code change and no route-inventory edit: a
    // per-request timeout means the literal first request can complete on
    // one run and time out on the next, promoting a different request to
    // `completed[0]` with nothing about the target having changed. The wrong
    // implementation (route: undefined, request: completed[0].request fed
    // straight into the (method, path)-based fingerprint) hashes whichever
    // request happens to land first, so run A and run B below — same origin,
    // same missing headers — would get different fingerprints for the
    // identical fact.
    const a = result({ status: 200, request: { path: '/a', id: 'anonymous GET /a' } });
    const b = result({ status: 200, request: { path: '/b', id: 'anonymous GET /b' } });
    const timedOutA = result({
      outcome: 'timeout',
      status: null,
      request: { path: '/a', id: 'anonymous GET /a' },
    });

    const runA = analyzeOrigin(input({ results: [a, b] }));
    const runB = analyzeOrigin(input({ results: [timedOutA, b] }));

    const fpA = runA.find((x) => x.check === 'security_headers')?.fingerprint;
    const fpB = runB.find((x) => x.check === 'security_headers')?.fingerprint;
    expect(fpA).toBeDefined();
    expect(fpA).toBe(fpB);
  });
});
