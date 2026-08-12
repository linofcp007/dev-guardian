import { describe, expect, it } from 'vitest';
import { analyzeOrigin } from '../../../src/dast/analyze.js';
import { input, result } from './helpers.js';   // created in Task 4

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
