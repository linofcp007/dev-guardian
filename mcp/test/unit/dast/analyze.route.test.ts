import { describe, expect, it } from 'vitest';
import { analyzeRoutes } from '../../../src/dast/analyze.js';
import type { ProbeResult } from '../../../src/dast/types.js';
import { input, result, route } from './helpers.js';

describe('analyzeRoutes — anonymous exposure', () => {
  it('flags a 200 with no credentials on a route the spec says needs auth', () => {
    const r = route({ auth_hint: 'required', provenance: 'spec' });
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      results: [result({ status: 200 })],
    }));
    const hit = f.find((x) => x.check === 'anonymous_exposure');
    expect(hit).toBeDefined();
    // 'high', not 'critical', and the spec (design doc section 8) is the
    // reason: auth_hint 'required' can be inherited from a DOCUMENT-level
    // `security` default, so a genuinely public route whose author forgot to
    // write `security: []` on it would otherwise be reported as a critical
    // auth bypass on a homepage. Severity inflation is over-reporting, and
    // this feature under-reports by construction.
    expect(hit?.severity).toBe('high');
    expect(hit?.file_path).toBe('src/users.ts');
    expect(hit?.line_start).toBe(10);
  });

  it('does not flag anonymous exposure when auth_hint is unknown', () => {
    // The guard against the tempting wrong implementation: treating every
    // anonymous 200 as a finding would fire on every public homepage.
    const f = analyzeRoutes(input({ results: [result({ status: 200 })] }));
    expect(f.some((x) => x.check === 'anonymous_exposure')).toBe(false);
  });

  it('does not flag anonymous exposure on 401 or 403', () => {
    const r = route({ auth_hint: 'required' });
    for (const status of [401, 403]) {
      const f = analyzeRoutes(input({
        plan: { requests: [], routes: [r], skipped: [], truncated: false },
        results: [result({ status })],
      }));
      expect(f.some((x) => x.check === 'anonymous_exposure'), String(status)).toBe(false);
    }
  });
});

describe('analyzeRoutes — reachability', () => {
  it('confirms a shadow endpoint when a code-only route answers', () => {
    const f = analyzeRoutes(input({
      results: [result({ status: 200 })],
      shadowPaths: new Set(['/users']),
    }));
    const hit = f.find((x) => x.check === 'reachability');
    expect(hit?.title).toMatch(/shadow endpoint/i);
    expect(hit?.severity).toBe('medium');
  });

  it('confirms dead documentation when a spec-only route 404s', () => {
    const r = route({ provenance: 'spec', path_resolved: '/gone' });
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      results: [result({ status: 404, request: { path: '/gone' } })],
      deadDocPaths: new Set(['/gone']),
    }));
    expect(f.find((x) => x.check === 'reachability')?.title).toMatch(/dead documentation/i);
  });

  it('reports an extractor coverage gap when a spec-only route is LIVE', () => {
    const r = route({ provenance: 'spec', path_resolved: '/live' });
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      results: [result({ status: 200, request: { path: '/live' } })],
      deadDocPaths: new Set(['/live']),
    }));
    const hit = f.find((x) => x.check === 'reachability');
    expect(hit?.title).toMatch(/extractor|coverage gap/i);
    expect(hit?.severity).toBe('info');
  });

  it('never calls a synthetic-parameter route unreachable on a 404', () => {
    // 404 on /users/1 is ambiguous: no such route, or no such record. The
    // wrong implementation reports "dead documentation" here.
    const r = route({ provenance: 'spec', path_resolved: '/users/{id}' });
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      results: [result({
        status: 404,
        request: { path: '/users/1', synthetic_params: true },
      })],
      deadDocPaths: new Set(['/users/{id}']),
    }));
    expect(f.some((x) => x.check === 'reachability')).toBe(false);
  });
});

describe('analyzeRoutes — differential authz', () => {
  it('flags a route whose anonymous and authenticated responses are identical', () => {
    const anon = result({ status: 200, body_hash: 'same' });
    const authed = result({
      status: 200, body_hash: 'same',
      request: { id: 'authenticated GET /users', variant: 'authenticated' },
    });
    const f = analyzeRoutes(input({ results: [anon, authed], hasCredentials: true }));
    const hit = f.find((x) => x.check === 'differential_authz');
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('high');
  });

  it('does not flag when the bodies differ', () => {
    const anon = result({ status: 200, body_hash: 'a' });
    const authed = result({
      status: 200, body_hash: 'b',
      request: { id: 'authenticated GET /users', variant: 'authenticated' },
    });
    const f = analyzeRoutes(input({ results: [anon, authed], hasCredentials: true }));
    expect(f.some((x) => x.check === 'differential_authz')).toBe(false);
  });

  it('does not flag when the anonymous request was rejected', () => {
    const anon = result({ status: 401, body_hash: 'x' });
    const authed = result({
      status: 401, body_hash: 'x',
      request: { id: 'authenticated GET /users', variant: 'authenticated' },
    });
    const f = analyzeRoutes(input({ results: [anon, authed], hasCredentials: true }));
    expect(f.some((x) => x.check === 'differential_authz')).toBe(false);
  });
});

describe('analyzeRoutes — CORS', () => {
  it('flags a reflected Origin combined with credentials', () => {
    const cors = result({
      status: 200,
      headers: {
        'access-control-allow-origin': 'https://dev-guardian-cors-probe.invalid',
        'access-control-allow-credentials': 'true',
      },
      request: { id: 'cors GET /users', variant: 'cors' },
    });
    const f = analyzeRoutes(input({ results: [cors] }));
    expect(f.find((x) => x.check === 'cors')?.severity).toBe('critical');
  });

  it('flags wildcard-with-credentials', () => {
    const cors = result({
      status: 200,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      },
      request: { id: 'cors GET /users', variant: 'cors' },
    });
    expect(analyzeRoutes(input({ results: [cors] })).some((x) => x.check === 'cors')).toBe(true);
  });

  it('does not flag a reflected origin WITHOUT credentials', () => {
    const cors = result({
      status: 200,
      headers: { 'access-control-allow-origin': 'https://dev-guardian-cors-probe.invalid' },
      request: { id: 'cors GET /users', variant: 'cors' },
    });
    expect(analyzeRoutes(input({ results: [cors] })).some((x) => x.check === 'cors')).toBe(false);
  });
});

describe('analyzeRoutes — open redirect and method surface', () => {
  it('flags a 3xx whose Location leaves the target origin', () => {
    const f = analyzeRoutes(input({
      results: [result({ status: 302, headers: { location: 'https://evil.example.com/' } })],
    }));
    expect(f.some((x) => x.check === 'open_redirect')).toBe(true);
  });

  it('does not flag a same-origin or relative redirect', () => {
    for (const location of ['/login', 'http://localhost:3000/login']) {
      const f = analyzeRoutes(input({
        results: [result({ status: 302, headers: { location } })],
      }));
      expect(f.some((x) => x.check === 'open_redirect'), location).toBe(false);
    }
  });

  it('flags methods the server advertises that the inventory never saw', () => {
    const f = analyzeRoutes(input({
      results: [result({
        status: 204,
        headers: { allow: 'GET, HEAD, OPTIONS, DELETE' },
        request: { id: 'anonymous OPTIONS /users', method: 'OPTIONS', variant: 'anonymous' },
      })],
    }));
    const hit = f.find((x) => x.check === 'method_surface');
    expect(hit?.message).toMatch(/DELETE/);
    // HEAD and OPTIONS are added automatically by mainstream frameworks to
    // any GET route, so a server advertising them is not a discovery — it is
    // noise, and noise in an accusation about a running system is the
    // over-reporting this feature refuses to do. A bare /DELETE/ match would
    // pass while the message also named both.
    expect(hit?.message).not.toMatch(/HEAD/);
    expect(hit?.message).not.toMatch(/OPTIONS/);
  });

  it('does not flag a server that advertises only the framework defaults', () => {
    const f = analyzeRoutes(input({
      results: [result({
        status: 204,
        headers: { allow: 'GET, HEAD, OPTIONS' },
        request: { id: 'anonymous OPTIONS /users', method: 'OPTIONS', variant: 'anonymous' },
      })],
    }));
    expect(f.some((x) => x.check === 'method_surface')).toBe(false);
  });
});

/**
 * Every route-scoped check filters to `variant === 'anonymous'`, and until
 * now nothing exercised them with credentials in play — so the filters could
 * be deleted one at a time and the suite would stay green. `plan.ts` builds
 * an `authenticated` request for every (method, path) once a credential is
 * supplied, on top of the `cors` GET it already adds at every kept path, so a
 * missing filter is a check firing two or three times on one fact.
 *
 * This is the same defect `checkInfoDisclosure` actually shipped with. The
 * assertions below are exact counts, not `some(...)`: a predicate passes for
 * both the correct implementation and the one that double-fires.
 */
describe('analyzeRoutes — route-scoped checks fire once per fact, with credentials in play', () => {
  const r = route({ auth_hint: 'required' });
  /** The three variants `plan.ts` sends to one route when a credential exists. */
  const variants = (over: Partial<ProbeResult> = {}): ProbeResult[] => [
    result({ ...over, request: { id: 'anonymous GET /users', variant: 'anonymous' } }),
    result({ ...over, request: { id: 'authenticated GET /users', variant: 'authenticated' } }),
    result({ ...over, request: { id: 'cors GET /users', variant: 'cors' } }),
  ];

  function analyze(over: Partial<ProbeResult>): ReturnType<typeof analyzeRoutes> {
    return analyzeRoutes(input({
      hasCredentials: true,
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      inventoryRoutes: [r],
      // Distinct body hashes per variant, so `differential_authz` (which
      // needs a byte-identical pair) stays out of these counts and each
      // assertion below is about its own check alone.
      results: variants(over).map((x, i) => ({ ...x, body_hash: `h${i}` })),
    }));
  }

  it('reports anonymous exposure once, not once per variant', () => {
    const f = analyze({ status: 200 });
    expect(f.filter((x) => x.check === 'anonymous_exposure')).toHaveLength(1);
  });

  it('reports an open redirect once, not once per variant', () => {
    const f = analyze({ status: 302, headers: { location: 'https://evil.example.com/' } });
    expect(f.filter((x) => x.check === 'open_redirect')).toHaveLength(1);
  });

  it('reports an undocumented method once, not once per variant', () => {
    // Honest note on what this one proves: `checkMethodSurface` is defended
    // twice over — the variant filter AND its own per-path `reported` Set —
    // and each mechanism alone keeps this at 1. Verified by mutation: removing
    // either one leaves this green, removing BOTH turns it red (3 findings).
    // So it pins the contract rather than any single guard, unlike its three
    // siblings above, each of which fails the moment its filter is dropped.
    const f = analyze({ status: 204, headers: { allow: 'GET, DELETE' } });
    expect(f.filter((x) => x.check === 'method_surface')).toHaveLength(1);
  });

  it('reports a confirmed shadow endpoint once, not once per variant', () => {
    const f = analyzeRoutes(input({
      hasCredentials: true,
      plan: { requests: [], routes: [r], skipped: [], truncated: false },
      inventoryRoutes: [r],
      shadowPaths: new Set(['/users']),
      results: variants({ status: 200 }).map((x, i) => ({ ...x, body_hash: `h${i}` })),
    }));
    expect(f.filter((x) => x.check === 'reachability')).toHaveLength(1);
  });
});

/**
 * `method_surface` compares what the server ADVERTISES against what the
 * INVENTORY holds — never against the subset of the inventory this run
 * happened to probe. Those two are the same array only when the envelope
 * dropped nothing, which under the default read-only envelope is never true
 * for any project that has a single POST route.
 *
 * The plausible-wrong implementation reads `plan.routes` (the routes that
 * SURVIVED the envelope — `plan.ts` `continue`s on `method_envelope` before
 * `kept.push`). Every test below is built so that `plan.routes` and
 * `inventoryRoutes` genuinely differ: reading the wrong one accuses the user
 * of a route their own inventory contains, and is contradicted by the very
 * snapshot the scan just read.
 */
describe('analyzeRoutes — method_surface reads the full inventory, not the probed subset', () => {
  const GET_X = route({ method: 'GET', path_raw: '/x', path_resolved: '/x' });
  const POST_X = route({ method: 'POST', path_raw: '/x', path_resolved: '/x' });

  /** The `Allow` probe as `plan.ts` actually builds it, aimed at `/x`. */
  const allowResult = (allow: string): ProbeResult =>
    result({
      status: 204,
      headers: { allow },
      request: {
        id: 'anonymous OPTIONS /x',
        method: 'OPTIONS',
        path: '/x',
        url: 'http://localhost:3000/x',
        variant: 'anonymous',
      },
    });

  it('stays silent on a POST the inventory declares but the read-only envelope dropped', () => {
    // The exact default-path shape: a DRF/Spring/Express project with both
    // `GET /x` and `POST /x` written down. The default envelope keeps only
    // the GET, so `plan.routes` is [GET /x] while the inventory holds both.
    // Reading `plan.routes` yields known = {GET}, POST survives the
    // `isImpliedMethod` carve-out, and a medium finding fires saying POST is
    // "absent from the extracted route inventory" — about a route sitting in
    // the inventory the same scan read.
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [GET_X], skipped: [], truncated: false },
      inventoryRoutes: [GET_X, POST_X],
      results: [allowResult('GET, POST')],
    }));
    expect(f.filter((x) => x.check === 'method_surface')).toEqual([]);
  });

  it('stays silent on the same inventory once allow_write_methods opens the envelope', () => {
    // The control for the test above: with writes allowed, `plan.routes`
    // holds both routes, so BOTH implementations stay silent here. Pinning
    // it keeps the fix honest — the correct implementation must be silent in
    // both configurations, not merely in the one the bug shows up in.
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [GET_X, POST_X], skipped: [], truncated: false },
      inventoryRoutes: [GET_X, POST_X],
      results: [allowResult('GET, POST')],
    }));
    expect(f.filter((x) => x.check === 'method_surface')).toEqual([]);
  });

  it('still reports a genuine discovery, naming only the method the inventory lacks', () => {
    // The other direction, and the reason this check exists at all: DELETE is
    // in neither the plan nor the inventory. Widening the comparison set must
    // not blind the check — exactly one finding, naming DELETE and nothing
    // else. `not.toMatch(/POST/)` is what separates "reads the inventory"
    // from "reports every method in Allow".
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [GET_X], skipped: [], truncated: false },
      inventoryRoutes: [GET_X, POST_X],
      results: [allowResult('GET, POST, DELETE')],
    }));
    const hits = f.filter((x) => x.check === 'method_surface');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/advertises DELETE, absent from/);
    expect(hits[0]?.message).not.toMatch(/POST/);
  });

  it('names a repeated Allow entry once, not once per repetition', () => {
    // `extra.join(', ')` over an un-deduped array renders "DELETE, DELETE"
    // for a server that repeats a verb in its Allow header — a report that
    // reads like two discoveries where there is one.
    const f = analyzeRoutes(input({
      plan: { requests: [], routes: [GET_X], skipped: [], truncated: false },
      inventoryRoutes: [GET_X],
      results: [allowResult('GET, DELETE, DELETE')],
    }));
    expect(f.find((x) => x.check === 'method_surface')?.message)
      .toMatch(/advertises DELETE, absent from/);
  });
});

describe('dast fingerprints', () => {
  it('is stable across a status change for the same check and route', () => {
    // Selected by check, never by index: analyzeRoutes may legitimately emit
    // more than one finding for a result, and an index-based assertion would
    // start comparing two different checks the moment it does.
    const pick = (results: ProbeResult[]): string | undefined =>
      analyzeRoutes(input({ results })).find((x) => x.check === 'open_redirect')?.fingerprint;

    const a = pick([result({ status: 302, headers: { location: 'https://evil.example.com/' } })]);
    const b = pick([result({ status: 307, headers: { location: 'https://evil.example.com/x' } })]);
    expect(a).toBeDefined();
    expect(a).toBe(b);
  });
});
