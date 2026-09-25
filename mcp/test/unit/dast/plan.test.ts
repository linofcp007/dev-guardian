import { describe, expect, it } from 'vitest';
import { planProbes, substituteParams, DEFAULT_MAX_REQUESTS } from '../../../src/dast/plan.js';
import type { RouteRecord } from '../../../src/types.js';

function route(over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: '/users',
    path_resolved: '/users',
    path_partial: false,
    file: 'src/routes/users.ts',
    line: 10,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    ...over,
  };
}

const OPTS = {
  origin: 'http://localhost:3000',
  allowWriteMethods: false,
  authHeaderValue: null,
  maxRequests: DEFAULT_MAX_REQUESTS,
};

describe('planProbes — safety envelope', () => {
  it('never plans a request for a path_partial route, and reports the skip', () => {
    const out = planProbes([route({ path_partial: true, path_resolved: '/{server}/users' })], OPTS);
    expect(out.requests).toEqual([]);
    expect(out.skipped).toEqual([
      { method: 'GET', path: '/{server}/users', reason: 'partial_path' },
    ]);
  });

  it('drops write methods under the read-only default and reports why', () => {
    const out = planProbes([route({ method: 'DELETE', path_resolved: '/users/1' })], OPTS);
    expect(out.requests).toEqual([]);
    expect(out.skipped[0]?.reason).toBe('method_envelope');
  });

  it('plans write methods with an EMPTY body once allowWriteMethods is on', () => {
    const out = planProbes([route({ method: 'DELETE', path_resolved: '/users/1' })], {
      ...OPTS,
      allowWriteMethods: true,
    });
    const del = out.requests.find((r) => r.method === 'DELETE');
    expect(del).toBeDefined();
    expect(del?.body).toBe('');
    expect(out.skipped).toEqual([]);
  });

  it('expands ANY to exactly the three read methods by default', () => {
    const out = planProbes([route({ method: 'ANY', path_resolved: '/all' })], OPTS);
    // Filter to the anonymous variant: every route also gets exactly one
    // `cors` GET probe, which is not part of the method expansion under test.
    // Exact set, not a count: a wrong implementation that expands to five and
    // then filters four would also produce "some" requests.
    const anon = out.requests.filter((r) => r.variant === 'anonymous');
    expect(anon.map((r) => r.method).sort()).toEqual(['GET', 'HEAD', 'OPTIONS']);
    // And the cors probe stays singular however wide the expansion gets.
    expect(out.requests.filter((r) => r.variant === 'cors')).toHaveLength(1);
  });

  it('expands ANY to all seven methods when writes are allowed', () => {
    const out = planProbes([route({ method: 'ANY', path_resolved: '/all' })], {
      ...OPTS,
      allowWriteMethods: true,
    });
    const anon = out.requests.filter((r) => r.variant === 'anonymous');
    expect(anon.map((r) => r.method).sort()).toEqual([
      'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT',
    ]);
    expect(out.requests.filter((r) => r.variant === 'cors')).toHaveLength(1);
  });

  it('builds an absolute url from the origin and the resolved path', () => {
    const out = planProbes([route({ path_resolved: '/users' })], OPTS);
    expect(out.requests[0]?.url).toBe('http://localhost:3000/users');
  });

  it('adds an authenticated twin for each anonymous probe when a credential is given', () => {
    const out = planProbes([route()], { ...OPTS, authHeaderValue: 'Bearer t0ken' });
    const variants = out.requests.map((r) => r.variant).sort();
    expect(variants).toContain('anonymous');
    expect(variants).toContain('authenticated');
    const authed = out.requests.find((r) => r.variant === 'authenticated');
    expect(authed?.headers['authorization']).toBe('Bearer t0ken');
    const anon = out.requests.find((r) => r.variant === 'anonymous');
    expect(anon?.headers['authorization']).toBeUndefined();
  });

  it('plans no authenticated twin at all without a credential', () => {
    const out = planProbes([route()], OPTS);
    expect(out.requests.some((r) => r.variant === 'authenticated')).toBe(false);
  });

  it('dedupes identical (method, path) routes into one probe per variant', () => {
    const out = planProbes(
      [route({ file: 'a.ts' }), route({ file: 'b.ts' })],
      OPTS,
    );
    expect(out.requests.filter((r) => r.variant === 'anonymous')).toHaveLength(1);
    expect(out.skipped.some((s) => s.reason === 'duplicate')).toBe(true);
  });

  it('dedupes per (method, path), so an ANY route cannot re-fire a specific route write probe', () => {
    // Measured defect: keying dedupe on the whole expanded method-set string
    // gave `DELETE /users/1` and `ANY /users/1` different keys, so BOTH planned
    // an anonymous DELETE at the same URL — two destructive-shaped requests at
    // a live target, carrying an identical `id` that downstream correlation
    // keys on. A spec declaring `delete` plus an `app.all()` in code produces
    // exactly this pair.
    const out = planProbes(
      [
        route({ method: 'DELETE', path_resolved: '/users/1', file: 'a.ts' }),
        route({ method: 'ANY', path_resolved: '/users/1', file: 'b.ts' }),
      ],
      { ...OPTS, allowWriteMethods: true },
    );
    const deletes = out.requests.filter(
      (r) => r.variant === 'anonymous' && r.method === 'DELETE',
    );
    expect(deletes).toHaveLength(1);
    expect(out.requests.filter((r) => r.variant === 'cors')).toHaveLength(1);
    expect(
      out.skipped.filter((s) => s.reason === 'duplicate' && s.method === 'DELETE'),
    ).toHaveLength(1);
    // Every planned request id is unique: `id` is the correlation key.
    const ids = out.requests.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('caps the plan at maxRequests and reports truncated', () => {
    const routes = Array.from({ length: 20 }, (_, i) =>
      route({ path_resolved: `/r${i}` }),
    );
    // 20 routes × (1 anonymous GET + 1 cors GET) = 40 planned requests, of
    // which 5 survive the cap and 35 are reported as cap skips. The count is
    // spelled out rather than derived so a change in probes-per-route shows
    // up here as a failure instead of quietly passing.
    const out = planProbes(routes, { ...OPTS, maxRequests: 5 });
    expect(out.requests).toHaveLength(5);
    expect(out.truncated).toBe(true);
    expect(out.skipped.filter((s) => s.reason === 'cap')).toHaveLength(35);
  });

  it('does not report truncated when the plan fits', () => {
    const out = planProbes([route()], OPTS);
    expect(out.truncated).toBe(false);
  });

  it('keeps route_index aligned with the surviving routes', () => {
    const out = planProbes(
      [route({ path_partial: true }), route({ path_resolved: '/kept', file: 'k.ts' })],
      OPTS,
    );
    const req = out.requests[0];
    expect(req).toBeDefined();
    const idx = req?.route_index;
    expect(idx).not.toBeNull();
    expect(out.routes[idx as number]?.file).toBe('k.ts');
  });

  it('plans a CORS variant carrying an off-origin Origin header', () => {
    const out = planProbes([route()], OPTS);
    const cors = out.requests.find((r) => r.variant === 'cors');
    expect(cors?.headers['origin']).toMatch(/^https:\/\/.*\.invalid$/);
    expect(cors?.method).toBe('GET');
  });

  // Measured defect (task 4 brief, item 1): a Django/Laravel/Rails/Spring
  // path with no leading slash (`api/users/`) concatenated onto
  // `http://localhost` naively produced `http://localhostapi/users/` — a
  // request to a HOST that happens to share a prefix with the real one,
  // never to the target at all. Normalising the leading slash before
  // building the URL is what makes `new URL(path, origin)` resolve it as a
  // path ON origin instead.
  it('normalises a resolved path missing its leading slash before building the url', () => {
    const out = planProbes([route({ path_resolved: 'api/users' })], OPTS);
    expect(out.requests[0]?.url).toBe('http://localhost:3000/api/users');
    expect(out.requests[0]?.path).toBe('/api/users');
    expect(out.skipped).toEqual([]);
  });

  // A protocol-relative path (`//evil.example/x`) is a NETWORK-PATH
  // reference per RFC 3986: `new URL('//evil.example/x', origin)` resolves
  // to host `evil.example`, not `origin`'s own host, however the leading
  // slash is normalised. This is the one shape leading-slash normalisation
  // alone cannot fix, and exactly why every request URL must also be
  // checked against `origin` after being built, never assumed safe just
  // because it was built with `new URL`.
  it('skips a route whose resolved path would leave the origin, with reason off_origin', () => {
    const out = planProbes([route({ path_resolved: '//evil.example/x' })], OPTS);
    expect(out.requests).toEqual([]);
    expect(out.skipped).toEqual([
      { method: 'GET', path: '//evil.example/x', reason: 'off_origin' },
    ]);
  });

  it('never sends a request whose url origin differs from the target, across every planned variant', () => {
    // Guards a partial fix that only checks the anonymous probe and still
    // builds the authenticated/cors twins from the unnormalised path.
    const out = planProbes([route({ path_resolved: '//evil.example/x' })], {
      ...OPTS,
      authHeaderValue: 'Bearer t0ken',
    });
    expect(out.requests).toEqual([]);
  });
});

describe('substituteParams', () => {
  it('substitutes all four parameter syntaxes and flags the path synthetic', () => {
    const cases: [string, string][] = [
      ['/users/{id}', '/users/1'],
      ['/users/:id', '/users/1'],
      ['/users/<int:id>', '/users/1'],
      ['/wp/v2/posts/(?P<id>[0-9]+)', '/wp/v2/posts/1'],
    ];
    for (const [input, expected] of cases) {
      const r = substituteParams(input);
      expect(r.path, input).toBe(expected);
      expect(r.synthetic, input).toBe(true);
    }
  });

  it('leaves a parameterless path untouched and not synthetic', () => {
    const r = substituteParams('/users');
    expect(r.path).toBe('/users');
    expect(r.synthetic).toBe(false);
  });

  it('substitutes every parameter in a multi-parameter path', () => {
    const r = substituteParams('/orgs/{org}/repos/{repo}');
    expect(r.path).toBe('/orgs/1/repos/1');
  });
});
