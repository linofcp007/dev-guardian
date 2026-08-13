import { describe, expect, it } from 'vitest';
import {
  selectRateLimitTarget, buildBurst, rateLimitVerdict, RATE_LIMIT_BURST,
} from '../../../src/dast/rateLimit.js';
import { route, result } from './helpers.js';

describe('selectRateLimitTarget', () => {
  it('prefers the explicitly named path over any inference', () => {
    const routes = [route({ path_resolved: '/login' }), route({ path_resolved: '/custom' })];
    const sel = selectRateLimitTarget(routes, '/custom');
    expect(sel?.route.path_resolved).toBe('/custom');
    expect(sel?.inferred).toBe(false);
  });

  it('returns null when the explicit path is not in the inventory', () => {
    // Never fall back to bursting something else: the caller named a target,
    // and silently bursting a different endpoint is the worst possible answer.
    expect(selectRateLimitTarget([route({ path_resolved: '/login' })], '/nope')).toBeNull();
  });

  it('infers an auth-shaped route and marks it inferred', () => {
    const routes = [route({ path_resolved: '/health' }), route({ path_resolved: '/api/v1/login', method: 'POST' })];
    const sel = selectRateLimitTarget(routes, null);
    expect(sel?.route.path_resolved).toBe('/api/v1/login');
    expect(sel?.inferred).toBe(true);
  });

  it('returns null when nothing looks like an auth endpoint', () => {
    expect(selectRateLimitTarget([route({ path_resolved: '/health' })], null)).toBeNull();
  });

  it('never selects a path_partial route', () => {
    expect(selectRateLimitTarget([route({ path_resolved: '/login', path_partial: true })], null))
      .toBeNull();
  });

  it('never selects a path_partial route even when explicitly named', () => {
    // The brief's rule is "path_partial routes are never selectable by
    // either route" — the inference case above alone leaves a wrong
    // implementation that only guards inference (and matches the explicit
    // path unconditionally) passing every other test in this file.
    const routes = [route({ path_resolved: '/login', path_partial: true })];
    expect(selectRateLimitTarget(routes, '/login')).toBeNull();
  });

  it('does not infer a GET-only route as an auth endpoint — a login page is not a login handler', () => {
    // A server-rendered login PAGE matches AUTH_PATH_HINTS on path alone,
    // exactly like the form handler that actually checks credentials would.
    // Bursting it produces thirty 404s/405s, never a 429 — a confident-shaped
    // `{ observed: false, sent: 30 }` from a burst that never reached
    // authentication code, indistinguishable from a genuine negative.
    const routes = [route({ path_resolved: '/login', method: 'GET' })];
    expect(selectRateLimitTarget(routes, null)).toBeNull();
  });

  it('skips a GET auth-shaped route in favor of a write-capable one elsewhere', () => {
    // Guards against a fix that filters by method but still returns the
    // first PATH match: the correct implementation must keep looking past
    // the disqualified GET /login and find the real POST handler.
    const routes = [
      route({ path_resolved: '/login', method: 'GET' }),
      route({ path_resolved: '/api/auth/login', method: 'POST' }),
    ];
    const sel = selectRateLimitTarget(routes, null);
    expect(sel?.route.path_resolved).toBe('/api/auth/login');
    expect(sel?.inferred).toBe(true);
  });
});

describe('buildBurst', () => {
  it('builds `size` identical requests with a synthetic invalid credential', () => {
    const reqs = buildBurst(route({ path_resolved: '/login', method: 'POST' }), 'http://x:1', 5);
    expect(reqs).toHaveLength(5);
    expect(reqs.every((r) => r.variant === 'rate_limit')).toBe(true);
    expect(reqs[0]?.method).toBe('POST');
    const body = reqs[0]?.body ?? '';
    // The username must be un-ownable so the lockout control under test can
    // never lock out a real account.
    expect(body).toMatch(/dev-guardian-probe/);
    expect(body).toMatch(/@invalid/);
    // Every request in the burst is identical — this is a limiter probe, not
    // a guessing attack.
    expect(new Set(reqs.map((r) => r.body)).size).toBe(1);
  });

  it('defaults the burst to RATE_LIMIT_BURST', () => {
    expect(buildBurst(route({ path_resolved: '/login' }), 'http://x:1', RATE_LIMIT_BURST))
      .toHaveLength(30);
  });
});

describe('rateLimitVerdict', () => {
  it('reports observed with the 1-based index of the first 429', () => {
    const results = [result({ status: 200 }), result({ status: 200 }), result({ status: 429 })];
    expect(rateLimitVerdict(results)).toEqual({ observed: true, at_request: 3 });
  });

  it('treats a 503 with Retry-After as a limiter too', () => {
    const results = [result({ status: 503, headers: { 'retry-after': '30' } })];
    expect(rateLimitVerdict(results).observed).toBe(true);
  });

  it('reports not-observed with how many were actually sent', () => {
    const results = Array.from({ length: 30 }, () => result({ status: 200 }));
    expect(rateLimitVerdict(results)).toEqual({ observed: false, sent: 30 });
  });

  it('counts only completed requests as sent', () => {
    const results = [
      result({ status: 200 }),
      result({ outcome: 'network_error', status: null }),
    ];
    expect(rateLimitVerdict(results)).toEqual({ observed: false, sent: 1 });
  });
});
