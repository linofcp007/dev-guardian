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
    expect(hit?.severity).toBe('critical');
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
