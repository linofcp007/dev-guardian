// Shared fixture builders for the DAST unit tests. Tasks 4, 5, 6 and 9 all
// import from here — three divergent copies of a fixture builder is how a
// test starts asserting against a shape the code no longer produces.
import type { AnalyzeInput } from '../../../src/dast/analyze.js';
import type { ProbeRequest, ProbeResult } from '../../../src/dast/types.js';
import type { RouteRecord } from '../../../src/types.js';

export function route(over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET', provenance: 'code', path_raw: '/users', path_resolved: '/users',
    path_partial: false, file: 'src/users.ts', line: 10, framework: 'express',
    language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
    ...over,
  };
}

export function result(
  over: Partial<Omit<ProbeResult, 'request'>> & { request?: Partial<ProbeRequest> } = {},
): ProbeResult {
  const { request: requestOver, ...rest } = over;
  const request: ProbeRequest = {
    id: 'anonymous GET /users', method: 'GET', path: '/users',
    url: 'http://localhost:3000/users', headers: {}, variant: 'anonymous',
    synthetic_params: false, route_index: 0, ...requestOver,
  };
  return {
    request, outcome: 'completed', status: 200, headers: {}, body_prefix: '',
    body_hash: 'h', elapsed_ms: 1, error: null, ...rest,
  };
}

export function input(over: Partial<AnalyzeInput> = {}): AnalyzeInput {
  return {
    plan: { requests: [], routes: [route()], skipped: [], truncated: false },
    results: [],
    origin: 'http://localhost:3000',
    shadowPaths: new Set<string>(),
    deadDocPaths: new Set<string>(),
    hasCredentials: false,
    ...over,
  };
}
