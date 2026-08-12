import { describe, expect, it } from 'vitest';
import { diffSpecRoutes, normalisePath } from '../../../src/surface/specDiff.js';
import type { RouteRecord } from '../../../src/types.js';

function route(over: Partial<RouteRecord> & { path_resolved: string }): RouteRecord {
  return {
    method: 'GET',
    path_raw: over.path_resolved,
    path_partial: false,
    file: 'f',
    line: 1,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    provenance: 'code',
    ...over,
  };
}

const spec = (over: Partial<RouteRecord> & { path_resolved: string }): RouteRecord =>
  route({ ...over, provenance: 'spec', framework: 'openapi-3', language: 'spec' });

describe('normalisePath', () => {
  it('collapses every parameter syntax to one placeholder', () => {
    expect(normalisePath('/users/{id}')).toBe('/users/{}');
    expect(normalisePath('/users/:id')).toBe('/users/{}');
    expect(normalisePath('/users/:id?')).toBe('/users/{}');
    expect(normalisePath('/users/<int:id>')).toBe('/users/{}');
    expect(normalisePath('/users/(?P<id>\\d+)')).toBe('/users/{}');
  });

  it('strips a trailing slash and guarantees a leading one', () => {
    expect(normalisePath('/users/')).toBe('/users');
    expect(normalisePath('users')).toBe('/users');
  });
});

describe('diffSpecRoutes', () => {
  it('returns null when no spec parsed — absence of a spec is not a finding', () => {
    expect(diffSpecRoutes([route({ path_resolved: '/a' })], [], 0)).toBeNull();
  });

  it('matches the same endpoint written in two syntaxes', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/users/:id' })],
      [spec({ path_resolved: '/users/{id}' })],
      1,
    );
    expect(d?.matched).toHaveLength(1);
    expect(d?.code_only).toEqual([]);
    expect(d?.spec_only).toEqual([]);
  });

  it('reports a code route no spec documents as a shadow endpoint', () => {
    const d = diffSpecRoutes([route({ path_resolved: '/secret' })], [spec({ path_resolved: '/known' })], 1);
    expect(d?.code_only.map((e) => e.path)).toEqual(['/secret']);
  });

  it('reports a spec route no code implements as dead documentation', () => {
    const d = diffSpecRoutes([route({ path_resolved: '/known' })], [spec({ path_resolved: '/gone' })], 1);
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/gone']);
  });

  it('treats an ANY code route as matching any documented method', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/x', method: 'ANY' })],
      [spec({ path_resolved: '/x', method: 'POST' })],
      1,
    );
    expect(d?.matched).toHaveLength(1);
  });

  it('sends a partial code route to unmatchable, never to shadow', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/other' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
    expect(d?.unmatchable.some((e) => e.code_route?.path_resolved === '/list')).toBe(true);
  });

  it('sends a spec route with a templated server to unmatchable', () => {
    const d = diffSpecRoutes([], [spec({ path_resolved: '/x', path_partial: true })], 1);
    expect(d?.spec_only).toEqual([]);
    expect(d?.unmatchable).toHaveLength(1);
  });

  it('does not call a spec route dead when a partial code route could be it', () => {
    // The code registers /list behind an unresolved mount; the spec says
    // /api/list. That is the same route, not dead documentation.
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/api/list' })],
      1,
    );
    expect(d?.spec_only).toEqual([]);
    expect(d?.unmatchable.some((e) => e.spec_route?.path_resolved === '/api/list')).toBe(true);
  });

  it('still calls a spec route dead when no partial route shares its suffix', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/api/orders' })],
      1,
    );
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/api/orders']);
  });

  it('ignores provenance mislabelling by filtering its own inputs', () => {
    // Defensive: the caller splits by provenance, but a spec route arriving in
    // the code list must not be diffed against itself.
    const d = diffSpecRoutes(
      [spec({ path_resolved: '/x' })],
      [spec({ path_resolved: '/x' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
  });
});
