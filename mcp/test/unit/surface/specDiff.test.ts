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

  it('returns null when specsParsed is negative — a parsed-minus-failed count must gate too', () => {
    // A caller computing `parsed − failed` can hand us a negative number.
    // That must gate exactly like zero, not fall through to a full diff
    // where every code route reads as undocumented.
    expect(diffSpecRoutes([route({ path_resolved: '/a' })], [], -1)).toBeNull();
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
    // The concrete, documented method is more informative than the 'ANY'
    // sentinel in a report meant for a human — pin which one wins.
    expect(d?.matched.map((e) => e.method)).toEqual(['POST']);
  });

  it('sends a partial code route to unmatchable, never to shadow', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/other' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
    const entry = d?.unmatchable.find((e) => e.code_route?.path_resolved === '/list');
    expect(entry).toBeDefined();
    expect(entry?.reason).toBe('code route has an unresolved prefix');
  });

  it('sends a spec route with a templated server to unmatchable', () => {
    const d = diffSpecRoutes([], [spec({ path_resolved: '/x', path_partial: true })], 1);
    expect(d?.spec_only).toEqual([]);
    expect(d?.unmatchable).toHaveLength(1);
    expect(d?.unmatchable.find((e) => e.spec_route?.path_resolved === '/x')?.reason)
      .toBe('spec server url is templated');
  });

  it('unmatchable entries report the raw path, not the resolved one, for partial routes', () => {
    // path_resolved is not trustworthy for a partial route — it may not even
    // be a path (RouteRecord's own doc comment). path_raw is what the source
    // literally says, and it is also the value the suffix rule itself
    // compares — so it, not path_resolved, is what an unmatchable entry
    // should display.
    const d = diffSpecRoutes(
      [route({ path_resolved: '/mounted/list', path_raw: '/list', path_partial: true })],
      [spec({ path_resolved: '/other' })],
      1,
    );
    const entry = d?.unmatchable.find((e) => e.code_route?.path_raw === '/list');
    expect(entry?.path).toBe('/list');
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
    expect(d?.spec_only_withheld).toBe(1);
    expect(d?.code_only_withheld).toBe(0);
  });

  it('still calls a spec route dead when no partial route shares its suffix', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/api/orders' })],
      1,
    );
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/api/orders']);
    expect(d?.spec_only_withheld).toBe(0);
  });

  it('does not call a code route a shadow endpoint when a partial spec route could be it', () => {
    // The spec's servers[].url is templated, so /orders is left unprefixed
    // and partial; the code registers GET /v2/orders. That is the same
    // route, not a shadow endpoint. Mirror-image of the spec_only guard
    // above — this is the direction fix round 1 added (I-1).
    const d = diffSpecRoutes(
      [route({ path_resolved: '/v2/orders' })],
      [spec({ path_resolved: '/orders', path_partial: true })],
      1,
    );
    expect(d?.code_only).toEqual([]);
    expect(d?.unmatchable.some((e) => e.code_route?.path_resolved === '/v2/orders')).toBe(true);
    expect(d?.code_only_withheld).toBe(1);
    expect(d?.spec_only_withheld).toBe(0);
  });

  it('still calls a code route a shadow endpoint when no partial spec route shares its suffix', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/v2/payments' })],
      [spec({ path_resolved: '/orders', path_partial: true })],
      1,
    );
    expect(d?.code_only.map((e) => e.path)).toEqual(['/v2/payments']);
    expect(d?.code_only_withheld).toBe(0);
  });

  it('ignores provenance mislabelling by filtering its own inputs', () => {
    // Defensive: the caller splits by provenance, but a spec route arriving in
    // the code list must not be diffed against itself. Both routes have the
    // same path, so a filter-less implementation would still find *a* match
    // (the mislabelled route pairs with the real spec route directly) and
    // code_only would read empty either way — that's why code_only alone
    // does not discriminate. matched and spec_only do: with the filter,
    // there is no code route at all to match, so matched stays empty and the
    // real spec route is unmatched (spec_only); without it, the two
    // structurally-identical routes pair off into matched instead.
    const d = diffSpecRoutes(
      [spec({ path_resolved: '/x' })],
      [spec({ path_resolved: '/x' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
    expect(d?.matched).toEqual([]);
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/x']);
  });
});
