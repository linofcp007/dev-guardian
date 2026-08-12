import { describe, expect, it } from 'vitest';
import { resolveWordpressRoutes } from '../../../../src/surface/resolvers/wordpress.js';
import type { RouteRecord } from '../../../../src/types.js';

function wpRoute(pathRaw: string, overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: pathRaw,
    path_resolved: pathRaw,
    path_partial: false,
    file: 'wp-content/plugins/x/api.php',
    line: 20,
    framework: 'wp-rest',
    language: 'php',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    namespace: 'myplugin/v1',
    ...overrides,
  };
}

describe('resolveWordpressRoutes', () => {
  it('joins namespace and route under /wp-json', () => {
    const [r] = resolveWordpressRoutes([wpRoute('/items')]);
    expect(r?.path_resolved).toBe('/wp-json/myplugin/v1/items');
    expect(r?.path_partial).toBe(false);
    expect(r?.path_raw).toBe('/items');
  });

  it('tolerates slash variants on both sides', () => {
    expect(
      resolveWordpressRoutes([wpRoute('items', { namespace: '/myplugin/v1/' })])[0]?.path_resolved,
    ).toBe('/wp-json/myplugin/v1/items');
    expect(
      resolveWordpressRoutes([wpRoute('/items', { namespace: 'myplugin/v1' })])[0]?.path_resolved,
    ).toBe('/wp-json/myplugin/v1/items');
  });

  it('preserves a WP regex route segment verbatim', () => {
    const [r] = resolveWordpressRoutes([
      wpRoute('/items/(?P<id>\\d+)', { namespace: 'ns/v1' }),
    ]);
    expect(r?.path_resolved).toBe('/wp-json/ns/v1/items/(?P<id>\\d+)');
  });

  it('marks the route partial when the namespace is missing', () => {
    const [r] = resolveWordpressRoutes([wpRoute('/items', { namespace: undefined })]);
    expect(r?.path_partial).toBe(true);
    expect(r?.path_resolved).toBe('/items');
  });

  it('marks the route partial when the namespace is an empty string', () => {
    const [r] = resolveWordpressRoutes([wpRoute('/items', { namespace: '  ' })]);
    expect(r?.path_partial).toBe(true);
  });

  it('never clears a path_partial the extractor set on a non-literal capture', () => {
    // `register_rest_route(self::NAMESPACE, $route)` — the dominant real-world
    // idiom. /wp-json/self::NAMESPACE/$route is a URL that exists nowhere.
    const [r] = resolveWordpressRoutes([
      wpRoute('$route', { namespace: 'self::NAMESPACE', path_partial: true }),
    ]);
    expect(r?.path_partial).toBe(true);
    expect(r?.path_resolved).toBe('$route');
  });

  it('leaves non-wp-rest routes untouched', () => {
    const other = wpRoute('/x', { framework: 'laravel' });
    expect(resolveWordpressRoutes([other])[0]?.path_resolved).toBe('/x');
    expect(resolveWordpressRoutes([other])[0]?.path_partial).toBe(false);
  });
});
