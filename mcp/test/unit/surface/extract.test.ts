import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  extractParams,
  extractSurface,
  isLiteralPath,
  languageFromPath,
} from '../../../src/surface/extract.js';

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(join(__dirname, '../../fixtures/surface', name), 'utf8'));

describe('extractSurface', () => {
  it('maps a route match to a RouteRecord', () => {
    const { routes } = extractSurface(fixture('express.json'));
    expect(routes).toHaveLength(1);
    const route = routes[0];
    expect(route?.method).toBe('GET');
    expect(route?.path_raw).toBe('/users/:id');
    expect(route?.path_resolved).toBe('/users/:id');
    expect(route?.path_partial).toBe(false);
    expect(route?.file).toBe('src/routes/users.ts');
    expect(route?.line).toBe(12);
    expect(route?.framework).toBe('express');
    expect(route?.language).toBe('typescript');
    expect(route?.params).toEqual(['id']);
    expect(route?.confidence).toBe('high');
    expect(route?.auth_hint).toBe('unknown');
  });

  it('maps a mount match to a MountRecord', () => {
    const { mounts } = extractSurface(fixture('express.json'));
    expect(mounts).toEqual([
      { prefix: '/api', router_var: 'usersRouter', file: 'src/app.ts', line: 4 },
    ]);
  });

  it('ignores matches without guardian_kind — other rule packs must not leak in', () => {
    const { routes, mounts } = extractSurface(fixture('express.json'));
    expect(routes.every((r) => r.framework !== '')).toBe(true);
    expect(routes.length + mounts.length).toBe(2);
  });

  it('defaults confidence to low when the rule omits it', () => {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'x',
          path: 'a.py',
          start: { line: 1 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'flask' },
            metavars: { $PATH: { abstract_content: '/x' } },
          },
        },
      ],
    });
    expect(routes[0]?.confidence).toBe('low');
    expect(routes[0]?.method).toBe('ANY');
  });

  it('returns empty arrays for malformed input instead of throwing', () => {
    expect(extractSurface(null)).toEqual({ routes: [], mounts: [] });
    expect(extractSurface({ results: 'nope' })).toEqual({ routes: [], mounts: [] });
    expect(extractSurface({ results: [{ nonsense: true }] })).toEqual({
      routes: [],
      mounts: [],
    });
  });

  it('reads $NS + $ROUTE for namespaced frameworks, keeping them separate', () => {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'guardian-route-wp-rest',
          path: 'wp-content/plugins/x/api.php',
          start: { line: 20 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'wp-rest', confidence: 'high' },
            metavars: {
              $NS: { abstract_content: "'myplugin/v1'" },
              $ROUTE: { abstract_content: "'/items'" },
            },
          },
        },
      ],
    });
    // Semgrep cannot build a third metavariable, so the extractor keeps both
    // and the WP resolver composes them. Quotes from abstract_content go.
    expect(routes[0]?.namespace).toBe('myplugin/v1');
    expect(routes[0]?.path_raw).toBe('/items');
  });

  it('leaves namespace undefined for frameworks that have none', () => {
    const { routes } = extractSurface(fixture('express.json'));
    expect(routes[0]?.namespace).toBeUndefined();
  });

  it('reads auth_hint from rule metadata only', () => {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'x',
          path: 'a.cs',
          start: { line: 3 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'aspnet', auth: 'required' },
            metavars: { $PATH: { abstract_content: '/admin' } },
          },
        },
      ],
    });
    expect(routes[0]?.auth_hint).toBe('required');
  });
});

describe('isLiteralPath', () => {
  // Every value a Semgrep metavariable was observed to bind that is a code
  // expression, not a path. The next tool in this series sends HTTP requests
  // to whatever path it is handed, so any of these leaking through as a
  // confident path is a correctness bug, not cosmetics.
  const CODE_EXPRESSIONS = [
    'self::NAMESPACE',
    '$this->namespace',
    '$route',
    'SETTINGS.users_path',
    'Paths.ORDERS',
    'routeVar',
    'MyController.BASE',
  ];

  // Real route syntax across the stacks the pack covers. `items` is a valid
  // WordPress route (no leading slash) and the (?P<id>\d+) form is a valid WP
  // regex route — parentheses, ?, <, > and a backslash are all legitimate.
  const REAL_PATHS = [
    '/users/:id',
    '/items',
    'items',
    '/items/(?P<id>\\d+)',
    '/users/{id}',
    '/opt/:id?',
    '/items/<int:item_id>',
  ];

  for (const value of CODE_EXPRESSIONS) {
    it(`rejects the code expression ${value}`, () => {
      expect(isLiteralPath(value)).toBe(false);
    });
  }

  for (const value of REAL_PATHS) {
    it(`accepts the real path ${value}`, () => {
      expect(isLiteralPath(value)).toBe(true);
    });
  }

  it('rejects an empty or blank capture', () => {
    expect(isLiteralPath('')).toBe(false);
    expect(isLiteralPath('   ')).toBe(false);
  });

  it('rejects concatenation and calls even when a slash is present', () => {
    expect(isLiteralPath('basePath + /users')).toBe(false);
    expect(isLiteralPath('prefix()/users')).toBe(false);
    expect(isLiteralPath('routes[0]/users')).toBe(false);
  });
});

describe('extractSurface path-literal guard', () => {
  function routeFrom(pathValue: string, metadata: Record<string, unknown> = {}): unknown {
    return {
      results: [
        {
          check_id: 'guardian-route-x',
          path: 'src/a.php',
          start: { line: 1 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'wp-rest', confidence: 'medium', ...metadata },
            metavars: { $PATH: { abstract_content: pathValue } },
          },
        },
      ],
    };
  }

  it('flags a non-literal capture partial, keeps the raw value, drops confidence', () => {
    const { routes } = extractSurface(routeFrom('self::NAMESPACE'));
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path_partial).toBe(true);
    expect(routes[0]?.path_resolved).toBe('self::NAMESPACE');
    expect(routes[0]?.path_raw).toBe('self::NAMESPACE');
    expect(routes[0]?.confidence).toBe('low');
  });

  it('keeps the route — a path we cannot name is still evidence of surface', () => {
    const { routes } = extractSurface(routeFrom('$this->namespace'));
    expect(routes).toHaveLength(1);
    expect(routes[0]?.file).toBe('src/a.php');
  });

  it('leaves a real path resolved and at its rule confidence', () => {
    const { routes } = extractSurface(routeFrom('/items/(?P<id>\\d+)'));
    expect(routes[0]?.path_partial).toBe(false);
    expect(routes[0]?.confidence).toBe('medium');
  });

  it('flags a non-literal $NS namespace too', () => {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'guardian-route-wp-rest',
          path: 'api.php',
          start: { line: 1 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'wp-rest', confidence: 'medium' },
            metavars: {
              $NS: { abstract_content: 'self::NAMESPACE' },
              $ROUTE: { abstract_content: "'/items'" },
            },
          },
        },
      ],
    });
    expect(routes[0]?.namespace).toBe('self::NAMESPACE');
    expect(routes[0]?.path_partial).toBe(true);
  });
});

describe('normalizeMethod via extractSurface', () => {
  function methodFrom(metavars: Record<string, unknown>, metadata: Record<string, unknown> = {}) {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'guardian-route-x',
          path: 'a.cs',
          start: { line: 1 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'aspnet-minimal', ...metadata },
            metavars: { $PATH: { abstract_content: '/users' }, ...metavars },
          },
        },
      ],
    });
    return routes[0]?.method;
  }

  it('understands the ASP.NET minimal-API Map* form', () => {
    expect(methodFrom({ $METHOD: { abstract_content: 'MapGet' } })).toBe('GET');
    expect(methodFrom({ $METHOD: { abstract_content: 'MapDelete' } })).toBe('DELETE');
  });

  it('falls back to metadata.method when the rule captures no $METHOD', () => {
    expect(methodFrom({}, { method: 'POST' })).toBe('POST');
  });

  it('still reports ANY for an unrecognised verb', () => {
    expect(methodFrom({ $METHOD: { abstract_content: 'MapGroup' } })).toBe('ANY');
    expect(methodFrom({ $METHOD: { abstract_content: 'map' } })).toBe('ANY');
  });
});

describe('extractParams', () => {
  it('normalises every supported parameter syntax to a bare name', () => {
    expect(extractParams('/users/:id')).toEqual(['id']);
    expect(extractParams('/users/{id}/posts/{postId}')).toEqual(['id', 'postId']);
    expect(extractParams('/items/<int:item_id>')).toEqual(['item_id']);
    expect(extractParams('/opt/:id?')).toEqual(['id']);
    expect(extractParams('/static/path')).toEqual([]);
  });
});

describe('languageFromPath', () => {
  it('maps extensions to the language names used in coverage reporting', () => {
    expect(languageFromPath('a/b.ts')).toBe('typescript');
    expect(languageFromPath('a/b.py')).toBe('python');
    expect(languageFromPath('a/b.php')).toBe('php');
    expect(languageFromPath('a/b.unknown')).toBe('unknown');
  });
});
