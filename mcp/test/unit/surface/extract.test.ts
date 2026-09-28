import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  extractParams,
  extractSurface,
  INHERITED_PATH,
  INHERITED_PATH_KEY,
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
  // WordPress route (no leading slash) — parentheses, ?, < and > are all
  // legitimate. The `(?P<id>\d+)` regex-group shape (a backslash escape
  // inside it) used to live in this list too; it now lives in the
  // host-confusion describe block below, next to why it moved.
  const REAL_PATHS = [
    '/users/:id',
    '/items',
    'items',
    '/users/{id}',
    '/opt/:id?',
    '/items/<int:item_id>',
    // A dot NOT at the start, and a slash-containing path with no other
    // punctuation, are both ordinary and must stay accepted — only a
    // LEADING dot is the host-confusion shape (see below).
    '/files/report.pdf',
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

  // Task 4 brief, item 2: a captured "path" that reaches `dast/plan.ts` as
  // `path_partial: false` is treated as a VERIFIED, probeable URL. These
  // four shapes turn a naive `${origin}${path}` (or even a careless
  // `new URL` call elsewhere that is not `plan.ts#buildProbeUrl`) into a
  // request at a DIFFERENT host — see that file's rule 5 for the mechanism.
  // `isLiteralPath` is the extraction-time backstop: reject them here so
  // nothing downstream of the extractor ever has to reason about whether a
  // "resolved, high-confidence" route might secretly be one of these.
  describe('rejects host-confusion shapes even when a slash is present', () => {
    const HOST_CONFUSION = [
      // `@` reads as a URL userinfo separator ahead of a host when the
      // origin and this path are concatenated naively.
      '/redirect/@evil.example/x',
      '@evil.example/x',
      // A leading `.` can resolve as a relative reference against a
      // different base than the one intended.
      '.evil.example/x',
      // A leading `//` is a protocol-relative (network-path) reference — it
      // names a NEW HOST, never a path on the current one.
      '//evil.example/x',
      // A backslash is accepted as a path separator synonym by the WHATWG
      // URL algorithm for http(s) — `/\evil.example/x` parses to host
      // `evil.example` exactly like `//evil.example/x` does. This is also
      // the one REAL WordPress shape this rejects: `(?P<id>\d+)`, a
      // legitimate PCRE-escape regex route. Losing that one case (it now
      // reads `path_partial: true` instead of a resolved, high-confidence
      // route) is the accepted cost — this module's own header already
      // states the rule this follows: "a false 'partial' costs a consumer
      // one skipped probe; a false 'resolved' costs it a request to a path
      // that never existed — and hides the one that does."
      '/items/(?P<id>\\d+)',
      '/redirect\\evil.example/x',
    ];
    for (const value of HOST_CONFUSION) {
      it(`rejects ${JSON.stringify(value)}`, () => {
        expect(isLiteralPath(value)).toBe(false);
      });
    }
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
    const { routes } = extractSurface(routeFrom('/users/{id}'));
    expect(routes[0]?.path_partial).toBe(false);
    expect(routes[0]?.confidence).toBe('medium');
  });

  // Task 4 brief, item 2: `(?P<id>\d+)`'s backslash is the one real
  // WordPress shape `isLiteralPath`'s host-confusion check costs — see its
  // own doc comment. Pinned here as understood, deliberate behaviour: a
  // route this module cannot verify is safe to resolve as a URL is kept
  // (still evidence of surface) but never marked `path_partial: false`.
  it('flags a regex-group path partial for its own backslash, even with no namespace involved', () => {
    const { routes } = extractSurface(routeFrom('/items/(?P<id>\\d+)'));
    expect(routes[0]?.path_partial).toBe(true);
    expect(routes[0]?.confidence).toBe('low');
    // Still knowable, and still reported — see `looksLikePathSyntax`.
    expect(routes[0]?.params).toEqual(['id']);
  });

  it('still reports params when the path is literal but the namespace is not', () => {
    // register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)') — the
    // dominant WordPress idiom. We cannot say WHERE the route is served, but
    // `id` is knowable from the path alone, and emitting [] would assert
    // "this route takes no parameters", which is untrue.
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
              $ROUTE: { abstract_content: "'/items/(?P<id>\\d+)'" },
            },
          },
        },
      ],
    });
    expect(routes[0]?.params).toEqual(['id']);
    expect(routes[0]?.path_partial).toBe(true);
  });

  it('reports no params for a path that is itself a code expression', () => {
    const { routes } = extractSurface(routeFrom('SETTINGS.users_path'));
    expect(routes[0]?.params).toEqual([]);
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

describe('extractSurface — an annotation with no path of its own', () => {
  /** A bare `@Get()` / `[HttpGet]` / `@GetMapping` match: no metavars at all. */
  function bareMatch(metadata: Record<string, unknown>): unknown {
    return {
      results: [
        {
          check_id: 'guardian-route-nestjs-get-bare',
          path: 'src/users.controller.ts',
          start: { line: 7 },
          extra: {
            metadata: {
              guardian_kind: 'route',
              framework: 'nestjs',
              confidence: 'low',
              method: 'GET',
              ...metadata,
            },
            // No `metavars` key at all — there was nothing to capture.
          },
        },
      ],
    };
  }

  it('drops a path-less route rule that does not declare the flag', () => {
    // The shipped behaviour for three whole annotation families, stated as a
    // test: the rule matched, and the route silently did not exist. Without
    // `guardian_path`, `toRoute` has no path and no way to tell "the rule
    // captures none" from "the capture failed", so dropping it stays correct
    // — which is exactly why the rule pack has to declare the flag, and why
    // rulePack.test.ts holds it in lock-step with the patterns.
    const { routes } = extractSurface(bareMatch({}));
    expect(routes).toEqual([]);
  });

  it('emits an empty own-path, partial and low, when the rule declares it', () => {
    const { routes } = extractSurface(bareMatch({ [INHERITED_PATH_KEY]: INHERITED_PATH }));
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path_raw).toBe('');
    expect(routes[0]?.path_resolved).toBe('');
    // Never presented as a URL: the served path is the class-level prefix and
    // nothing here can resolve it, so a consumer that sends HTTP requests
    // (scan_dast) skips it on `path_partial` like any other unresolved route.
    expect(routes[0]?.path_partial).toBe(true);
    expect(routes[0]?.confidence).toBe('low');
    // The verb still comes from the rule identity, and the endpoint is in the
    // inventory with its file and line — which is the whole point.
    expect(routes[0]?.method).toBe('GET');
    expect(routes[0]?.line).toBe(7);
    expect(routes[0]?.params).toEqual([]);
  });

  it('ignores the flag when the rule did capture a path', () => {
    // A real capture always wins: the flag says "this rule binds no path", so
    // if one arrives the flag is the thing that is wrong, not the capture.
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'guardian-route-x',
          path: 'a.java',
          start: { line: 3 },
          extra: {
            metadata: {
              guardian_kind: 'route',
              framework: 'spring',
              confidence: 'medium',
              [INHERITED_PATH_KEY]: INHERITED_PATH,
            },
            metavars: { $PATH: { abstract_content: '"/list"' } },
          },
        },
      ],
    });
    expect(routes[0]?.path_resolved).toBe('/list');
    expect(routes[0]?.path_partial).toBe(false);
  });

  it('does not treat an unknown guardian_path value as inherited', () => {
    const { routes } = extractSurface(bareMatch({ [INHERITED_PATH_KEY]: 'whatever' }));
    expect(routes).toEqual([]);
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

describe('provenance', () => {
  it('marks every extracted route as coming from code', () => {
    const { routes } = extractSurface(fixture('express.json'));
    expect(routes.every((r) => r.provenance === 'code')).toBe(true);
  });
});
