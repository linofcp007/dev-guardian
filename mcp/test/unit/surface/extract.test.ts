import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RouteRecord } from '../../../src/types.js';
import {
  CLASS_PREFIX_ASPNET,
  CLASS_PREFIX_KEY,
  CLASS_PREFIX_SPRING,
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

/* ---- class-level prefixes ------------------------------------------------
 *
 * The facts as configs/semgrep/routes.yml's `scope` rules report them: a
 * declaration's byte range, or a value bound inside one. The offsets below are
 * synthetic — only containment matters to the join — but the shapes are the
 * ones Semgrep 1.182.0 emitted for the fixtures: a class range from its first
 * annotation to its closing brace, the prefix literal inside it, quotes kept.
 */
const JAVA = 'src/main/java/OrderController.java';
const CS = 'Controllers/OrdersController.cs';

interface Fact {
  role: string;
  start: number;
  end: number;
  value?: string;
  framework?: string;
  file?: string;
}

function scopeMatch(fact: Fact): unknown {
  const focus = fact.role === 'prefix' ? 'path' : fact.role.endsWith('name') ? 'name' : undefined;
  const metavar = fact.role === 'prefix' ? '$PATH' : '$NAME';
  return {
    check_id: `guardian-scope-${fact.role}`,
    path: fact.file ?? JAVA,
    start: { line: 1, offset: fact.start },
    end: { line: 1, offset: fact.end },
    extra: {
      metadata: {
        guardian_kind: 'scope',
        framework: fact.framework ?? 'spring',
        guardian_scope: fact.role,
        ...(focus !== undefined ? { guardian_focus: focus } : {}),
      },
      ...(fact.value !== undefined ? { metavars: { [metavar]: { abstract_content: fact.value } } } : {}),
    },
  };
}

/** A class route at `offset`: `path` is its `$PATH` capture as Semgrep reports it, quotes kept; undefined for a bare one. */
function classRoute(
  path: string | undefined,
  offset: number,
  options: { style?: string; framework?: string; file?: string; confidence?: string } = {},
): unknown {
  const style = options.style ?? CLASS_PREFIX_SPRING;
  return {
    check_id: 'guardian-route-x',
    path: options.file ?? (style === CLASS_PREFIX_ASPNET ? CS : JAVA),
    start: { line: 9, offset },
    end: { line: 9, offset: offset + 1 },
    extra: {
      metadata: {
        guardian_kind: 'route',
        framework: options.framework ?? (style === CLASS_PREFIX_ASPNET ? 'aspnet' : 'spring'),
        confidence: options.confidence ?? (path === undefined ? 'low' : 'medium'),
        method: 'GET',
        [CLASS_PREFIX_KEY]: style,
        ...(path === undefined ? { [INHERITED_PATH_KEY]: INHERITED_PATH } : {}),
      },
      ...(path !== undefined ? { metavars: { $PATH: { abstract_content: path } } } : {}),
    },
  };
}

function served(route: unknown, facts: readonly Fact[]): RouteRecord | undefined {
  const json = { results: [...facts.map(scopeMatch), route] };
  return extractSurface(json).routes[0];
}

/** `@RestController @RequestMapping("/api/orders") class OrderController { … }` */
const SPRING_HANDLER: readonly Fact[] = [
  { role: 'type', start: 0, end: 1000 },
  { role: 'handler', start: 0, end: 1000 },
  { role: 'prefix', start: 20, end: 33, value: '"/api/orders"' },
];

describe('extractSurface — Spring: a handler joins its class-level @RequestMapping', () => {
  it('serves a method mapping at the prefix plus its own path, resolved', () => {
    expect(served(classRoute('"/list"', 100), SPRING_HANDLER)).toMatchObject({
      path_raw: '/list',
      path_resolved: '/api/orders/list',
      path_partial: false,
      confidence: 'medium',
    });
  });

  it("applies Spring's slash rules: a leading one added, a doubled one kept once", () => {
    const withPrefix = (prefix: string, own: string): string | undefined =>
      served(classRoute(own, 100), [
        ...SPRING_HANDLER.slice(0, 2),
        { role: 'prefix', start: 20, end: 33, value: prefix },
      ])?.path_resolved;
    expect(withPrefix('"/api/orders"', '"list"')).toBe('/api/orders/list');
    expect(withPrefix('"api/orders"', '"/list"')).toBe('/api/orders/list');
    expect(withPrefix('"/api/"', '"/list"')).toBe('/api/list');
    expect(withPrefix('"/api/orders"', '""')).toBe('/api/orders');
    expect(withPrefix('""', '"/list"')).toBe('/list');
  });

  it('serves a bare mapping AT the prefix, its own path left empty', () => {
    expect(served(classRoute(undefined, 100), SPRING_HANDLER)).toMatchObject({
      path_raw: '',
      path_resolved: '/api/orders',
      path_partial: false,
    });
  });

  it('carries a parameter of the prefix into params', () => {
    const route = served(classRoute('"/{id}"', 100), [
      ...SPRING_HANDLER.slice(0, 2),
      { role: 'prefix', start: 20, end: 40, value: '"/tenants/{tenant}/orders"' },
    ]);
    expect(route?.path_resolved).toBe('/tenants/{tenant}/orders/{id}');
    expect(route?.params).toEqual(['tenant', 'id']);
  });

  it('resolves a handler with no prefix and no supertype at its own path', () => {
    const facts = SPRING_HANDLER.slice(0, 2);
    expect(served(classRoute('"list"', 100), facts)).toMatchObject({ path_resolved: '/list', path_partial: false });
  });

  it('keeps partial what the facts cannot settle', () => {
    const partial = (route: unknown, facts: readonly Fact[]): unknown => served(route, facts)?.path_partial;
    // No prefix, but a supertype that may carry one — an OpenAPI-generated
    // `implements OrdersApi` puts the type-level mapping on the interface.
    expect(partial(classRoute('"/list"', 100), [...SPRING_HANDLER.slice(0, 2), { role: 'inherits', start: 0, end: 1000 }])).toBe(true);
    // A bare mapping with no prefix at all maps the empty pattern.
    expect(partial(classRoute(undefined, 100), SPRING_HANDLER.slice(0, 2))).toBe(true);
    // Not a handler: an interface's, a base class's or an abstract class's
    // mapping is served under whichever subclass inherits it.
    expect(partial(classRoute('"/list"', 100), [{ role: 'type', start: 0, end: 1000 }, SPRING_HANDLER[2] ?? { role: 'x', start: 0, end: 0 }])).toBe(true);
    // In no type at all.
    expect(partial(classRoute('"/list"', 2000), SPRING_HANDLER)).toBe(true);
    // A prefix that is not one string literal: a constant, a placeholder, an
    // array, a wildcard pattern.
    for (const prefix of ['Paths.ORDERS', '"${api.prefix}/orders"', '{"/a", "/b"}', '"/api/*"']) {
      const facts = [...SPRING_HANDLER.slice(0, 2), { role: 'prefix', start: 20, end: 33, value: prefix }];
      expect(partial(classRoute('"/list"', 100), facts), prefix).toBe(true);
    }
    // A prefix Semgrep reported and recovery could not read: the class HAS
    // one, so leaving it off would be the confidently wrong URL.
    expect(partial(classRoute('"/list"', 100), [...SPRING_HANDLER.slice(0, 2), { role: 'prefix', start: 20, end: 33 }])).toBe(true);
    // An own path that is not one literal names nothing a prefix completes.
    expect(served(classRoute('{"/a", "/b"}', 100), SPRING_HANDLER)).toMatchObject({
      path_resolved: '{"/a", "/b"}',
      path_partial: true,
      confidence: 'low',
    });
    expect(partial(classRoute('Paths.LIST', 100), SPRING_HANDLER)).toBe(true);
  });

  it('gives a nested type its own answer, never its outer class prefix', () => {
    const facts: Fact[] = [
      ...SPRING_HANDLER,
      // `public static class Plain { @GetMapping("/p") … }` — no handler.
      { role: 'type', start: 200, end: 300 },
      // `@RestController @RequestMapping("/inner") static class Inner { … }`
      { role: 'type', start: 400, end: 600 },
      { role: 'handler', start: 400, end: 600 },
      { role: 'prefix', start: 420, end: 428, value: '"/inner"' },
    ];
    expect(served(classRoute('"/p"', 250), facts)?.path_partial).toBe(true);
    expect(served(classRoute('"/i"', 500), facts)?.path_resolved).toBe('/inner/i');
    // And the outer class's own routes keep the outer prefix.
    expect(served(classRoute('"/o"', 700), facts)?.path_resolved).toBe('/api/orders/o');
  });

  it('keeps two classes in one file apart', () => {
    const facts: Fact[] = [
      ...SPRING_HANDLER,
      { role: 'type', start: 1100, end: 1500 },
      { role: 'handler', start: 1100, end: 1500 },
    ];
    expect(served(classRoute('"/second"', 1200), facts)?.path_resolved).toBe('/second');
  });

  it('leaves the whole file partial when a prefix lies in no type it was told about', () => {
    const facts: Fact[] = [...SPRING_HANDLER, { role: 'prefix', start: 5000, end: 5010, value: '"/lost"' }];
    expect(served(classRoute('"/list"', 100), facts)?.path_partial).toBe(true);
  });

  it("reads only its own framework's facts, in its own file", () => {
    const aspnetFacts = SPRING_HANDLER.map((f) => ({ ...f, framework: 'aspnet' }));
    expect(served(classRoute('"/list"', 100), aspnetFacts)?.path_partial).toBe(true);
    const otherFile = SPRING_HANDLER.map((f) => ({ ...f, file: 'src/Other.java' }));
    expect(served(classRoute('"/list"', 100), otherFile)?.path_partial).toBe(true);
  });

  it('keeps a route partial under a guardian_class_prefix value it does not know', () => {
    expect(served(classRoute('"/list"', 100, { style: 'always' }), SPRING_HANDLER)?.path_partial).toBe(true);
  });

  it('without the key, a literal path is resolved as before', () => {
    const { routes } = extractSurface({
      results: [
        {
          check_id: 'guardian-route-x',
          path: JAVA,
          start: { line: 9, offset: 100 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'spring', confidence: 'medium', method: 'GET' },
            metavars: { $PATH: { abstract_content: '"/list"' } },
          },
        },
      ],
    });
    expect(routes[0]?.path_partial).toBe(false);
  });

  it('never reports a scope fact as a route or a mount', () => {
    expect(extractSurface({ results: SPRING_HANDLER.map(scopeMatch) })).toEqual({ routes: [], mounts: [] });
  });
});

/** `[ApiController] [Route("api/[controller]")] public class OrdersController : ControllerBase { … }` */
const CONTROLLER: readonly Fact[] = [
  { role: 'type', start: 0, end: 1000, framework: 'aspnet', file: CS },
  { role: 'prefix', start: 20, end: 38, value: '"api/[controller]"', framework: 'aspnet', file: CS },
  { role: 'class-name', start: 50, end: 66, value: 'OrdersController', framework: 'aspnet', file: CS },
];

/** An action's range [`start`, `end`) and its name, as the two ASP.NET method rules report them. */
function action(start: number, end: number, name: string, nameAt = start + 30): Fact[] {
  return [
    { role: 'method', start, end, framework: 'aspnet', file: CS },
    { role: 'method-name', start: nameAt, end: nameAt + name.length, value: name, framework: 'aspnet', file: CS },
  ];
}

const aspnet = (path: string | undefined, offset: number): unknown => classRoute(path, offset, { style: CLASS_PREFIX_ASPNET });

describe("extractSurface — ASP.NET: a controller joins its own [Route]", () => {
  it('replaces [controller] with the class name less its Controller suffix, case kept', () => {
    expect(served(aspnet('"{id}"', 100), CONTROLLER)).toMatchObject({
      path_raw: '{id}',
      path_resolved: '/api/Orders/{id}',
      path_partial: false,
      params: ['id'],
    });
    const named = (name: string): string | undefined =>
      served(aspnet('"all"', 100), [...CONTROLLER.slice(0, 2), { ...CONTROLLER[2], role: 'class-name', start: 50, end: 60, value: name }])?.path_resolved;
    expect(named('Orders')).toBe('/api/Orders/all');
    expect(named('Reportcontroller')).toBe('/api/Report/all');
  });

  it('serves a bare attribute AT the class route, and cleans the slashes CombineTemplates does', () => {
    expect(served(aspnet(undefined, 100), CONTROLLER)?.path_resolved).toBe('/api/Orders');
    expect(served(aspnet('"list/"', 100), CONTROLLER)?.path_resolved).toBe('/api/Orders/list');
    expect(served(aspnet('""', 100), CONTROLLER)?.path_resolved).toBe('/api/Orders');
  });

  it('lets a rooted method path ignore the class route, with or without any fact in the file', () => {
    expect(served(aspnet('"/aspnet/orders"', 100), CONTROLLER)?.path_resolved).toBe('/aspnet/orders');
    expect(served(aspnet('"~/legacy/orders"', 100), CONTROLLER)).toMatchObject({
      path_raw: '~/legacy/orders',
      path_resolved: '/legacy/orders',
      path_partial: false,
    });
    expect(served(aspnet('"/aspnet/orders"', 100), [])?.path_partial).toBe(false);
    // A rooted template still replaces its tokens.
    expect(served(aspnet('"/v2/[controller]"', 100), CONTROLLER)?.path_resolved).toBe('/v2/Orders');
    expect(served(aspnet('"/v2/[controller]"', 100), [])?.path_partial).toBe(true);
  });

  it('replaces [action] with the method name less an Async suffix', () => {
    const facts = [...CONTROLLER, ...action(80, 300, 'ListAsync')];
    expect(served(aspnet('"[action]"', 90), facts)?.path_resolved).toBe('/api/Orders/List');
    // A local function inside the action is a method of its own: its name
    // belongs to its own range, never to the action around it.
    const withLocal = [...CONTROLLER, ...action(80, 300, 'Index', 100), ...action(200, 250, 'Local', 210)];
    expect(served(aspnet('"[action]"', 90), withLocal)?.path_resolved).toBe('/api/Orders/Index');
  });

  it('keeps partial what the facts cannot settle', () => {
    const partial = (route: unknown, facts: readonly Fact[]): unknown => served(route, facts)?.path_partial;
    // No [Route] of its own: a base class may declare the one MVC uses.
    expect(partial(aspnet('"all"', 100), [CONTROLLER[0] ?? { role: 'x', start: 0, end: 0 }])).toBe(true);
    // Two [Route]s: every action is served twice.
    const twice = [...CONTROLLER, { role: 'prefix', start: 40, end: 48, value: '"api/v2"', framework: 'aspnet', file: CS }];
    expect(partial(aspnet('"all"', 100), twice)).toBe(true);
    // A prefix that is not one string literal.
    for (const prefix of ['Routes.Orders', '@"api/orders"']) {
      const facts = [CONTROLLER[0], { ...CONTROLLER[1], role: 'prefix', start: 20, end: 38, value: prefix }].filter(
        (f): f is Fact => f !== undefined,
      );
      expect(partial(aspnet('"all"', 100), facts), prefix).toBe(true);
    }
    // No class name read — an abstract class, `[ControllerName]` — for a
    // template that needs one.
    expect(partial(aspnet('"all"', 100), CONTROLLER.slice(0, 2))).toBe(true);
    // [area], an unknown token, an escape.
    for (const prefix of ['"[area]/[controller]"', '"api/[version]"', '"api/[[controller]]"']) {
      const facts = [CONTROLLER[0], CONTROLLER[2], { role: 'prefix', start: 20, end: 38, value: prefix, framework: 'aspnet', file: CS }].filter(
        (f): f is Fact => f !== undefined,
      );
      expect(partial(aspnet('"all"', 100), facts), prefix).toBe(true);
    }
    // [action] on a method with no range — `[ActionName]` excludes it — or
    // with no name inside its range.
    expect(partial(aspnet('"[action]"', 90), CONTROLLER)).toBe(true);
    expect(partial(aspnet('"[action]"', 90), [...CONTROLLER, { role: 'method', start: 80, end: 300, framework: 'aspnet', file: CS }])).toBe(true);
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
