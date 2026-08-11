/**
 * Every span in this file was captured from a real Semgrep run against a
 * multi-language fixture (1.86.0 for the metavariable ground truth, 1.164.0
 * for the redacted byte offsets that make recovery necessary). They are
 * observations, not invented shapes.
 */
import { describe, expect, it } from 'vitest';
import { extractSurface } from '../../../src/surface/extract.js';
import { recoverMetavars, type RecoveryOutcome } from '../../../src/surface/recoverMetavars.js';

const FILE = 'src/app.ts';

interface RedactedResult {
  check_id: string;
  path: string;
  start: { line: number; col: number; offset: number };
  end: { line: number; col: number; offset: number };
  extra: { metadata: Record<string, unknown>; severity: string };
}

/**
 * Build the exact shape modern Semgrep emits for a redacted match: position
 * intact, `extra.metavars` absent. Offsets are BYTE offsets, so they are
 * computed against the encoded buffer — the same way Semgrep computes them.
 */
function scenario(
  source: string,
  span: string,
  metadata: Record<string, unknown>,
  file = FILE,
): { json: { results: RedactedResult[] }; sources: Map<string, string> } {
  const buf = Buffer.from(source, 'utf8');
  const start = buf.indexOf(Buffer.from(span, 'utf8'));
  if (start < 0) throw new Error(`test span not present in source: ${span}`);
  return {
    json: {
      results: [
        {
          check_id: 'guardian-test',
          path: file,
          start: { line: 1, col: 1, offset: start },
          end: { line: 1, col: 1, offset: start + Buffer.byteLength(span, 'utf8') },
          extra: { metadata, severity: 'INFO' },
        },
      ],
    },
    sources: new Map([[file, source]]),
  };
}

/** Read a synthesized capture back out of the returned JSON. */
function mv(outcome: RecoveryOutcome, name: string): string | undefined {
  const results = (
    outcome.json as {
      results?: { extra?: { metavars?: Record<string, { abstract_content?: string }> } }[];
    }
  ).results;
  return results?.[0]?.extra?.metavars?.[name]?.abstract_content;
}

function recoverSpan(
  span: string,
  metadata: Record<string, unknown>,
  source = span,
): RecoveryOutcome {
  const { json, sources } = scenario(source, span, metadata);
  return recoverMetavars(json, sources);
}

const ROUTE = { guardian_kind: 'route' };

describe('recoverMetavars — $PATH from the first string literal', () => {
  // The captured spans, one per framework. Quoting is asserted verbatim
  // because it is what `isLiteralPath` in extract.ts keys off.
  const cases: [name: string, span: string, expected: string][] = [
    ['express', "app.get('/health', (req, res) => res.send('ok'))", "'/health'"],
    ['flask', "@app.route('/flask-route')", "'/flask-route'"],
    ['go net/http', 'http.HandleFunc("/go-route", handler)', '"/go-route"'],
    ['spring', '@GetMapping("/spring-route")', '"/spring-route"'],
    ['rust actix', '#[get("/rust-route")]', '"/rust-route"'],
    ['laravel', "Route::get('/laravel-route', 'Controller@index')", "'/laravel-route'"],
    ['gin', 'r.GET("/gin-route", nil)', '"/gin-route"'],
    ['aspnet minimal', 'app.MapGet("/dotnet-route", () => "ok")', '"/dotnet-route"'],
    ['rails', "get '/ruby-route', to: 'users#index'", "'/ruby-route'"],
    ['django', "path('django-route/', flask_route)", "'django-route/'"],
  ];

  for (const [name, span, expected] of cases) {
    it(`recovers ${name}`, () => {
      const outcome = recoverSpan(span, ROUTE);
      expect(mv(outcome, '$PATH')).toBe(expected);
      expect(outcome.recovered).toBe(1);
      expect(outcome.unrecoverable).toBe(0);
    });
  }

  it('reads the path out of a multi-line span (Rust attribute + fn body)', () => {
    // Semgrep reports the whole item for `#[get($PATH)]`, not just the
    // attribute — the span really does span two lines, and the body contains
    // another string literal that must NOT be mistaken for the path.
    const span = '#[get("/rust-route")]\nasync fn hello() -> String { "ok".to_string() }';
    expect(mv(recoverSpan(span, ROUTE), '$PATH')).toBe('"/rust-route"');
  });

  it('invents nothing for a call with an empty argument list', () => {
    // A real over-match from the Rust rules as they were before validation:
    // Semgrep reported `"ok".to_string()` as a route span. Semgrep 1.86.0
    // binds `metavars: {}` there — it captured nothing — so taking the
    // receiver string would fabricate a route named `ok` that no ground-truth
    // run ever produced. The rule no longer emits such spans, but the guard
    // stays: a user rule registered through register_custom_rules can.
    const outcome = recoverSpan('"ok".to_string()', ROUTE);
    expect(mv(outcome, '$PATH')).toBeUndefined();
    expect(outcome.unrecoverable).toBe(1);
    expect(extractSurface(outcome.json).routes).toHaveLength(0);
  });
});

describe('recoverMetavars — $METHOD from the callee', () => {
  const cases: [span: string, expected: string][] = [
    ["app.get('/health', h)", 'get'],
    ["Route::get('/laravel-route', h)", 'get'],
    ['r.GET("/gin-route", nil)', 'GET'],
    ['app.MapGet("/dotnet-route", h)', 'MapGet'],
    ["@app.get('/fastapi-ish')", 'get'],
    // Ruby's bare form has no parentheses at all; the verb is the leading word.
    ["get '/ruby-route', to: 'users#index'", 'get'],
  ];

  for (const [span, expected] of cases) {
    it(`reads ${expected} from ${span}`, () => {
      expect(mv(recoverSpan(span, ROUTE), '$METHOD')).toBe(expected);
    });
  }

  it('emits no $METHOD when the rule already declares metadata.method', () => {
    // `@GetMapping(` would yield the callee `GetMapping`, which normalizeMethod
    // cannot read as a verb — it would return ANY and *override* the correct
    // metadata.method the rule carries. Emitting nothing is what keeps GET.
    const outcome = recoverSpan('@GetMapping("/spring-route")', {
      guardian_kind: 'route',
      framework: 'spring',
      method: 'GET',
    });
    expect(mv(outcome, '$METHOD')).toBeUndefined();
    expect(extractSurface(outcome.json).routes[0]?.method).toBe('GET');
  });

  it('lets normalizeMethod turn a recovered MapGet into GET end to end', () => {
    const outcome = recoverSpan('app.MapGet("/dotnet-route", h)', {
      guardian_kind: 'route',
      framework: 'aspnet-minimal',
    });
    expect(extractSurface(outcome.json).routes[0]?.method).toBe('GET');
  });

  it('reads the verb out of a Rust attribute span, where it is the callee', () => {
    // The actix rule binds the attribute name to $METHOD and declares no
    // metadata.method, so on a redacting Semgrep the verb exists only if the
    // recovery finds it — and the `(` it must anchor on is inside `#[patch(`,
    // not at the start of the span. A second attribute follows the first.
    const span =
      '#[patch("/rust/items/{id}/status")]\n#[allow(clippy::unused_async)]\n' +
      'async fn patch_item(path: web::Path<u32>) -> impl Responder { HttpResponse::Ok().finish() }';
    const outcome = recoverSpan(span, { guardian_kind: 'route', framework: 'actix' });
    expect(mv(outcome, '$METHOD')).toBe('patch');
    const route = extractSurface(outcome.json).routes[0];
    expect(route?.method).toBe('PATCH');
    expect(route?.path_resolved).toBe('/rust/items/{id}/status');
    expect(route?.path_partial).toBe(false);
  });
});

/**
 * Three rule families match the attribute PLUS the declaration it decorates,
 * so Semgrep's span starts at the first attribute on that declaration — not
 * necessarily the route one. Every span below was captured from Semgrep
 * 1.164.0; every expected value is what Semgrep 1.86.0 binds for the same
 * match. Before the attribute anchor these produced a *fabricated* route from
 * the wrong attribute's argument, and five of them were emitted as resolved
 * paths a DAST tool would request.
 */
describe('recoverMetavars — attribute routes with a PRECEDING decorator', () => {
  const ACTIX = { guardian_kind: 'route', framework: 'actix', confidence: 'medium' };
  const NEST_GET = { guardian_kind: 'route', framework: 'nestjs', method: 'GET' };
  const ASPNET_GET = { guardian_kind: 'route', framework: 'aspnet', method: 'GET' };

  const cases: [name: string, span: string, metadata: Record<string, unknown>, path: string][] = [
    [
      'rust #[allow(dead_code)]',
      '#[allow(dead_code)]\n#[get("/real/d")]\nasync fn d() -> String { String::new() }',
      ACTIX,
      '"/real/d"',
    ],
    [
      'rust #[instrument(skip_all)]',
      '#[instrument(skip_all)]\n#[get("/real/health")]\nasync fn health() -> String { String::new() }',
      ACTIX,
      '"/real/health"',
    ],
    [
      'rust #[cfg(test)]',
      '#[cfg(test)]\n#[get("/real/items")]\nasync fn items() -> String { String::new() }',
      ACTIX,
      '"/real/items"',
    ],
    [
      'rust #[cfg(feature = "api")]',
      '#[cfg(feature = "api")]\n#[get("/real/r3")]\nasync fn r3() -> String { String::new() }',
      ACTIX,
      '"/real/r3"',
    ],
    [
      // Semgrep reports the C# attribute from *inside* the bracket list, so a
      // span that starts at the route attribute has no leading `[`.
      'aspnet [Produces("application/json")]',
      'Produces("application/json")]\n    [HttpGet("/real/orders")]\n    public IActionResult List() => Ok();',
      ASPNET_GET,
      '"/real/orders"',
    ],
    [
      'aspnet [ProducesResponseType(...)]',
      'ProducesResponseType(StatusCodes.Status200OK)]\n    [HttpGet("/c1")]\n    public IActionResult C1() => Ok();',
      ASPNET_GET,
      '"/c1"',
    ],
    [
      'aspnet attributes sharing one bracket list',
      'Produces("application/json"), HttpGet("/shared")]\n    public IActionResult S() => Ok();',
      ASPNET_GET,
      '"/shared"',
    ],
    [
      "nestjs @Roles('admin')",
      "@Roles('admin')\n  @Get('/real/users')\n  findAll(): string[] { return []; }",
      NEST_GET,
      "'/real/users'",
    ],
    [
      'nestjs @ApiOperation({ summary })',
      "@ApiOperation({ summary: 'list' })\n  @Get('/n1')\n  n1(): string[] { return []; }",
      NEST_GET,
      "'/n1'",
    ],
  ];

  for (const [name, span, metadata, expected] of cases) {
    it(`anchors on the route attribute, not the first one — ${name}`, () => {
      const outcome = recoverSpan(span, metadata);
      expect(mv(outcome, '$PATH')).toBe(expected);
      expect(outcome.recovered).toBe(1);
    });
  }

  it('still recovers when the route attribute comes first', () => {
    expect(
      mv(
        recoverSpan(
          '#[get("/plain/ok")]\n#[allow(clippy::unused_async)]\nasync fn p() -> String { String::new() }',
          ACTIX,
        ),
        '$PATH',
      ),
    ).toBe('"/plain/ok"');
    expect(
      mv(
        recoverSpan(
          'HttpGet("/plain/ok")]\n    [Authorize]\n    public IActionResult P() => Ok();',
          ASPNET_GET,
        ),
        '$PATH',
      ),
    ).toBe('"/plain/ok"');
  });

  it('binds the Rust attribute name to $METHOD, as Semgrep does', () => {
    const outcome = recoverSpan(
      '#[cfg(test)]\n#[delete("/rust/items/{id}")]\nasync fn d() -> String { String::new() }',
      ACTIX,
    );
    expect(mv(outcome, '$METHOD')).toBe('delete');
    expect(extractSurface(outcome.json).routes[0]?.method).toBe('DELETE');
  });

  it('recovers NOTHING when the named route attribute is absent from the span', () => {
    // Never fall back to "the first argument list": that is exactly how a
    // decorator's argument became a resolved route path.
    const outcome = recoverSpan(
      "@Roles('admin')\n  somethingElse(): void {}",
      NEST_GET,
    );
    expect(mv(outcome, '$PATH')).toBeUndefined();
    expect(outcome.unrecoverable).toBe(1);
    expect(extractSurface(outcome.json).routes).toHaveLength(0);
  });

  it('does not read a route attribute out of a string literal', () => {
    const outcome = recoverSpan(
      '#[doc = "use #[get(\\"/fake\\")] here"]\n#[get("/real")]\nasync fn r() -> String { String::new() }',
      ACTIX,
    );
    expect(mv(outcome, '$PATH')).toBe('"/real"');
  });

  it('does not match an identifier merely ending in the attribute name', () => {
    const outcome = recoverSpan(
      'MyHttpGet("/decoy")]\n    public IActionResult X() => Ok();',
      ASPNET_GET,
    );
    expect(outcome.unrecoverable).toBe(1);
  });

  /**
   * An apostrophe is a string delimiter in JS/PHP/Python, a lifetime in Rust,
   * and an English contraction in every comment ever written. An earlier
   * version of the anchor search scanned the span forward treating every `'` as
   * a string opener; an odd number of them before the route attribute made it
   * jump straight over it. Every span below is real Semgrep 1.164.0 output, and
   * every expectation is Semgrep 1.86.0's own capture for the same match.
   */
  describe('apostrophes in comments and Rust lifetimes', () => {
    it('recovers past a doc comment containing an apostrophe (route was LOST)', () => {
      const outcome = recoverSpan(
        '#[allow(dead_code)]\n/// Don\'t call this directly; use the router.\n' +
          '#[get("/t1/real")]\nasync fn t1(name: &\'static str) -> impl Responder { ok(name) }',
        ACTIX,
      );
      expect(mv(outcome, '$PATH')).toBe('"/t1/real"');
      expect(outcome.unrecoverable).toBe(0);
    });

    it('is not confused by a lifetime in the signature', () => {
      expect(
        mv(
          recoverSpan(
            '#[get("/t2/real")]\nasync fn t2(name: &\'static str) -> impl Responder { ok(name) }',
            ACTIX,
          ),
          '$PATH',
        ),
      ).toBe('"/t2/real"');
    });

    it('recovers past an apostrophe between C# attributes (route was FABRICATED)', () => {
      // The parity used to close the phantom string inside the body, landing
      // the scanner on `[HttpGet("…FABRICATED…")]` written in a string there.
      const outcome = recoverSpan(
        'Produces("application/json")]\n    // Don\'t expose this without the guard.\n' +
          '    [HttpGet("/q1/real")]\n' +
          '    public IActionResult Q1() => Ok("it\'s [HttpGet(\\"/q1/FABRICATED\\")]");',
        ASPNET_GET,
      );
      expect(mv(outcome, '$PATH')).toBe('"/q1/real"');
    });

    it('recovers past an apostrophe between NestJS decorators (route was FABRICATED)', () => {
      const outcome = recoverSpan(
        "@UseGuards(AuthGuard)\n  // Don't expose this without the guard.\n" +
          "  @Get('/n1/real')\n  n1(): string { return \"it's @Get('/n1/FABRICATED')\"; }",
        NEST_GET,
      );
      expect(mv(outcome, '$PATH')).toBe("'/n1/real'");
      expect(extractSurface(outcome.json).routes[0]?.path_resolved).toBe('/n1/real');
    });

    it('prefers the real attribute over anchor-shaped text in the body', () => {
      const outcome = recoverSpan(
        '#[get("/s1/real")]\nasync fn s1() -> impl Responder { body("get(\\"/s1/FABRICATED\\")") }',
        ACTIX,
      );
      expect(mv(outcome, '$PATH')).toBe('"/s1/real"');
    });
  });

  it('never throws on a metadata.method that is not a plain verb', () => {
    // `metadata.method` comes from a YAML file a user can edit. It used to be
    // interpolated into `new RegExp`, so this threw a SyntaxError out of a
    // module whose contract is that it never throws — and out of an unguarded
    // call site in mapAttackSurface.ts.
    for (const method of ['a(', 'Get|Post', '[', '\\', '(?<', '']) {
      const run = (): RecoveryOutcome =>
        recoverSpan('HttpGet("/x")]\n public IActionResult X() => Ok();', {
          guardian_kind: 'route',
          framework: 'aspnet',
          method,
        });
      expect(run).not.toThrow();
      // Rejected rather than guessed: no anchor name, so nothing is recovered.
      expect(run().unrecoverable).toBe(1);
    }
  });
});

describe('recoverMetavars — paths that are code, not literals', () => {
  it('synthesizes $PATH unquoted from the first argument when there is no literal', () => {
    const outcome = recoverSpan('path(settings.ADMIN_URL, flask_route)', {
      guardian_kind: 'route',
      framework: 'django',
    });
    expect(mv(outcome, '$PATH')).toBe('settings.ADMIN_URL');
    expect(outcome.recovered).toBe(1);
  });

  it('keeps such a route but flags it path_partial — dropping it would erase surface', () => {
    const outcome = recoverSpan('@PostMapping(Paths.ORDERS)', {
      guardian_kind: 'route',
      framework: 'spring',
      method: 'POST',
    });
    const route = extractSurface(outcome.json).routes[0];
    expect(route).toBeDefined();
    expect(route?.path_raw).toBe('Paths.ORDERS');
    expect(route?.path_partial).toBe(true);
    expect(route?.confidence).toBe('low');
  });

  it('a recovered literal path is NOT flagged partial', () => {
    const outcome = recoverSpan("app.get('/health', h)", {
      guardian_kind: 'route',
      framework: 'express',
      confidence: 'high',
    });
    const route = extractSurface(outcome.json).routes[0];
    expect(route?.path_resolved).toBe('/health');
    expect(route?.path_partial).toBe(false);
    expect(route?.confidence).toBe('high');
  });
});

describe('recoverMetavars — wp-rest $NS + $ROUTE', () => {
  const WP = { guardian_kind: 'route', framework: 'wp-rest', confidence: 'medium' };

  it('splits a literal namespace and route, quotes preserved', () => {
    const outcome = recoverSpan(
      "register_rest_route('myplugin/v1', '/items', array('methods' => 'GET'))",
      WP,
    );
    expect(mv(outcome, '$NS')).toBe("'myplugin/v1'");
    expect(mv(outcome, '$ROUTE')).toBe("'/items'");
  });

  it('keeps a computed namespace unquoted so the route survives as path_partial', () => {
    // The dominant idiom in real WordPress plugins. Quoting `self::NAMESPACE`
    // would make isLiteralPath accept it and fabricate /wp-json/self::NAMESPACE/…
    const outcome = recoverSpan(
      "register_rest_route(self::NAMESPACE, '/computed', array('methods' => 'GET'))",
      WP,
    );
    expect(mv(outcome, '$NS')).toBe('self::NAMESPACE');
    expect(mv(outcome, '$ROUTE')).toBe("'/computed'");

    const route = extractSurface(outcome.json).routes[0];
    expect(route).toBeDefined();
    expect(route?.namespace).toBe('self::NAMESPACE');
    expect(route?.path_partial).toBe(true);
  });

  it('does not split on a comma nested inside the third argument', () => {
    const outcome = recoverSpan(
      "register_rest_route('ns/v1', '/items', array('methods' => 'GET', 'callback' => 'cb'))",
      WP,
    );
    expect(mv(outcome, '$ROUTE')).toBe("'/items'");
  });

  it('does not split on a comma inside a quoted string', () => {
    const outcome = recoverSpan("register_rest_route('ns,v1', '/items', array())", WP);
    expect(mv(outcome, '$NS')).toBe("'ns,v1'");
    expect(mv(outcome, '$ROUTE')).toBe("'/items'");
  });
});

describe('recoverMetavars — mount, import and env', () => {
  it('recovers $PREFIX and $ROUTER from an express mount', () => {
    const outcome = recoverSpan("app.use('/api', usersRouter)", { guardian_kind: 'mount' });
    expect(mv(outcome, '$PREFIX')).toBe("'/api'");
    expect(mv(outcome, '$ROUTER')).toBe('usersRouter');
    expect(extractSurface(outcome.json).mounts[0]).toMatchObject({
      prefix: '/api',
      router_var: 'usersRouter',
    });
  });

  it('recovers an ESM import with $MODULE unquoted, as the real run reports it', () => {
    // resolveModuleFile tests `specifier.startsWith('.')`, so a stray quote
    // would silently disable mount resolution.
    const outcome = recoverSpan("import usersRouter from './routes/users'", {
      guardian_kind: 'import',
      framework: 'esm',
    });
    expect(mv(outcome, '$SYMBOL')).toBe('usersRouter');
    expect(mv(outcome, '$MODULE')).toBe('./routes/users');
  });

  it('recovers a CommonJS require', () => {
    const outcome = recoverSpan("const usersRouter = require('./routes/users')", {
      guardian_kind: 'import',
      framework: 'esm',
    });
    expect(mv(outcome, '$SYMBOL')).toBe('usersRouter');
    expect(mv(outcome, '$MODULE')).toBe('./routes/users');
  });

  const envCases: [span: string, expected: string][] = [
    ['process.env.API_KEY', 'API_KEY'],
    ["process.env['DB_URL']", "'DB_URL'"],
    ["os.environ['DATABASE_URL']", "'DATABASE_URL'"],
    ["os.getenv('TOKEN', '')", "'TOKEN'"],
    ["getenv('SECRET_KEY')", "'SECRET_KEY'"],
    ['Environment.GetEnvironmentVariable("DOTNET_KEY")', '"DOTNET_KEY"'],
  ];

  for (const [span, expected] of envCases) {
    it(`recovers $NAME from ${span}`, () => {
      expect(mv(recoverSpan(span, { guardian_kind: 'env' }), '$NAME')).toBe(expected);
    });
  }
});

describe('recoverMetavars — counting and degradation', () => {
  it('leaves a match that already has metavars untouched and counts it intact', () => {
    const json = {
      results: [
        {
          check_id: 'guardian-route-express',
          path: FILE,
          start: { line: 1, col: 1, offset: 0 },
          end: { line: 1, col: 1, offset: 10 },
          extra: {
            metadata: { guardian_kind: 'route', framework: 'express' },
            metavars: { $PATH: { abstract_content: "'/real'" } },
          },
        },
      ],
    };
    // A source that would recover something *different*, proving we did not
    // overwrite: real metavars are more precise than anything we reconstruct.
    const outcome = recoverMetavars(json, new Map([[FILE, "app.get('/other', h)"]]));
    expect(outcome.intact).toBe(1);
    expect(outcome.recovered).toBe(0);
    expect(mv(outcome, '$PATH')).toBe("'/real'");
  });

  it('treats an empty metavars object as missing and recovers into it', () => {
    const source = "app.get('/health', h)";
    const json = {
      results: [
        {
          check_id: 'guardian-route-express',
          path: FILE,
          start: { line: 1, col: 1, offset: 0 },
          end: { line: 1, col: 1, offset: Buffer.byteLength(source, 'utf8') },
          extra: { metadata: { guardian_kind: 'route' }, metavars: {} },
        },
      ],
    };
    const outcome = recoverMetavars(json, new Map([[FILE, source]]));
    expect(outcome.recovered).toBe(1);
    expect(mv(outcome, '$PATH')).toBe("'/health'");
  });

  it('counts a file missing from the map as unrecoverable without throwing', () => {
    const { json } = scenario("app.get('/health', h)", "app.get('/health', h)", ROUTE);
    const outcome = recoverMetavars(json, new Map());
    expect(outcome.unrecoverable).toBe(1);
    expect(outcome.recovered).toBe(0);
    expect(mv(outcome, '$PATH')).toBeUndefined();
  });

  it('counts an offset past end-of-file as unrecoverable without throwing', () => {
    const source = "app.get('/health', h)";
    const json = {
      results: [
        {
          check_id: 'x',
          path: FILE,
          start: { line: 1, col: 1, offset: 0 },
          end: { line: 1, col: 1, offset: 99_999 },
          extra: { metadata: ROUTE },
        },
      ],
    };
    const outcome = recoverMetavars(json, new Map([[FILE, source]]));
    expect(outcome.unrecoverable).toBe(1);
  });

  it('degrades rather than hangs on an unterminated string literal', () => {
    // `skipString` runs to end-of-span when a quote never closes. That exit was
    // an uncovered statement while it was also the mechanism behind a route
    // -fabrication defect, so it is pinned here. A truncated span is not
    // hypothetical: `end.offset` can land mid-literal if the file changed.
    const outcome = recoverSpan("app.use('/api", { guardian_kind: 'mount' });
    expect(outcome.unrecoverable).toBe(1);
    expect(recoverSpan("app.get('/oops", ROUTE).recovered + outcome.recovered).toBe(0);
  });

  it('never throws on malformed input', () => {
    expect(() => recoverMetavars(null, new Map())).not.toThrow();
    expect(() => recoverMetavars({ results: 'nope' }, new Map())).not.toThrow();
    expect(() => recoverMetavars({ results: [{ nonsense: true }] }, new Map())).not.toThrow();
    expect(recoverMetavars(null, new Map())).toMatchObject({
      intact: 0,
      recovered: 0,
      unrecoverable: 0,
    });
  });

  it('ignores matches with no guardian_kind rather than calling them unrecoverable', () => {
    // extract.ts skips these entirely, so counting them would fabricate a
    // "broken toolchain" signal out of a rule pack that simply has other rules.
    const json = {
      results: [
        {
          check_id: 'someone-elses-rule',
          path: FILE,
          start: { line: 1, col: 1, offset: 0 },
          end: { line: 1, col: 1, offset: 5 },
          extra: { metadata: { category: 'security' } },
        },
      ],
    };
    const outcome = recoverMetavars(json, new Map([[FILE, 'hello world']]));
    expect(outcome).toMatchObject({ intact: 0, recovered: 0, unrecoverable: 0 });
  });

  it('does not mutate the input JSON', () => {
    const { json, sources } = scenario("app.get('/health', h)", "app.get('/health', h)", ROUTE);
    recoverMetavars(json, sources);
    expect(json.results[0]?.extra).not.toHaveProperty('metavars');
  });

  it('counts several results independently', () => {
    const source = "app.get('/health', h)\napp.use('/api', usersRouter)";
    const buf = Buffer.from(source, 'utf8');
    const one = "app.get('/health', h)";
    const two = "app.use('/api', usersRouter)";
    const json = {
      results: [
        {
          check_id: 'a', path: FILE,
          start: { line: 1, col: 1, offset: buf.indexOf(one) },
          end: { line: 1, col: 1, offset: buf.indexOf(one) + one.length },
          extra: { metadata: { guardian_kind: 'route' } },
        },
        {
          check_id: 'b', path: FILE,
          start: { line: 2, col: 1, offset: buf.indexOf(two) },
          end: { line: 2, col: 1, offset: buf.indexOf(two) + two.length },
          extra: { metadata: { guardian_kind: 'mount' } },
        },
        {
          check_id: 'c', path: 'missing.ts',
          start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 1, offset: 4 },
          extra: { metadata: { guardian_kind: 'env' } },
        },
      ],
    };
    const outcome = recoverMetavars(json, new Map([[FILE, source]]));
    expect(outcome).toMatchObject({ intact: 0, recovered: 2, unrecoverable: 1 });
  });
});

describe('recoverMetavars — byte offsets are not string indices', () => {
  it('slices by byte when a non-ASCII comment precedes the match', () => {
    // 10 × U+2615 (3 bytes each) plus two 2-byte letters put the byte offset
    // 22 code units ahead of the UTF-16 index. A naive `text.slice(start, end)`
    // starts 22 characters into the call and reports `'ok'` as the path.
    const source = "// ☕☕☕☕☕☕☕☕☕☕ configuração\napp.get('/health', (req, res) => res.send('ok'));";
    const span = "app.get('/health', (req, res) => res.send('ok'))";
    const outcome = recoverSpan(span, ROUTE, source);

    expect(mv(outcome, '$PATH')).toBe("'/health'");
    expect(mv(outcome, '$PATH')).not.toBe("'ok'");

    // Guard the guard: assert the two index spaces really do diverge here, so
    // this test cannot quietly stop testing anything.
    const buf = Buffer.from(source, 'utf8');
    expect(buf.indexOf(Buffer.from(span, 'utf8'))).not.toBe(source.indexOf(span));
  });

  it('recovers correctly when the non-ASCII text is inside the span itself', () => {
    const span = "app.get('/café', h)";
    expect(mv(recoverSpan(span, ROUTE), '$PATH')).toBe("'/café'");
  });
});
