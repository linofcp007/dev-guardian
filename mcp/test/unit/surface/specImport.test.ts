import { describe, expect, it } from 'vitest';
import { importSpec } from '../../../src/surface/specImport.js';

const OPENAPI = `
openapi: "3.0.3"
servers:
  - url: https://api.example.com/v1
security:
  - bearer: []
paths:
  /users:
    get:
      summary: list
    post:
      security: []
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
`;

describe('importSpec — OpenAPI 3', () => {
  it('imports one route per operation, with the server base path applied', () => {
    const { routes, report } = importSpec('openapi.yaml', OPENAPI);
    expect(report.format).toBe('openapi-3');
    expect(report.status).toBe('ok');
    expect(report.routes_found).toBe(3);
    expect(routes.map((r) => `${r.method} ${r.path_resolved}`).sort()).toEqual([
      'GET /v1/users',
      'GET /v1/users/{id}',
      'POST /v1/users',
    ]);
  });

  it('marks every route as coming from a spec, at high confidence', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.every((r) => r.provenance === 'spec')).toBe(true);
    expect(routes.every((r) => r.confidence === 'high')).toBe(true);
    expect(routes.every((r) => r.language === 'spec')).toBe(true);
    expect(routes.every((r) => r.framework === 'openapi-3')).toBe(true);
  });

  it('reads security: [] as an affirmative declaration that the route is public', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    const post = routes.find((r) => r.method === 'POST');
    expect(post?.auth_hint).toBe('none');
  });

  it('inherits document-level security as required', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.find((r) => r.path_raw === '/users' && r.method === 'GET')?.auth_hint)
      .toBe('required');
  });

  it('leaves auth unknown when neither the operation nor the document declares any', () => {
    const { routes } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths:\n  /x:\n    get: {}\n');
    expect(routes[0]?.auth_hint).toBe('unknown');
  });

  it('extracts path parameters from the template', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.find((r) => r.path_raw === '/users/{id}')?.params).toEqual(['id']);
  });

  it('resolves an internal $ref parameter to its name and location', () => {
    const text = [
      'openapi: "3.0.0"',
      'components:',
      '  parameters:',
      '    idParam:',
      '      name: id',
      '      in: path',
      'paths:',
      '  /users/{id}:',
      '    get:',
      '      parameters:',
      '        - $ref: "#/components/parameters/idParam"',
      '',
    ].join('\n');
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.params).toEqual(['id']);
  });

  it('reports a YAML line for each route', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.every((r) => r.line > 0)).toBe(true);
  });

  it('reports the key\'s own line even when the first operation is several lines below it', () => {
    // "/x:" is on line 3; its first operation ("get:") is on line 7. A line
    // computed from the path item's VALUE node (rather than its key) would
    // land on line 4 — the value node's range starts at its first child,
    // `summary`, not at the key itself. `line > 0` alone cannot tell these
    // two implementations apart; this asserts the exact line.
    const text = [
      'openapi: "3.0.0"',
      'paths:',
      '  /x:',
      '    summary: pushes the operation down several lines',
      '    description: more filler',
      '    parameters: []',
      '    get: {}',
      '',
    ].join('\n');
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.line).toBe(3);
  });

  it('is not partial when the document declares no servers — the default base is /', () => {
    const { routes } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths:\n  /x:\n    get: {}\n');
    expect(routes[0]?.path_partial).toBe(false);
    expect(routes[0]?.path_resolved).toBe('/x');
  });

  it('is partial when the server url is templated', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: https://{env}.example.com/v2\npaths:\n  /x:\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes[0]?.path_partial).toBe(true);
  });

  it('uses the first server when several are declared', () => {
    const text =
      'openapi: "3.0.0"\nservers:\n  - url: https://a.example.com/one\n  - url: https://b.example.com/two\npaths:\n  /x:\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes[0]?.path_resolved).toBe('/one/x');
  });

  it('uses a relative server url (an absolute-path reference) as the base path directly', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: /v1\npaths:\n  /x:\n    get: {}\n';
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.path_partial).toBe(false);
    expect(routes[0]?.path_resolved).toBe('/v1/x');
  });

  it('is partial when the server url is a scheme-less host with a path (not an absolute path)', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: api.example.com/v1\npaths:\n  /x:\n    get: {}\n';
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.path_partial).toBe(true);
    expect(routes[0]?.path_resolved).toBe('/x');
  });

  it('is partial when the server url is a bare host with no path', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: api.example.com\npaths:\n  /x:\n    get: {}\n';
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.path_partial).toBe(true);
  });

  it('is partial when the server url is protocol-relative', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: "//api.example.com/v1"\npaths:\n  /x:\n    get: {}\n';
    const { routes } = importSpec('o.yaml', text);
    expect(routes[0]?.path_partial).toBe(true);
  });

  it('excludes trace operations from import instead of overloading the ANY sentinel', () => {
    // `'ANY'` means "this handler accepts every method" in specDiff.ts's
    // methodsMatch — mapping the real (if rare) wire method TRACE onto it
    // would make a spec declaring only `trace: /x` falsely document every
    // method at /x. Excluding it is the contained fix; see the comment on
    // OPERATION_KEYS in specImport.ts for the alternative considered and
    // rejected (adding TRACE to the persisted HttpMethod union).
    const { routes, report } = importSpec(
      'o.yaml',
      'openapi: "3.0.0"\npaths:\n  /x:\n    trace: {}\n',
    );
    expect(routes).toEqual([]);
    expect(report.status).toBe('ok');
    expect(report.routes_found).toBe(0);
  });

  it('imports the other operations at a path even when trace is also present', () => {
    const { routes } = importSpec(
      'o.yaml',
      'openapi: "3.0.0"\npaths:\n  /x:\n    trace: {}\n    get: {}\n',
    );
    expect(routes.map((r) => r.method)).toEqual(['GET']);
  });
});

describe('importSpec — Swagger 2', () => {
  it('applies basePath and reports the swagger-2 format', () => {
    const text = 'swagger: "2.0"\nbasePath: /api\npaths:\n  /pets:\n    get: {}\n';
    const { routes, report } = importSpec('swagger.yaml', text);
    expect(report.format).toBe('swagger-2');
    expect(routes[0]?.path_resolved).toBe('/api/pets');
    expect(routes[0]?.framework).toBe('swagger-2');
  });
});

describe('importSpec — JSON documents', () => {
  it('parses JSON and reports line 0, because JSON.parse gives no positions', () => {
    const text = JSON.stringify({ openapi: '3.0.0', paths: { '/x': { get: {} } } });
    const { routes, report } = importSpec('openapi.json', text);
    expect(report.status).toBe('ok');
    expect(routes[0]?.line).toBe(0);
  });
});

describe('importSpec — degradation', () => {
  it('reports a parse error rather than throwing', () => {
    const { routes, report } = importSpec('bad.yaml', 'paths:\n  - [unclosed\n');
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports a parse error rather than throwing on an unresolved alias', () => {
    // Valid YAML syntax — `doc.errors` is empty. `yaml` resolves aliases
    // lazily, so a reference to an anchor that was never set surfaces only
    // when the document is materialised (`doc.toJS()`), as a thrown
    // `ReferenceError`, not as a parse error.
    const { routes, report } = importSpec('bad.yaml', 'openapi: "3.0.0"\npaths: *nope\n');
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports a parse error rather than throwing on a forward alias reference', () => {
    const { routes, report } = importSpec('bad.yaml', 'foo: *later\nbar: &later 1\n');
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports a parse error rather than throwing on a merge key from a missing anchor', () => {
    const text = 'openapi: "3.0.0"\npaths:\n  /x:\n    <<: *base\n    get: {}\n';
    const { routes, report } = importSpec('bad.yaml', text);
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports a parse error rather than throwing on an alias-expansion bomb', () => {
    // A 7-level exponential alias expansion ("billion laughs"). `yaml`
    // itself throws "Excessive alias count indicates a resource exhaustion
    // attack" out of `toJS()` — this only asserts that the throw never
    // reaches the caller of `importSpec`.
    let text = 'a: &a ["x","x","x","x","x","x","x","x","x"]\n';
    let prev = 'a';
    for (const name of ['b', 'c', 'd', 'e', 'f', 'g']) {
      text += `${name}: &${name} [*${prev},*${prev},*${prev},*${prev},*${prev},*${prev},*${prev},*${prev},*${prev}]\n`;
      prev = name;
    }
    const { routes, report } = importSpec('bomb.yaml', text);
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports an unsupported version when neither openapi nor swagger is present', () => {
    const { report } = importSpec('x.yaml', 'foo: bar\n');
    expect(report.status).toBe('unsupported_version');
    expect(report.format).toBe('unknown');
  });

  it('reports no_paths for a valid document that declares nothing', () => {
    const { report } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths: {}\n');
    expect(report.status).toBe('no_paths');
    expect(report.routes_found).toBe(0);
  });

  it('counts an external $ref path item instead of dropping it', () => {
    const text = 'openapi: "3.0.0"\npaths:\n  /x:\n    $ref: "./paths/x.yaml"\n';
    const { routes, report } = importSpec('o.yaml', text);
    expect(report.unresolved_refs).toBe(1);
    expect(routes).toEqual([]);
  });

  it('counts an internal path-item $ref the same as an external one', () => {
    // This module resolves internal `$ref`s for `parameters` entries only,
    // never for a whole path item — an internal path-item ref is exactly as
    // unresolved as an external one, so it must not fall through uncounted.
    const text = 'openapi: "3.0.0"\npaths:\n  /x:\n    $ref: "#/components/pathItems/Foo"\n';
    const { routes, report } = importSpec('o.yaml', text);
    expect(report.unresolved_refs).toBe(1);
    expect(routes).toEqual([]);
  });

  it('ignores non-operation keys under a path item', () => {
    const text =
      'openapi: "3.0.0"\npaths:\n  /x:\n    summary: not an operation\n    parameters: []\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes).toHaveLength(1);
  });
});
