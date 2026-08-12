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

  it('reports a YAML line for each route', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.every((r) => r.line > 0)).toBe(true);
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

  it('ignores non-operation keys under a path item', () => {
    const text =
      'openapi: "3.0.0"\npaths:\n  /x:\n    summary: not an operation\n    parameters: []\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes).toHaveLength(1);
  });
});
