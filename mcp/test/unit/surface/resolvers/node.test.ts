import { describe, expect, it } from 'vitest';
import { resolveNodeMounts } from '../../../../src/surface/resolvers/node.js';
import type { MountRecord, RouteRecord } from '../../../../src/types.js';

function route(overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: '/list',
    path_resolved: '/list',
    path_partial: false,
    file: 'src/routes/users.ts',
    line: 3,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    ...overrides,
  };
}

const mount: MountRecord = {
  prefix: '/api',
  router_var: 'usersRouter',
  file: 'src/app.ts',
  line: 4,
};

const imp = {
  symbol: 'usersRouter',
  module_file: 'src/routes/users.ts',
  file: 'src/app.ts',
};

describe('resolveNodeMounts', () => {
  it('prefixes routes in the mounted module', () => {
    const [resolved] = resolveNodeMounts([route()], [mount], [imp]);
    expect(resolved?.path_resolved).toBe('/api/list');
    expect(resolved?.path_partial).toBe(false);
    expect(resolved?.path_raw).toBe('/list');
  });

  it('normalises double and missing slashes at the join', () => {
    const [a] = resolveNodeMounts([route({ path_raw: 'list', path_resolved: 'list' })], [mount], [imp]);
    expect(a?.path_resolved).toBe('/api/list');

    const [b] = resolveNodeMounts(
      [route()],
      [{ ...mount, prefix: '/api/' }],
      [imp],
    );
    expect(b?.path_resolved).toBe('/api/list');
  });

  it('collapses a root-mounted router to the route path itself', () => {
    const [resolved] = resolveNodeMounts([route()], [{ ...mount, prefix: '/' }], [imp]);
    expect(resolved?.path_resolved).toBe('/list');
    expect(resolved?.path_partial).toBe(false);
  });

  it('marks a route partial when its module is mounted twice', () => {
    const second: MountRecord = { ...mount, prefix: '/v2', line: 5 };
    const [resolved] = resolveNodeMounts([route()], [mount, second], [imp]);
    expect(resolved?.path_partial).toBe(true);
    expect(resolved?.path_resolved).toBe('/list');
  });

  it('marks a route partial when nothing mounts its module', () => {
    const [resolved] = resolveNodeMounts([route()], [], []);
    expect(resolved?.path_partial).toBe(true);
    expect(resolved?.path_resolved).toBe('/list');
  });

  it('leaves routes defined in the mounting file itself alone', () => {
    const appRoute = route({ file: 'src/app.ts', path_raw: '/health', path_resolved: '/health' });
    const [resolved] = resolveNodeMounts([appRoute], [mount], [imp]);
    expect(resolved?.path_resolved).toBe('/health');
    expect(resolved?.path_partial).toBe(false);
  });

  it('never clears a path_partial the extractor set on a non-literal capture', () => {
    const expr = route({ path_raw: 'routeVar', path_resolved: 'routeVar', path_partial: true });
    const [resolved] = resolveNodeMounts([expr], [mount], [imp]);
    expect(resolved?.path_partial).toBe(true);
    expect(resolved?.path_resolved).toBe('routeVar');
  });

  it('ignores non-JS/TS routes entirely', () => {
    const py = route({ file: 'app/main.py', language: 'python', framework: 'fastapi' });
    const [resolved] = resolveNodeMounts([py], [mount], [imp]);
    expect(resolved?.path_resolved).toBe('/list');
    expect(resolved?.path_partial).toBe(false);
  });
});
