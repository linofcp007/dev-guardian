import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { SurfaceRepo } from '../../../src/storage/surfaceRepo.js';
import type { AttackSurfaceSnapshot, RouteRecord } from '../../../src/types.js';

function makeRoute(overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: '/users',
    path_resolved: '/users',
    path_partial: false,
    file: 'src/routes/users.ts',
    line: 10,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    ...overrides,
  };
}

function makeSnapshot(overrides: Partial<AttackSurfaceSnapshot> = {}): AttackSurfaceSnapshot {
  return {
    routes: [makeRoute()],
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [],
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [],
    ...overrides,
  };
}

function setup() {
  const db = new Database(':memory:');
  runMigrations(db);
  return new SurfaceRepo(db);
}

describe('SurfaceRepo', () => {
  it('returns null when nothing has been captured yet', () => {
    const repo = setup();
    expect(repo.getLatest()).toBeNull();
    expect(repo.getById(1)).toBeNull();
    expect(repo.getByTreeHash('deadbeef')).toBeNull();
  });

  it('round-trips a snapshot through JSON storage', () => {
    const repo = setup();
    const inserted = repo.insert({
      project_path: '/p',
      tree_hash: 'hash-1',
      snapshot: makeSnapshot(),
    });

    expect(inserted.id).toBeGreaterThan(0);
    const fetched = repo.getById(inserted.id);
    expect(fetched?.snapshot.routes[0]?.path_resolved).toBe('/users');
    expect(fetched?.tree_hash).toBe('hash-1');
  });

  it('getLatest returns the most recent insert', () => {
    const repo = setup();
    repo.insert({ project_path: '/p', tree_hash: 'h1', snapshot: makeSnapshot() });
    repo.insert({
      project_path: '/p',
      tree_hash: 'h2',
      snapshot: makeSnapshot({ routes: [makeRoute({ path_raw: '/newer' })] }),
    });

    expect(repo.getLatest()?.snapshot.routes[0]?.path_raw).toBe('/newer');
  });

  it('getByTreeHash finds a snapshot by hash — the cache lookup', () => {
    const repo = setup();
    repo.insert({ project_path: '/p', tree_hash: 'h1', snapshot: makeSnapshot() });
    expect(repo.getByTreeHash('h1')?.tree_hash).toBe('h1');
    expect(repo.getByTreeHash('nope')).toBeNull();
  });

  it('tolerates malformed stored JSON instead of throwing', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    db.prepare(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', 'not json')`,
    ).run();

    const repo = new SurfaceRepo(db);
    expect(repo.getLatest()?.snapshot.routes).toEqual([]);
  });

  it('backfills provenance as code for snapshots written before the field existed', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    const legacyRoute = { ...makeRoute() } as Record<string, unknown>;
    delete legacyRoute['provenance'];
    db.prepare(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', ?)`,
    ).run(JSON.stringify({ routes: [legacyRoute] }));

    const repo = new SurfaceRepo(db);
    expect(repo.getLatest()?.snapshot.routes[0]?.provenance).toBe('code');
  });
});
