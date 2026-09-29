import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { SURFACE_SNAPSHOTS_KEPT, SurfaceRepo } from '../../../src/storage/surfaceRepo.js';
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
    // `spec_files`/`spec_diff`/`imports` were added to `AttackSurfaceSnapshot`
    // after this helper was written; `...overrides` spreading a `Partial<T>`
    // made every field "present" (as possibly `undefined`) to the type
    // checker, so the gap never surfaced as a hard error until tsconfig.test
    // json started checking this file. `AttackSurfaceSnapshot` genuinely
    // requires all three at runtime — this fixture was just stale — so the
    // fix is defaults here, not relaxing the production type.
    spec_files: [],
    spec_diff: null,
    imports: [],
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
    expect(
      repo.findCacheHit({
        cache_key: 'k',
        project_path: '/p',
        tree_hash: 'deadbeef',
        freshThreshold: '1970-01-01T00:00:00.000Z',
      }),
    ).toBeNull();
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

  it('getLatestForProject ignores a newer snapshot belonging to another project', () => {
    // The distinction `getLatest()` cannot make, and the one every consumer
    // that relativizes paths against a project root needs: a snapshot of
    // another tree relativizes into a different key space, so every
    // comparison against it silently answers "not found" rather than failing.
    const repo = setup();
    repo.insert({ project_path: '/mine', tree_hash: 'h1', snapshot: makeSnapshot() });
    repo.insert({
      project_path: '/theirs',
      tree_hash: 'h2',
      snapshot: makeSnapshot({ routes: [makeRoute({ path_raw: '/theirs' })] }),
    });

    // getLatest() answers with the OTHER project's snapshot — kept, and
    // asserted, because two callers still depend on exactly that behaviour.
    expect(repo.getLatest()?.project_path).toBe('/theirs');

    const mine = repo.getLatestForProject('/mine');
    expect(mine?.project_path).toBe('/mine');
    expect(mine?.snapshot.routes[0]?.path_raw).toBe('/users');
  });

  it('getLatestForProject returns null for a project with no snapshot, not another project’s', () => {
    const repo = setup();
    repo.insert({ project_path: '/theirs', tree_hash: 'h1', snapshot: makeSnapshot() });
    expect(repo.getLatestForProject('/mine')).toBeNull();
  });

  it('findCacheHit matches key, project and tree exactly, within the freshness window', () => {
    const repo = setup();
    const past = '1970-01-01T00:00:00.000Z';
    const hit = repo.insert({ project_path: '/p', tree_hash: 'h1', snapshot: makeSnapshot(), cache_key: 'k1' });
    // Same tree hash, another project — the case the old tree-hash-only
    // lookup answered with the wrong project's routes.
    repo.insert({ project_path: '/other', tree_hash: 'h1', snapshot: makeSnapshot(), cache_key: 'k2' });
    // A pre-006 row: no key, never a hit.
    repo.insert({ project_path: '/p', tree_hash: 'h1', snapshot: makeSnapshot() });

    const args = { cache_key: 'k1', project_path: '/p', tree_hash: 'h1', freshThreshold: past };
    expect(repo.findCacheHit(args)?.id).toBe(hit.id);
    expect(repo.findCacheHit({ ...args, cache_key: 'k2' })).toBeNull();
    expect(repo.findCacheHit({ ...args, project_path: '/other' })).toBeNull();
    expect(repo.findCacheHit({ ...args, tree_hash: 'h2' })).toBeNull();
    expect(repo.findCacheHit({ ...args, freshThreshold: '2999-01-01T00:00:00.000Z' })).toBeNull();
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

  it('tolerates a stored `routes` that is valid JSON but not an array, instead of throwing', () => {
    // `?? []` only catches null/undefined. A row containing `{"routes": {}}`
    // is valid JSON — `parseJsonObject` succeeds — but `.map` is called on a
    // plain object, which throws a TypeError out of getLatest()/getById(),
    // i.e. out of the guardian://surface/* resource handlers. This file's
    // own convention (parseJsonObject) is to tolerate malformed stored data
    // rather than throw; a corrupted `routes` field should be no different.
    const db = new Database(':memory:');
    runMigrations(db);
    db.prepare(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', ?)`,
    ).run(JSON.stringify({ routes: {} }));

    const repo = new SurfaceRepo(db);
    expect(() => repo.getLatest()).not.toThrow();
    expect(repo.getLatest()?.snapshot.routes).toEqual([]);
  });

  it('reads back a stored spec-provenance route as spec, not backfilled to code', () => {
    // Sibling of the backfill test above: that one pins the missing-field
    // (legacy) case; this pins the other branch of the same `{ provenance:
    // 'code' as const, ...r }` spread in rowToSnapshot — a route that DOES
    // carry a stored provenance must have that value win over the default.
    // Spec routes are now genuinely persisted in routes[] (this branch), so
    // this is reachable in production, not just a hypothetical. Reversing
    // the spread order (`{ ...r, provenance: 'code' as const }`) would make
    // this fail by always reporting 'code' regardless of what was stored.
    const db = new Database(':memory:');
    runMigrations(db);
    const specRoute = makeRoute({ provenance: 'spec' });
    db.prepare(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', ?)`,
    ).run(JSON.stringify({ routes: [specRoute] }));

    const repo = new SurfaceRepo(db);
    expect(repo.getLatest()?.snapshot.routes[0]?.provenance).toBe('spec');
  });
});

describe('SurfaceRepo — third-party imports and retention (review of part C, M6)', () => {
  function withRow(json: unknown): SurfaceRepo {
    const db = new Database(':memory:');
    runMigrations(db);
    db.prepare(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', ?)`,
    ).run(JSON.stringify(json));
    return new SurfaceRepo(db);
  }

  it('reads external_imports stored in the earlier flat shape as absent, so it is recomputed', () => {
    const repo = withRow({ routes: [], external_imports: [{ file: 'a.ts', specifier: 'x', language: 'typescript' }] });
    expect(repo.getLatest()?.snapshot.external_imports).toBeUndefined();
  });

  it('drops a stored package entry whose file index points nowhere, keeping the rest', () => {
    const repo = withRow({
      routes: [],
      external_imports: {
        files: ['a.ts'],
        packages: [
          { specifier: 'x', language: 'typescript', files: [0], file_count: 1 },
          { specifier: 'y', language: 'typescript', files: [7], file_count: 1 },
        ],
      },
    });
    expect(repo.getLatest()?.snapshot.external_imports).toEqual({
      files: ['a.ts'],
      packages: [{ specifier: 'x', language: 'typescript', files: [0], file_count: 1 }],
    });
  });

  it(`keeps the newest ${SURFACE_SNAPSHOTS_KEPT} snapshots per project and never touches another project's`, () => {
    const repo = setup();
    const ids: number[] = [];
    for (let i = 0; i < SURFACE_SNAPSHOTS_KEPT + 3; i += 1) {
      ids.push(repo.insert({ project_path: '/a', tree_hash: `h${i}`, snapshot: makeSnapshot() }).id);
    }
    const other = repo.insert({ project_path: '/b', tree_hash: 'hb', snapshot: makeSnapshot() }).id;

    expect(repo.getById(ids[0] ?? -1)).toBeNull();
    expect(repo.getById(ids[2] ?? -1)).toBeNull();
    expect(repo.getById(ids[3] ?? -1)).not.toBeNull();
    expect(repo.getLatestForProject('/a')?.id).toBe(ids[ids.length - 1]);
    expect(repo.getById(other)).not.toBeNull();
    expect(repo.listRecent(100).filter((s) => s.project_path === '/a')).toHaveLength(SURFACE_SNAPSHOTS_KEPT);
  });
});
