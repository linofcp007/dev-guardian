# map_attack_surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `map_attack_surface` MCP tool that statically extracts an application's externally reachable surface (HTTP routes, env vars, exposed ports) across all 8 supported stacks and persists it as a queryable snapshot.

**Architecture:** A Semgrep rule pack (`configs/semgrep/routes.yml`) is the universal extractor — Semgrep already parses all 8 languages, so a new framework is a YAML entry rather than a new parser. Its JSON output is fed through pure TypeScript modules that map matches to `RouteRecord`s, resolve route prefixes for JS/TS and WordPress, and collect env vars and ports. The result is persisted to a new `surface_snapshots` table and served through two MCP resources. Only the Semgrep invocation touches the outside world; everything downstream is a pure function over data and is unit-tested without Semgrep installed.

**Tech Stack:** TypeScript (ESM, NodeNext), better-sqlite3, zod, vitest, Semgrep.

**Spec:** [`docs/superpowers/specs/2026-08-10-map-attack-surface-design.md`](../specs/2026-08-10-map-attack-surface-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Working directory is `mcp/`** for all build and test commands: `npm run build`, `npm test`.
- **Import specifiers must end in `.js`** even when importing a `.ts` file — the project is ESM with `"module": "NodeNext"`.
- **`noUncheckedIndexedAccess: true`** — every array index and every `Record` lookup yields `T | undefined`. Destructuring `const [a, b] = arr` gives `a: T | undefined`. Guard before use; never use `!`.
- **`noUnusedLocals` and `noUnusedParameters` are on** — prefix intentionally-unused parameters with `_`.
- **`exactOptionalPropertyTypes: false`** — building objects with `{ ...(x ? { k: x } : {}) }` is allowed, and so is assigning `undefined` to an optional property.
- **`npm test` is `vitest run` — it does NOT check coverage.** Coverage thresholds (statements 70, branches 62, functions 72, lines 70, in `mcp/vitest.config.ts`) are enforced only by `npm run test:coverage`, which Task 8 runs once at the end. Every new `src/` module in this plan still ships with its tests in the same task — do not batch tests to the end, or that final run will fail and you will not know which task caused it.
- **`npm run build` is `tsc` + `copy-assets.mjs` + `bundle.mjs`.** All three must succeed; a `tsc` error means the commit is not ready.
- **Input schema primitives come from `mcp/src/schemas.ts`** — never inline zod literals in a tool's `inputSchema`.
- **Commit `mcp/dist/` in the same commit as any TypeScript change.** The repo is the distribution; Claude Code runs `mcp/dist/server.js` with no install-time build. Run `npm run build` before `git add`.
- **Do not push.** Commits are local unless the user asks otherwise.

---

## File Structure

| Path | Responsibility |
| --- | --- |
| `mcp/src/types.ts` (modify) | Add `RouteRecord`, `MountRecord`, `CoverageEntry`, `AttackSurfaceSnapshot` |
| `mcp/src/storage/migrations/002_attack_surface.sql` (create) | `surface_snapshots` table |
| `mcp/src/storage/surfaceRepo.ts` (create) | Persist/read snapshots; mirrors `stackRepo.ts` |
| `mcp/src/storage/index.ts` (modify) | Expose `storage.surface` |
| `mcp/src/surface/extract.ts` (create) | Semgrep JSON → `{ routes, mounts }`. Pure. |
| `mcp/src/surface/resolvers/node.ts` (create) | JS/TS router-mount prefix resolution. Pure. |
| `mcp/src/surface/resolvers/wordpress.ts` (create) | WP REST namespace resolution. Pure. |
| `mcp/src/surface/collectors/envVars.ts` (create) | Referenced env vars from Semgrep matches. Pure. |
| `mcp/src/surface/collectors/ports.ts` (create) | `EXPOSE` / compose `ports:`. Pure, reads files. |
| `configs/semgrep/routes.yml` (create) | The rule pack. Data, not code. |
| `mcp/src/tools/mapAttackSurface.ts` (create) | The tool: orchestration, caching, persistence |
| `mcp/src/resources/surface.ts` (create) | `guardian://surface/latest`, `guardian://surface/{id}` |
| `mcp/src/registerAll.ts` (modify) | Two new side-effect imports |

Tests mirror the source tree under `mcp/test/unit/` and `mcp/test/integration/`.

---

### Task 1: Types, migration, and the surface repository

The persistence layer, standalone and testable before any extraction exists.

**Files:**

- Modify: `mcp/src/types.ts` (append after `StackSnapshot`, around line 173)
- Create: `mcp/src/storage/migrations/002_attack_surface.sql`
- Create: `mcp/src/storage/surfaceRepo.ts`
- Modify: `mcp/src/storage/index.ts`
- Test: `mcp/test/unit/storage/surfaceRepo.test.ts`

**Interfaces:**

- Consumes: `DB` and `Statement` from `storage/db.js`; `nowIso`, `parseJsonObject` from `storage/repoUtil.js`; `runMigrations` from `storage/migrations/runner.js`.
- Produces: the four types below, and `SurfaceRepo` with `insert(input)`, `getLatest()`, `getById(id)`, `getByTreeHash(hash)`, `listRecent(limit)`. `PersistedSurfaceSnapshot` is `{ id, project_path, captured_at, tree_hash, snapshot }`.

- [ ] **Step 1: Write the failing test**

Create `mcp/test/unit/storage/surfaceRepo.test.ts`:

```ts
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { SurfaceRepo } from '../../../src/storage/surfaceRepo.js';
import type { AttackSurfaceSnapshot, RouteRecord } from '../../../src/types.js';

function makeRoute(overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
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
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/storage/surfaceRepo.test.ts`
Expected: FAIL — `Cannot find module '../../../src/storage/surfaceRepo.js'`.

- [ ] **Step 3: Add the types**

Append to `mcp/src/types.ts`, directly after the `StackSnapshot` interface:

```ts
export const HTTP_METHODS = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'ANY',
] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/**
 * One externally reachable HTTP route, extracted statically.
 *
 * `path_raw` is what the source literally says at the match site.
 * `path_resolved` adds any prefix we could resolve (router mounting,
 * WordPress REST namespaces). When we know a prefix may be missing but could
 * not resolve it, `path_partial` is true — consumers must not treat
 * `path_resolved` as a complete URL path in that case.
 */
export interface RouteRecord {
  method: HttpMethod;
  path_raw: string;
  path_resolved: string;
  path_partial: boolean;
  file: string;
  line: number;
  framework: string;
  language: string;
  /**
   * Never inferred from the absence of an auth decorator — see the design
   * doc. 'none' is emitted only for affirmative public declarations such as
   * WordPress `permission_callback: '__return_true'`.
   */
  auth_hint: 'none' | 'required' | 'unknown';
  params: string[];
  confidence: 'high' | 'medium' | 'low';
  /**
   * Framework-level route namespace, when the framework has one. Currently
   * only WordPress: `register_rest_route('myplugin/v1', '/items')` yields
   * namespace 'myplugin/v1'. Semgrep cannot concatenate two metavariables
   * into a third, so the extractor keeps them as separate fields and the WP
   * resolver combines them.
   */
  namespace?: string;
}

/** A `app.use('/prefix', router)`-style mount, consumed by the Node resolver. */
export interface MountRecord {
  prefix: string;
  router_var: string;
  file: string;
  line: number;
}

export interface CoverageEntry {
  language: string;
  detected: boolean;
  routes_found: number;
  /**
   * 'no_rules' means the language was detected but the rule pack covers no
   * framework for it — the case most tools hide by reporting zero.
   */
  status: 'ok' | 'no_matches' | 'no_rules';
}

export interface AttackSurfaceSnapshot {
  routes: RouteRecord[];
  env_vars: { name: string; file: string; line: number }[];
  ports: { port: number; source: string }[];
  /** Precomputed view over `routes`; duplicated so consumers need no regex. */
  webhooks: RouteRecord[];
  coverage: CoverageEntry[];
  tools_run: ToolRun[];
  missing_tools: string[];
}
```

- [ ] **Step 4: Write the migration**

Create `mcp/src/storage/migrations/002_attack_surface.sql`:

```sql
-- 002_attack_surface.sql
-- Snapshots produced by `map_attack_surface`.
--
-- tree_hash is a column here rather than a row in `tree_cache` because
-- tree_cache declares FOREIGN KEY (scan_id) REFERENCES scans(id), and this
-- tool produces a snapshot, not a scan — reusing that table would mean
-- fabricating a scans row purely to satisfy the constraint.

CREATE TABLE IF NOT EXISTS surface_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  tree_hash    TEXT NOT NULL,
  json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_surface_captured_at
  ON surface_snapshots(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_surface_tree_hash
  ON surface_snapshots(tree_hash);
```

- [ ] **Step 5: Write the repository**

Create `mcp/src/storage/surfaceRepo.ts`:

```ts
/**
 * Attack-surface snapshots repository.
 *
 * Each successful `map_attack_surface` run persists one row. The resources
 * `guardian://surface/latest` and `guardian://surface/{id}` read from here,
 * and `getByTreeHash` backs the tool's cache check.
 *
 * Mirrors `stackRepo.ts`; the additions are `getById` (the templated
 * resource needs it) and `getByTreeHash` (the cache).
 */

import type { DB, Statement } from './db.js';
import type { AttackSurfaceSnapshot } from '../types.js';
import { nowIso, parseJsonObject } from './repoUtil.js';

interface SurfaceRow {
  id: number;
  project_path: string;
  captured_at: string;
  tree_hash: string;
  json: string;
}

export interface InsertSurfaceSnapshotInput {
  project_path: string;
  tree_hash: string;
  snapshot: AttackSurfaceSnapshot;
}

export interface PersistedSurfaceSnapshot {
  id: number;
  project_path: string;
  captured_at: string;
  tree_hash: string;
  snapshot: AttackSurfaceSnapshot;
}

const EMPTY_SNAPSHOT: AttackSurfaceSnapshot = {
  routes: [],
  env_vars: [],
  ports: [],
  webhooks: [],
  coverage: [],
  tools_run: [],
  missing_tools: [],
};

export class SurfaceRepo {
  private readonly insertStmt: Statement<[string, string, string, string]>;
  private readonly getLatestStmt: Statement<[], SurfaceRow>;
  private readonly getByIdStmt: Statement<[number], SurfaceRow>;
  private readonly getByTreeHashStmt: Statement<[string], SurfaceRow>;
  private readonly listRecentStmt: Statement<[number], SurfaceRow>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
      VALUES (?, ?, ?, ?)
    `);
    this.getLatestStmt = db.prepare<[], SurfaceRow>(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT 1
    `);
    this.getByIdStmt = db.prepare<[number], SurfaceRow>(`
      SELECT * FROM surface_snapshots WHERE id = ?
    `);
    this.getByTreeHashStmt = db.prepare<[string], SurfaceRow>(`
      SELECT * FROM surface_snapshots WHERE tree_hash = ? ORDER BY id DESC LIMIT 1
    `);
    this.listRecentStmt = db.prepare<[number], SurfaceRow>(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT ?
    `);
  }

  insert(input: InsertSurfaceSnapshotInput): PersistedSurfaceSnapshot {
    const capturedAt = nowIso();
    const info = this.insertStmt.run(
      input.project_path,
      capturedAt,
      input.tree_hash,
      JSON.stringify(input.snapshot),
    );
    return {
      id: Number(info.lastInsertRowid),
      project_path: input.project_path,
      captured_at: capturedAt,
      tree_hash: input.tree_hash,
      snapshot: input.snapshot,
    };
  }

  getLatest(): PersistedSurfaceSnapshot | null {
    const row = this.getLatestStmt.get();
    return row ? rowToSnapshot(row) : null;
  }

  getById(id: number): PersistedSurfaceSnapshot | null {
    const row = this.getByIdStmt.get(id);
    return row ? rowToSnapshot(row) : null;
  }

  getByTreeHash(treeHash: string): PersistedSurfaceSnapshot | null {
    const row = this.getByTreeHashStmt.get(treeHash);
    return row ? rowToSnapshot(row) : null;
  }

  listRecent(limit = 10): PersistedSurfaceSnapshot[] {
    return this.listRecentStmt.all(limit).map(rowToSnapshot);
  }
}

function rowToSnapshot(row: SurfaceRow): PersistedSurfaceSnapshot {
  const parsed = parseJsonObject<Record<string, unknown>>(row.json, {});
  return {
    id: row.id,
    project_path: row.project_path,
    captured_at: row.captured_at,
    tree_hash: row.tree_hash,
    snapshot: { ...EMPTY_SNAPSHOT, ...(parsed as Partial<AttackSurfaceSnapshot>) },
  };
}
```

Note `ORDER BY id DESC` rather than `captured_at DESC`: two inserts within the same millisecond would tie on the timestamp, and the "getLatest returns the most recent insert" test would flake.

- [ ] **Step 6: Wire it into the Storage facade**

In `mcp/src/storage/index.ts`, add the import beside the others, the readonly field, and the constructor line:

```ts
import { SurfaceRepo } from './surfaceRepo.js';
// ...
  readonly surface: SurfaceRepo;
// ...
    this.surface = new SurfaceRepo(db);
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `npm test -- test/unit/storage/surfaceRepo.test.ts test/unit/storage/migrations.test.ts`
Expected: PASS, including the existing migrations test — `002` must apply cleanly on top of `001`.

- [ ] **Step 8: Build and commit**

```bash
npm run build
git add src/types.ts src/storage/ dist/ test/unit/storage/surfaceRepo.test.ts
git commit -m "feat(surface): add surface_snapshots table and SurfaceRepo"
```

---

### Task 2: Semgrep JSON extractor

Turns raw Semgrep output into `RouteRecord`s and `MountRecord`s. Pure — no filesystem, no process, no Semgrep needed to test.

**Files:**

- Create: `mcp/src/surface/extract.ts`
- Create: `mcp/test/unit/surface/extract.test.ts`
- Create: `mcp/test/fixtures/surface/express.json`

**Interfaces:**

- Consumes: `RouteRecord`, `MountRecord`, `HttpMethod` from `types.js` (Task 1).
- Produces: `extractSurface(semgrepJson: unknown): { routes: RouteRecord[]; mounts: MountRecord[] }`, and the helpers `extractParams(path: string): string[]` and `languageFromPath(file: string): string`.

**Semgrep output shape consumed** (only the fields used):

```json
{
  "results": [
    {
      "check_id": "guardian-route-express",
      "path": "src/routes/users.ts",
      "start": { "line": 12 },
      "extra": {
        "metadata": {
          "guardian_kind": "route",
          "framework": "express",
          "confidence": "high",
          "mountable": true
        },
        "metavars": {
          "$METHOD": { "abstract_content": "get" },
          "$PATH": { "abstract_content": "/users/:id" }
        }
      }
    }
  ]
}
```

- [ ] **Step 1: Write the fixture**

Create `mcp/test/fixtures/surface/express.json`:

```json
{
  "results": [
    {
      "check_id": "guardian-route-express",
      "path": "src/routes/users.ts",
      "start": { "line": 12 },
      "extra": {
        "metadata": {
          "guardian_kind": "route",
          "framework": "express",
          "confidence": "high",
          "mountable": true
        },
        "metavars": {
          "$METHOD": { "abstract_content": "get" },
          "$PATH": { "abstract_content": "/users/:id" }
        }
      }
    },
    {
      "check_id": "guardian-mount-express",
      "path": "src/app.ts",
      "start": { "line": 4 },
      "extra": {
        "metadata": { "guardian_kind": "mount", "framework": "express" },
        "metavars": {
          "$PREFIX": { "abstract_content": "/api" },
          "$ROUTER": { "abstract_content": "usersRouter" }
        }
      }
    },
    {
      "check_id": "some-other-rule",
      "path": "src/app.ts",
      "start": { "line": 9 },
      "extra": { "metadata": { "category": "security" }, "metavars": {} }
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

Create `mcp/test/unit/surface/extract.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  extractParams,
  extractSurface,
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
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/extract.test.ts`
Expected: FAIL — `Cannot find module '../../../src/surface/extract.js'`.

- [ ] **Step 4: Write the implementation**

Create `mcp/src/surface/extract.ts`:

```ts
/**
 * Semgrep `--json` → attack-surface records.
 *
 * Pure: takes already-parsed JSON, returns records. No filesystem, no
 * process spawning — which is what lets the whole extraction path be tested
 * without Semgrep installed.
 *
 * Only matches carrying `metadata.guardian_kind` are considered, so running
 * this over output from another rule pack yields nothing rather than noise.
 * Malformed or partial metadata degrades to a lower-confidence record; it
 * never throws, because the rule pack is user-extensible.
 */

import type { HttpMethod, MountRecord, RouteRecord } from '../types.js';

const METHOD_NAMES = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all', 'any',
]);

const EXTENSION_LANGUAGES: Record<string, string> = {
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  py: 'python',
  php: 'php',
  go: 'go',
  rs: 'rust',
  rb: 'ruby',
  java: 'java',
  cs: 'csharp',
};

export function languageFromPath(file: string): string {
  const ext = file.split('.').pop()?.toLowerCase();
  if (ext === undefined) return 'unknown';
  return EXTENSION_LANGUAGES[ext] ?? 'unknown';
}

/**
 * Normalise every path-parameter syntax we support to a bare name:
 *   :id  ·  :id?  ·  {id}  ·  <int:item_id>  →  id / item_id
 */
export function extractParams(path: string): string[] {
  const params: string[] = [];
  for (const match of path.matchAll(/:([A-Za-z_][\w]*)\??/g)) {
    const name = match[1];
    if (name !== undefined) params.push(name);
  }
  for (const match of path.matchAll(/\{([^}]+)\}/g)) {
    const inner = match[1];
    if (inner === undefined) continue;
    const name = inner.split(':').pop()?.trim();
    if (name !== undefined && name.length > 0) params.push(name);
  }
  for (const match of path.matchAll(/<([^>]+)>/g)) {
    const inner = match[1];
    if (inner === undefined) continue;
    const name = inner.split(':').pop()?.trim();
    if (name !== undefined && name.length > 0) params.push(name);
  }
  return [...new Set(params)];
}

export function extractSurface(semgrepJson: unknown): {
  routes: RouteRecord[];
  mounts: MountRecord[];
} {
  const routes: RouteRecord[] = [];
  const mounts: MountRecord[] = [];

  for (const raw of asArray(prop(semgrepJson, 'results'))) {
    const extra = prop(raw, 'extra');
    const metadata = prop(extra, 'metadata');
    const kind = str(metadata, 'guardian_kind');
    const file = str(raw, 'path');
    const line = num(prop(raw, 'start'), 'line') ?? 0;
    if (file === undefined) continue;

    if (kind === 'route') {
      const route = toRoute(metadata, prop(extra, 'metavars'), file, line);
      if (route) routes.push(route);
    } else if (kind === 'mount') {
      const mount = toMount(prop(extra, 'metavars'), file, line);
      if (mount) mounts.push(mount);
    }
  }

  return { routes, mounts };
}

function toRoute(
  metadata: unknown,
  metavars: unknown,
  file: string,
  line: number,
): RouteRecord | null {
  // Namespaced frameworks (WordPress) capture $NS + $ROUTE instead of $PATH,
  // because Semgrep cannot concatenate metavariables into a third one. Keep
  // them as separate fields; the WP resolver composes the served path.
  const namespace = stripQuotes(metavar(metavars, '$NS'));
  const path = stripQuotes(metavar(metavars, '$PATH') ?? metavar(metavars, '$ROUTE'));
  if (path === undefined) return null;

  const route: RouteRecord = {
    method: normalizeMethod(metavar(metavars, '$METHOD') ?? str(metadata, 'method')),
    path_raw: path,
    path_resolved: path,
    path_partial: false,
    file,
    line,
    framework: str(metadata, 'framework') ?? 'unknown',
    language: languageFromPath(file),
    auth_hint: normalizeAuth(str(metadata, 'auth')),
    params: extractParams(path),
    confidence: normalizeConfidence(str(metadata, 'confidence')),
  };
  if (namespace !== undefined) route.namespace = namespace;
  return route;
}

/**
 * Semgrep's `abstract_content` keeps the source quoting, so a captured path
 * arrives as `'/users'` rather than `/users`.
 */
function stripQuotes(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.replace(/^['"`]|['"`]$/g, '');
}

function toMount(metavars: unknown, file: string, line: number): MountRecord | null {
  const prefix = stripQuotes(metavar(metavars, '$PREFIX'));
  const routerVar = metavar(metavars, '$ROUTER');
  if (prefix === undefined || routerVar === undefined) return null;
  return { prefix, router_var: routerVar, file, line };
}

function normalizeMethod(raw: string | undefined): HttpMethod {
  if (raw === undefined) return 'ANY';
  const lowered = raw.toLowerCase();
  if (!METHOD_NAMES.has(lowered)) return 'ANY';
  if (lowered === 'all' || lowered === 'any') return 'ANY';
  return lowered.toUpperCase() as HttpMethod;
}

function normalizeAuth(raw: string | undefined): RouteRecord['auth_hint'] {
  if (raw === 'required' || raw === 'none') return raw;
  return 'unknown';
}

function normalizeConfidence(raw: string | undefined): RouteRecord['confidence'] {
  if (raw === 'high' || raw === 'medium' || raw === 'low') return raw;
  return 'low';
}

/* ---- tiny structural accessors (kept local; the parser helpers in
   runners/scannerParsers are Finding-shaped and would not fit) ---- */

function prop(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  return (value as Record<string, unknown>)[key];
}

function str(value: unknown, key: string): string | undefined {
  const v = prop(value, key);
  return typeof v === 'string' ? v : undefined;
}

function num(value: unknown, key: string): number | undefined {
  const v = prop(value, key);
  return typeof v === 'number' ? v : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Semgrep nests captures as `metavars.$NAME.abstract_content`. */
function metavar(metavars: unknown, name: string): string | undefined {
  return str(prop(metavars, name), 'abstract_content');
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/extract.test.ts`
Expected: PASS, 10 tests (6 in `extractSurface`, 2 in `extractParams` and `languageFromPath` combined with the namespace cases — count the `it()` blocks in Step 2 rather than trusting this number).

- [ ] **Step 6: Build and commit**

```bash
npm run build
git add src/surface/extract.ts test/unit/surface/ test/fixtures/surface/ dist/
git commit -m "feat(surface): extract routes and mounts from semgrep JSON"
```

---

### Task 3: Node router-mount resolver

Resolves `app.use('/api', usersRouter)` into a real prefix on the routes defined in the mounted module. This is the accuracy half of the hybrid approach.

**Files:**

- Create: `mcp/src/surface/resolvers/node.ts`
- Create: `mcp/test/unit/surface/resolvers/node.test.ts`

**Interfaces:**

- Consumes: `RouteRecord`, `MountRecord` from `types.js`; nothing from Task 2 at runtime (it operates on the records Task 2 produces).
- Produces: `resolveNodeMounts(routes: RouteRecord[], mounts: MountRecord[], imports: ImportRecord[]): RouteRecord[]` and `interface ImportRecord { symbol: string; module_file: string; file: string }`.

**Correlation strategy, and its honest limit:** a mount names a variable (`usersRouter`), not a file. To connect the mount to the routes it governs we need the import that bound that variable, which the rule pack also captures (`guardian_kind: 'import'`, Task 6). The chain is: mount in `app.ts` names `usersRouter` → import in `app.ts` binds `usersRouter` to `./routes/users` → routes in `src/routes/users.ts` get the `/api` prefix. When any link is missing — a dynamically-computed prefix, a re-exported router, a mount whose variable never resolves — the route keeps `path_raw` and gets `path_partial: true`. Guessing would be worse than admitting.

- [ ] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/resolvers/node.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { resolveNodeMounts } from '../../../../src/surface/resolvers/node.js';
import type { MountRecord, RouteRecord } from '../../../../src/types.js';

function route(overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
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

  it('ignores non-JS/TS routes entirely', () => {
    const py = route({ file: 'app/main.py', language: 'python', framework: 'fastapi' });
    const [resolved] = resolveNodeMounts([py], [mount], [imp]);
    expect(resolved?.path_resolved).toBe('/list');
    expect(resolved?.path_partial).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/resolvers/node.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `mcp/src/surface/resolvers/node.ts`:

```ts
/**
 * Resolve Express/Fastify/NestJS router mounting into real path prefixes.
 *
 * Semgrep sees `router.get('/list')` and `app.use('/api', usersRouter)` as
 * two unrelated matches in two files. Connecting them needs the import that
 * bound the variable:
 *
 *   app.ts:  import usersRouter from './routes/users'
 *   app.ts:  app.use('/api', usersRouter)
 *   routes/users.ts:  router.get('/list')      →  /api/list
 *
 * When a link in that chain is missing — a computed prefix, a re-exported
 * router, a module mounted at two different prefixes — we do NOT guess. The
 * route keeps its raw path and is flagged `path_partial`, so downstream
 * consumers know the path is incomplete rather than believing a wrong one.
 */

import type { MountRecord, RouteRecord } from '../../types.js';

export interface ImportRecord {
  /** The bound local symbol, e.g. `usersRouter`. */
  symbol: string;
  /** Project-relative file the symbol resolves to, e.g. `src/routes/users.ts`. */
  module_file: string;
  /** File containing the import statement. */
  file: string;
}

const NODE_LANGUAGES = new Set(['javascript', 'typescript']);

export function resolveNodeMounts(
  routes: RouteRecord[],
  mounts: MountRecord[],
  imports: ImportRecord[],
): RouteRecord[] {
  const prefixesByFile = buildPrefixIndex(mounts, imports);
  const mountingFiles = new Set(mounts.map((m) => m.file));

  return routes.map((route) => {
    if (!NODE_LANGUAGES.has(route.language)) return route;
    // A route declared in the same file that does the mounting is attached to
    // the app directly, not to a mounted sub-router.
    if (mountingFiles.has(route.file)) return route;

    const prefixes = prefixesByFile.get(route.file);
    if (prefixes === undefined || prefixes.size !== 1) {
      return { ...route, path_partial: true };
    }
    const prefix = [...prefixes][0];
    if (prefix === undefined) return { ...route, path_partial: true };

    return { ...route, path_resolved: joinPath(prefix, route.path_raw), path_partial: false };
  });
}

/** module file → the set of distinct prefixes it is mounted at. */
function buildPrefixIndex(
  mounts: MountRecord[],
  imports: ImportRecord[],
): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const mount of mounts) {
    const binding = imports.find(
      (i) => i.file === mount.file && i.symbol === mount.router_var,
    );
    if (binding === undefined) continue;
    const existing = index.get(binding.module_file);
    if (existing === undefined) {
      index.set(binding.module_file, new Set([mount.prefix]));
    } else {
      existing.add(mount.prefix);
    }
  }
  return index;
}

export function joinPath(prefix: string, path: string): string {
  const left = prefix.replace(/\/+$/, '');
  const right = path.startsWith('/') ? path : `/${path}`;
  const joined = `${left}${right}`;
  return joined.startsWith('/') ? joined : `/${joined}`;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/resolvers/node.test.ts`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
npm run build
git add src/surface/resolvers/node.ts test/unit/surface/resolvers/ dist/
git commit -m "feat(surface): resolve Express-style router mount prefixes"
```

---

### Task 4: WordPress REST namespace resolver

**Files:**

- Create: `mcp/src/surface/resolvers/wordpress.ts`
- Create: `mcp/test/unit/surface/resolvers/wordpress.test.ts`

**Interfaces:**

- Consumes: `RouteRecord` from `types.js`; `joinPath` from `surface/resolvers/node.js` (Task 3).
- Produces: `resolveWordpressRoutes(routes: RouteRecord[]): RouteRecord[]`.

`register_rest_route('myplugin/v1', '/items', [...])` serves at `/wp-json/myplugin/v1/items`. Task 2's extractor fills `RouteRecord.namespace` from `$NS` and `path_raw` from `$ROUTE`; this resolver combines them. When `namespace` is absent the route is flagged `path_partial` — we know where it is *not* served, which is all we honestly know.

- [ ] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/resolvers/wordpress.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { resolveWordpressRoutes } from '../../../../src/surface/resolvers/wordpress.js';
import type { RouteRecord } from '../../../../src/types.js';

function wpRoute(pathRaw: string, overrides: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
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

  it('leaves non-wp-rest routes untouched', () => {
    const other = wpRoute('/x', { framework: 'laravel' });
    expect(resolveWordpressRoutes([other])[0]?.path_resolved).toBe('/x');
    expect(resolveWordpressRoutes([other])[0]?.path_partial).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/resolvers/wordpress.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `mcp/src/surface/resolvers/wordpress.ts`:

```ts
/**
 * Resolve WordPress REST routes to their served path.
 *
 * `register_rest_route('myplugin/v1', '/items', ...)` is reachable at
 * `/wp-json/myplugin/v1/items`. Semgrep captures the namespace and the route
 * as two separate metavariables and cannot concatenate them, so the
 * extractor stores the namespace on `RouteRecord.namespace` and the route on
 * `path_raw`. This module is the only place that knows how they combine.
 *
 * Without a namespace we cannot know where the route is served, so it is
 * flagged `path_partial` rather than guessed at.
 */

import type { RouteRecord } from '../../types.js';
import { joinPath } from './node.js';

const WP_REST_PREFIX = '/wp-json';
const WP_FRAMEWORK = 'wp-rest';

export function resolveWordpressRoutes(routes: RouteRecord[]): RouteRecord[] {
  return routes.map((route) => {
    if (route.framework !== WP_FRAMEWORK) return route;

    const namespace = (route.namespace ?? '').trim().replace(/^\/+|\/+$/g, '');
    if (namespace.length === 0) return { ...route, path_partial: true };

    return {
      ...route,
      path_resolved: joinPath(`${WP_REST_PREFIX}/${namespace}`, route.path_raw),
      path_partial: false,
    };
  });
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/resolvers/wordpress.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
npm run build
git add src/surface/resolvers/wordpress.ts test/unit/surface/resolvers/wordpress.test.ts dist/
git commit -m "feat(surface): resolve WordPress REST namespaces to /wp-json paths"
```

---

### Task 5: Env-var and port collectors

**Files:**

- Create: `mcp/src/surface/collectors/envVars.ts`
- Create: `mcp/src/surface/collectors/ports.ts`
- Create: `mcp/test/unit/surface/collectors/envVars.test.ts`
- Create: `mcp/test/unit/surface/collectors/ports.test.ts`

**Interfaces:**

- Consumes: Semgrep JSON (same shape as Task 2) for env vars; the filesystem for ports.
- Produces: `collectEnvVars(semgrepJson: unknown): { name: string; file: string; line: number }[]` and `collectPorts(projectPath: string): { port: number; source: string }[]`.

Env vars come from the same Semgrep run (rules with `guardian_kind: 'env'`), so no extra process. Ports are read directly from `Dockerfile` and compose files, which are trivially parsed and not worth a Semgrep rule.

- [ ] **Step 1: Write the failing tests**

Create `mcp/test/unit/surface/collectors/envVars.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { collectEnvVars } from '../../../../src/surface/collectors/envVars.js';

function envMatch(name: string, file: string, line: number): unknown {
  return {
    check_id: 'guardian-env',
    path: file,
    start: { line },
    extra: {
      metadata: { guardian_kind: 'env' },
      metavars: { $NAME: { abstract_content: name } },
    },
  };
}

describe('collectEnvVars', () => {
  it('collects env var references from guardian_kind: env matches', () => {
    const result = collectEnvVars({
      results: [envMatch('DATABASE_URL', 'src/db.ts', 3), envMatch('API_KEY', 'src/api.ts', 8)],
    });
    expect(result).toEqual([
      { name: 'DATABASE_URL', file: 'src/db.ts', line: 3 },
      { name: 'API_KEY', file: 'src/api.ts', line: 8 },
    ]);
  });

  it('deduplicates by name, keeping the first occurrence', () => {
    const result = collectEnvVars({
      results: [envMatch('API_KEY', 'a.ts', 1), envMatch('API_KEY', 'b.ts', 9)],
    });
    expect(result).toEqual([{ name: 'API_KEY', file: 'a.ts', line: 1 }]);
  });

  it('strips surrounding quotes left by the metavariable capture', () => {
    const result = collectEnvVars({ results: [envMatch("'API_KEY'", 'a.ts', 1)] });
    expect(result[0]?.name).toBe('API_KEY');
  });

  it('returns an empty array for malformed input', () => {
    expect(collectEnvVars(null)).toEqual([]);
    expect(collectEnvVars({ results: [{ extra: {} }] })).toEqual([]);
  });
});
```

Create `mcp/test/unit/surface/collectors/ports.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectPorts } from '../../../../src/surface/collectors/ports.js';

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-ports-'));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

describe('collectPorts', () => {
  it('reads EXPOSE directives from a Dockerfile', () => {
    const dir = project({ Dockerfile: 'FROM node:20\nEXPOSE 3000\nEXPOSE 8080/tcp\n' });
    expect(collectPorts(dir)).toEqual([
      { port: 3000, source: 'Dockerfile' },
      { port: 8080, source: 'Dockerfile' },
    ]);
  });

  it('reads short-form compose port mappings', () => {
    const dir = project({
      'docker-compose.yml': 'services:\n  web:\n    ports:\n      - "8000:80"\n      - 9000\n',
    });
    expect(collectPorts(dir)).toEqual([
      { port: 8000, source: 'docker-compose.yml' },
      { port: 9000, source: 'docker-compose.yml' },
    ]);
  });

  it('reads long-form compose port mappings', () => {
    const dir = project({
      'compose.yml': 'services:\n  web:\n    ports:\n      - target: 80\n        published: 8080\n',
    });
    expect(collectPorts(dir)).toEqual([{ port: 8080, source: 'compose.yml' }]);
  });

  it('returns an empty array when no container files exist', () => {
    expect(collectPorts(project({ 'README.md': 'hi' }))).toEqual([]);
  });

  it('ignores unparseable port values instead of emitting NaN', () => {
    const dir = project({ Dockerfile: 'EXPOSE $PORT\nEXPOSE 3000\n' });
    expect(collectPorts(dir)).toEqual([{ port: 3000, source: 'Dockerfile' }]);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -- test/unit/surface/collectors/`
Expected: FAIL — modules not found.

- [ ] **Step 3: Write `envVars.ts`**

Create `mcp/src/surface/collectors/envVars.ts`:

```ts
/**
 * Environment variables the code reads, harvested from the same Semgrep run
 * that produces routes (rules tagged `guardian_kind: 'env'`).
 *
 * Deduplicated by name: a variable read in twelve places is one piece of
 * configuration, and the inventory is about what the app depends on, not how
 * often it asks for it.
 */

export function collectEnvVars(
  semgrepJson: unknown,
): { name: string; file: string; line: number }[] {
  const results = prop(semgrepJson, 'results');
  if (!Array.isArray(results)) return [];

  const seen = new Set<string>();
  const out: { name: string; file: string; line: number }[] = [];

  for (const raw of results) {
    const extra = prop(raw, 'extra');
    if (str(prop(extra, 'metadata'), 'guardian_kind') !== 'env') continue;

    const captured = str(prop(prop(extra, 'metavars'), '$NAME'), 'abstract_content');
    const file = str(raw, 'path');
    if (captured === undefined || file === undefined) continue;

    const name = captured.replace(/^['"`]|['"`]$/g, '');
    if (name.length === 0 || seen.has(name)) continue;
    seen.add(name);

    const line = numProp(prop(raw, 'start'), 'line') ?? 0;
    out.push({ name, file, line });
  }

  return out;
}

function prop(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  return (value as Record<string, unknown>)[key];
}

function str(value: unknown, key: string): string | undefined {
  const v = prop(value, key);
  return typeof v === 'string' ? v : undefined;
}

function numProp(value: unknown, key: string): number | undefined {
  const v = prop(value, key);
  return typeof v === 'number' ? v : undefined;
}
```

- [ ] **Step 4: Write `ports.ts`**

Create `mcp/src/surface/collectors/ports.ts`:

```ts
/**
 * Ports the project declares it will listen on.
 *
 * Read straight from `Dockerfile` and compose files rather than through a
 * Semgrep rule — these formats are line-oriented and a regex reads them more
 * reliably than a pattern matcher would.
 *
 * This is declaration-reading, not port scanning: nothing here touches the
 * network or inspects a running host.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const DOCKERFILES = ['Dockerfile', 'dockerfile'];
const COMPOSE_FILES = [
  'docker-compose.yml',
  'docker-compose.yaml',
  'compose.yml',
  'compose.yaml',
];

export function collectPorts(projectPath: string): { port: number; source: string }[] {
  const out: { port: number; source: string }[] = [];
  const seen = new Set<string>();

  const push = (port: number, source: string): void => {
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return;
    const key = `${port}:${source}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ port, source });
  };

  for (const name of DOCKERFILES) {
    for (const line of readLines(join(projectPath, name))) {
      const match = /^\s*EXPOSE\s+(.+)$/i.exec(line);
      if (match?.[1] === undefined) continue;
      for (const token of match[1].split(/\s+/)) {
        const portPart = token.split('/')[0];
        if (portPart === undefined) continue;
        const port = Number.parseInt(portPart, 10);
        if (Number.isNaN(port)) continue;
        push(port, name);
      }
    }
  }

  for (const name of COMPOSE_FILES) {
    for (const line of readLines(join(projectPath, name))) {
      // Long form: `published: 8080`
      const published = /^\s*published:\s*"?(\d+)"?\s*$/.exec(line);
      if (published?.[1] !== undefined) {
        push(Number.parseInt(published[1], 10), name);
        continue;
      }
      // Short form: `- "8000:80"` / `- 9000`
      const short = /^\s*-\s*"?(\d+)(?::\d+)?"?\s*$/.exec(line);
      if (short?.[1] !== undefined) {
        push(Number.parseInt(short[1], 10), name);
      }
    }
  }

  return out;
}

function readLines(path: string): string[] {
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, 'utf8').split(/\r?\n/);
  } catch {
    return [];
  }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm test -- test/unit/surface/collectors/`
Expected: PASS, 9 tests.

- [ ] **Step 6: Commit**

```bash
npm run build
git add src/surface/collectors/ test/unit/surface/collectors/ dist/
git commit -m "feat(surface): collect referenced env vars and declared ports"
```

---

### Task 6: The Semgrep rule pack

Data, not code. This is where new framework support lands forever after.

**Files:**

- Create: `configs/semgrep/routes.yml`
- Create: `mcp/test/unit/surface/rulePack.test.ts`

**Interfaces:**

- Consumes: nothing at runtime.
- Produces: the file `configs/semgrep/routes.yml`, whose every rule carries `metadata.guardian_kind` ∈ `{route, mount, import, env}` — the contract Task 2, Task 3 and Task 5 read.

The test validates the pack's structure — that every rule declares the metadata the extractor depends on — without running Semgrep. A rule that forgets `guardian_kind` would be silently dropped at runtime; this test turns that into a build failure.

- [ ] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/rulePack.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

const PACK_PATH = join(__dirname, '../../../../configs/semgrep/routes.yml');

interface Rule {
  id?: string;
  languages?: string[];
  severity?: string;
  message?: string;
  metadata?: Record<string, unknown>;
}

function rules(): Rule[] {
  const doc = parse(readFileSync(PACK_PATH, 'utf8')) as { rules?: Rule[] };
  return doc.rules ?? [];
}

const KINDS = new Set(['route', 'mount', 'import', 'env']);

describe('configs/semgrep/routes.yml', () => {
  it('parses and is non-empty', () => {
    expect(rules().length).toBeGreaterThan(0);
  });

  it('gives every rule a unique guardian- prefixed id', () => {
    const ids = rules().map((r) => r.id);
    expect(ids.every((id) => typeof id === 'string' && id.startsWith('guardian-'))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('tags every rule with a known guardian_kind — the extractor contract', () => {
    for (const rule of rules()) {
      expect(KINDS.has(String(rule.metadata?.guardian_kind))).toBe(true);
    }
  });

  it('gives every route rule a framework and a confidence', () => {
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      expect(typeof rule.metadata?.framework).toBe('string');
      expect(['high', 'medium', 'low']).toContain(rule.metadata?.confidence);
    }
  });

  it('keeps every rule at INFO severity so it never reads as a finding', () => {
    for (const rule of rules()) {
      expect(rule.severity).toBe('INFO');
    }
  });

  it('covers all 8 supported stacks with at least one route rule', () => {
    const covered = new Set(
      rules()
        .filter((r) => r.metadata?.guardian_kind === 'route')
        .flatMap((r) => r.languages ?? []),
    );
    for (const lang of ['javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp']) {
      expect(covered.has(lang), `no route rule covers ${lang}`).toBe(true);
    }
  });
});
```

`yaml` is neither declared in `mcp/package.json` nor resolvable transitively — verified before this plan was written. Install it as a **dev** dependency before running the test (it is used only by this test, never at runtime):

```bash
npm install --save-dev yaml
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/rulePack.test.ts`
Expected: FAIL — `ENOENT` on `configs/semgrep/routes.yml`.

- [ ] **Step 3: Write the rule pack**

Create `configs/semgrep/routes.yml`. Every rule uses `severity: INFO` and carries `metadata.guardian_kind`. The `mountable: true` flag opts a framework into the Node resolver from Task 3.

```yaml
# dev-guardian — attack-surface extraction rules.
#
# NOT a findings rule pack. `map_attack_surface` runs this with its own
# --config; the matches are consumed by mcp/src/surface/extract.ts and never
# reach the findings table. severity: INFO exists only because Semgrep
# requires the field.
#
# Contract with the extractor (mcp/src/surface/extract.ts):
#   metadata.guardian_kind: route | mount | import | env   (required)
#   route  → captures $PATH, optionally $METHOD
#   mount  → captures $PREFIX and $ROUTER
#   import → captures $SYMBOL and $MODULE
#   env    → captures $NAME
#
# Namespaced frameworks: register_rest_route takes the namespace and the route
# as two arguments. Semgrep cannot concatenate metavariables into a third, so
# the rule captures $NS and $ROUTE separately; extract.ts puts $NS on
# RouteRecord.namespace and $ROUTE on path_raw, and resolvers/wordpress.ts
# combines them into the served /wp-json path.

rules:
  # ---------- JavaScript / TypeScript ----------
  - id: guardian-route-express
    languages: [javascript, typescript]
    severity: INFO
    message: express/fastify route
    metadata:
      guardian_kind: route
      framework: express
      confidence: high
      mountable: true
    patterns:
      - pattern: $APP.$METHOD($PATH, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|options|head|all)$
      - metavariable-regex:
          metavariable: $PATH
          regex: ^['"`]/.*

  - id: guardian-mount-express
    languages: [javascript, typescript]
    severity: INFO
    message: express router mount
    metadata:
      guardian_kind: mount
      framework: express
    patterns:
      - pattern: $APP.use($PREFIX, $ROUTER)
      - metavariable-regex:
          metavariable: $PREFIX
          regex: ^['"`]/.*

  - id: guardian-import-esm
    languages: [javascript, typescript]
    severity: INFO
    message: module import
    metadata:
      guardian_kind: import
      framework: esm
    pattern-either:
      - pattern: import $SYMBOL from "$MODULE"
      - pattern: const $SYMBOL = require("$MODULE")

  - id: guardian-route-nestjs
    languages: [typescript]
    severity: INFO
    message: NestJS route
    metadata:
      guardian_kind: route
      framework: nestjs
      confidence: medium
      mountable: true
    pattern-either:
      - pattern: "@Get($PATH)"
      - pattern: "@Post($PATH)"
      - pattern: "@Put($PATH)"
      - pattern: "@Patch($PATH)"
      - pattern: "@Delete($PATH)"

  # ---------- Python ----------
  - id: guardian-route-flask
    languages: [python]
    severity: INFO
    message: Flask route
    metadata:
      guardian_kind: route
      framework: flask
      confidence: high
    pattern-either:
      - pattern: "@$APP.route($PATH, ...)"
      - pattern: "@$APP.route($PATH)"

  - id: guardian-route-fastapi
    languages: [python]
    severity: INFO
    message: FastAPI route
    metadata:
      guardian_kind: route
      framework: fastapi
      confidence: high
    patterns:
      - pattern: "@$APP.$METHOD($PATH, ...)"
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|options|head)$

  - id: guardian-route-django
    languages: [python]
    severity: INFO
    message: Django URL pattern
    metadata:
      guardian_kind: route
      framework: django
      confidence: medium
    pattern-either:
      - pattern: path($PATH, ...)
      - pattern: re_path($PATH, ...)

  # ---------- PHP / WordPress ----------
  - id: guardian-route-wp-rest
    languages: [php]
    severity: INFO
    message: WordPress REST route
    metadata:
      guardian_kind: route
      framework: wp-rest
      confidence: high
    pattern: register_rest_route($NS, $ROUTE, ...)

  - id: guardian-route-laravel
    languages: [php]
    severity: INFO
    message: Laravel route
    metadata:
      guardian_kind: route
      framework: laravel
      confidence: high
    patterns:
      - pattern: Route::$METHOD($PATH, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|options|any)$

  # ---------- Go ----------
  - id: guardian-route-go-nethttp
    languages: [go]
    severity: INFO
    message: net/http handler
    metadata:
      guardian_kind: route
      framework: net-http
      confidence: medium
    pattern-either:
      - pattern: http.HandleFunc($PATH, ...)
      - pattern: $MUX.HandleFunc($PATH, ...)

  - id: guardian-route-go-gin
    languages: [go]
    severity: INFO
    message: Gin route
    metadata:
      guardian_kind: route
      framework: gin
      confidence: medium
    patterns:
      - pattern: $R.$METHOD($PATH, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)$

  # ---------- Rust ----------
  - id: guardian-route-rust-actix
    languages: [rust]
    severity: INFO
    message: Actix/Rocket route attribute
    metadata:
      guardian_kind: route
      framework: actix
      confidence: low
    pattern-either:
      - pattern: "#[get($PATH)]"
      - pattern: "#[post($PATH)]"
      - pattern: "#[put($PATH)]"
      - pattern: "#[patch($PATH)]"
      - pattern: "#[delete($PATH)]"

  # ---------- Ruby ----------
  - id: guardian-route-rails
    languages: [ruby]
    severity: INFO
    message: Rails / Sinatra route
    metadata:
      guardian_kind: route
      framework: rails
      confidence: low
    patterns:
      - pattern: $METHOD $PATH
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete)$

  # ---------- Java ----------
  - id: guardian-route-spring
    languages: [java]
    severity: INFO
    message: Spring MVC mapping
    metadata:
      guardian_kind: route
      framework: spring
      confidence: medium
    pattern-either:
      - pattern: "@GetMapping($PATH)"
      - pattern: "@PostMapping($PATH)"
      - pattern: "@PutMapping($PATH)"
      - pattern: "@PatchMapping($PATH)"
      - pattern: "@DeleteMapping($PATH)"
      - pattern: "@RequestMapping($PATH)"

  # ---------- C# / .NET ----------
  - id: guardian-route-aspnet-minimal
    languages: [csharp]
    severity: INFO
    message: ASP.NET minimal API route
    metadata:
      guardian_kind: route
      framework: aspnet-minimal
      confidence: high
    patterns:
      - pattern: $APP.$METHOD($PATH, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^Map(Get|Post|Put|Patch|Delete)$

  - id: guardian-route-aspnet-attribute
    languages: [csharp]
    severity: INFO
    message: ASP.NET attribute route
    metadata:
      guardian_kind: route
      framework: aspnet
      confidence: medium
    pattern-either:
      - pattern: "[HttpGet($PATH)]"
      - pattern: "[HttpPost($PATH)]"
      - pattern: "[HttpPut($PATH)]"
      - pattern: "[HttpPatch($PATH)]"
      - pattern: "[HttpDelete($PATH)]"

  # ---------- Environment variables (all stacks) ----------
  - id: guardian-env-node
    languages: [javascript, typescript]
    severity: INFO
    message: environment variable read
    metadata:
      guardian_kind: env
    pattern-either:
      - pattern: process.env.$NAME
      - pattern: process.env[$NAME]

  - id: guardian-env-python
    languages: [python]
    severity: INFO
    message: environment variable read
    metadata:
      guardian_kind: env
    pattern-either:
      - pattern: os.environ[$NAME]
      - pattern: os.environ.get($NAME, ...)
      - pattern: os.getenv($NAME, ...)

  - id: guardian-env-php
    languages: [php]
    severity: INFO
    message: environment variable read
    metadata:
      guardian_kind: env
    pattern-either:
      - pattern: getenv($NAME)
      - pattern: $_ENV[$NAME]

  - id: guardian-env-dotnet
    languages: [csharp]
    severity: INFO
    message: environment variable read
    metadata:
      guardian_kind: env
    pattern: Environment.GetEnvironmentVariable($NAME)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/rulePack.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add ../configs/semgrep/routes.yml test/unit/surface/rulePack.test.ts package.json package-lock.json
git commit -m "feat(surface): add the routes.yml semgrep extraction pack"
```

---

### Task 7: The `map_attack_surface` tool

Orchestration: cache check, Semgrep invocation, pipeline, coverage report, persistence.

**Files:**

- Create: `mcp/src/tools/mapAttackSurface.ts`
- Create: `mcp/test/integration/surfaceTools.test.ts`

**Interfaces:**

- Consumes: `extractSurface` (Task 2), `resolveNodeMounts` + `ImportRecord` (Task 3), `resolveWordpressRoutes` (Task 4), `collectEnvVars` + `collectPorts` (Task 5), `SurfaceRepo` via `ctx.storage.surface` (Task 1), `configs/semgrep/routes.yml` (Task 6). Also `scannerAvailable`, `ensureReportDir`, `readJsonSafe` from `tools/scanHelpers.js`; `runProcess` from `runners/processRunner.js`; `computeTreeHash` from `treeHash/computeTreeHash.js`; `resolveProjectPath` from `platform/projectPath.js`; `ProjectPath`, `Force` from `schemas.js`.
- Produces: a registered `ToolModule` named `map_attack_surface`.

The tool is standalone (not built with `makeScanTool`) for the same reason `detect_stack` is: its output is structured metadata, not `Finding`s, and it must not create a row in `scans`.

- [ ] **Step 1: Write the failing integration test**

Create `mcp/test/integration/surfaceTools.test.ts`:

```ts
/**
 * Mocks `scannerAvailable` and `runProcess` so the whole tool runs without
 * Semgrep installed, following the pattern in securityTools.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn(), readJsonSafe: vi.fn() };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { readJsonSafe, scannerAvailable } from '../../src/tools/scanHelpers.js';
import { runProcess, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { TOOLS } from '../../src/tools/index.js';
import type { PluginContext } from '../../src/context.js';
import '../../src/tools/mapAttackSurface.js';

const SEMGREP_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'guardian-route-express',
      path: 'src/routes/users.ts',
      start: { line: 12 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: { $METHOD: { abstract_content: 'get' }, $PATH: { abstract_content: '/users' } },
      },
    },
  ],
});

function makeCtx(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool() {
  const found = TOOLS.find((t) => t.name === 'map_attack_surface');
  if (!found) throw new Error('map_attack_surface is not registered');
  return found;
}

/** ProcessRunResult has five required fields — a partial mock will not type-check. */
function okRun(outcome: ProcessRunResult['outcome'] = 'completed'): ProcessRunResult {
  return { outcome, exitCode: outcome === 'completed' ? 0 : 1, stdout: '', stderr: '', truncated: false };
}

describe('map_attack_surface', () => {
  beforeEach(() => {
    vi.mocked(scannerAvailable).mockReset();
    vi.mocked(readJsonSafe).mockReset();
    vi.mocked(runProcess).mockReset();
  });

  it('extracts, resolves and persists a snapshot', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      routes_total: number;
      snapshot_id: number;
      sample: { path_resolved: string }[];
    };

    expect(result.ok).toBe(true);
    expect(result.routes_total).toBe(1);
    expect(result.sample[0]?.path_resolved).toBe('/users');
    expect(ctx.storage.surface.getById(result.snapshot_id)?.snapshot.routes).toHaveLength(1);
  });

  it('persists NOTHING when semgrep is unavailable', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      missing_tools: string[];
      snapshot_id: number | null;
    };

    expect(result.missing_tools).toContain('semgrep');
    expect(result.snapshot_id).toBeNull();
    // The critical assertion: a zero-route snapshot must never be written,
    // or scan_dast would later read "this app exposes nothing".
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });

  it('reports no_rules for a detected language the pack does not cover', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results: [] }));

    const ctx = makeCtx();
    ctx.storage.stack.insert({
      project_path: '/p',
      snapshot: {
        os: 'linux', arch: 'x64', languages: ['elixir'], package_managers: [],
        frameworks: [], existing_tools: [], has_docker: false, has_compose: false,
        has_terraform: false, has_kubernetes: false, has_ansible: false,
        has_github_actions: false, has_gitlab_ci: false,
      },
    });

    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      coverage: { language: string; status: string }[];
    };

    expect(result.coverage.find((c) => c.language === 'elixir')?.status).toBe('no_rules');
  });

  it('returns the cached snapshot when the tree hash is unchanged', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    const first = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number;
    };
    const second = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(second.snapshot_id).toBe(first.snapshot_id);
    expect(second.tools_run[0]?.reason).toBe('cached');
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(1);
  });

  it('persists the snapshot when semgrep fails but still emitted parseable JSON', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun('failed'));
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      tools_run: { status: string }[];
    };

    // Partial data is still useful — the failed tools_run entry carries the
    // warning. This is the one failure mode where we DO persist.
    expect(result.snapshot_id).not.toBeNull();
    expect(result.tools_run[0]?.status).toBe('failed');
    expect(ctx.storage.surface.getLatest()).not.toBeNull();
  });

  it('returns a domain error for an unusable project_path', async () => {
    const ctx = makeCtx();
    const result = (await tool().handler(
      { project_path: join(tmpdir(), 'guardian-does-not-exist-xyz') },
      ctx,
    )) as { ok: boolean; error?: { code: string } };

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('not_a_git_repo');
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/integration/surfaceTools.test.ts`
Expected: FAIL — `Cannot find module '../../src/tools/mapAttackSurface.js'`.

- [ ] **Step 3: Write the tool**

Create `mcp/src/tools/mapAttackSurface.ts`:

```ts
/**
 * `map_attack_surface` — static inventory of what the application exposes.
 *
 * Standalone (no scan-tool factory): the output is structured metadata, not
 * Findings, and it must not create a row in `scans`. Same shape as
 * `detect_stack`.
 *
 * Failure policy: if Semgrep cannot run, NOTHING is persisted. A zero-route
 * snapshot written by a failed run would later be read by scan_dast and
 * risk_score as "this application exposes nothing" — the inverse of the
 * truth. "Zero because the scan failed" and "zero because there are none"
 * must stay distinguishable.
 */

import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { collectEnvVars } from '../surface/collectors/envVars.js';
import { collectPorts } from '../surface/collectors/ports.js';
import { extractSurface } from '../surface/extract.js';
import { resolveNodeMounts, type ImportRecord } from '../surface/resolvers/node.js';
import { resolveWordpressRoutes } from '../surface/resolvers/wordpress.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type {
  AttackSurfaceSnapshot,
  CoverageEntry,
  RouteRecord,
  ToolResult,
  ToolRun,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';

const SAMPLE_SIZE = 20;
const WEBHOOK_PATTERN = /webhook|callback|hook/i;

/** Languages the rule pack covers, for honest `no_rules` reporting. */
const COVERED_LANGUAGES = new Set([
  'javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp',
]);

const tool: ToolModule = {
  name: 'map_attack_surface',
  title: 'Map the application attack surface',
  description:
    'Statically extract the externally reachable surface of the project — HTTP routes ' +
    '(method, path, params, auth hint), referenced environment variables, and declared ' +
    'container ports — across all supported stacks. Persists a snapshot readable via ' +
    'guardian://surface/latest. Returns a summary plus a 20-route sample; read the ' +
    'resource for the full list.',
  inputSchema: {
    project_path: ProjectPath,
    force: Force,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; force?: boolean };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // `not_a_git_repo` is what detect_stack returns for an unusable
    // project_path (detectStack.ts:45-49), even though resolveProjectPath
    // actually rejects missing / non-directory / root-or-home paths. Keeping
    // the same code here means hosts and skills handle one failure, not two.
    // Do not "fix" this in isolation — it would desync the two tools.
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const treeHash = await computeTreeHash(projectPath);

  if (inp.force !== true) {
    const cached = ctx.storage.surface.getByTreeHash(treeHash);
    if (cached) return summarize(cached.snapshot, cached.id, [
      { name: 'semgrep', status: 'skipped', reason: 'cached' },
    ]);
  }

  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin === null) {
    return {
      ok: true,
      routes_total: 0,
      by_language: [],
      coverage: [],
      snapshot_id: null,
      sample: [],
      env_vars_total: 0,
      ports: [],
      tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['semgrep'],
      note:
        'Semgrep is not installed, so no surface was mapped and nothing was persisted. ' +
        'Run install_toolchain, then retry.',
    };
  }

  const reportDir = ensureReportDir(projectPath, treeHash, 'surface');
  const outFile = join(reportDir, 'surface.json');
  const rulesPath = join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml');

  const run = await runProcess({
    command: 'semgrep',
    args: [
      '--config', rulesPath,
      '--json', '--output', outFile,
      '--quiet', '--no-git-ignore',
      projectPath,
    ],
    cwd: projectPath,
  });

  const raw = readJsonSafe(outFile);
  if (raw === null) {
    return {
      ok: true,
      routes_total: 0,
      by_language: [],
      coverage: [],
      snapshot_id: null,
      sample: [],
      env_vars_total: 0,
      ports: [],
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'no_output' }],
      missing_tools: [],
      note: 'Semgrep produced no parseable output; nothing was persisted.',
    };
  }

  const parsed: unknown = JSON.parse(raw);
  const toolRun: ToolRun = {
    name: 'semgrep',
    status: run.outcome === 'completed' ? 'ok' : 'failed',
  };

  const snapshot = buildSnapshot(parsed, projectPath, ctx, [toolRun]);
  const persisted = ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot,
  });

  return summarize(snapshot, persisted.id, [toolRun]);
}

function buildSnapshot(
  parsed: unknown,
  projectPath: string,
  ctx: PluginContext,
  toolsRun: ToolRun[],
): AttackSurfaceSnapshot {
  const { routes, mounts } = extractSurface(parsed);
  const imports = extractImports(parsed);

  const resolved = resolveWordpressRoutes(resolveNodeMounts(routes, mounts, imports));

  return {
    routes: resolved,
    env_vars: collectEnvVars(parsed),
    ports: collectPorts(projectPath),
    webhooks: resolved.filter((r) => WEBHOOK_PATTERN.test(r.path_resolved)),
    coverage: buildCoverage(resolved, ctx),
    tools_run: toolsRun,
    missing_tools: [],
  };
}

/** `guardian_kind: 'import'` matches, needed by the Node mount resolver. */
function extractImports(parsed: unknown): ImportRecord[] {
  const results = (parsed as { results?: unknown }).results;
  if (!Array.isArray(results)) return [];

  const out: ImportRecord[] = [];
  for (const raw of results) {
    const record = raw as {
      path?: string;
      extra?: {
        metadata?: { guardian_kind?: string };
        metavars?: Record<string, { abstract_content?: string }>;
      };
    };
    if (record.extra?.metadata?.guardian_kind !== 'import') continue;
    const symbol = record.extra.metavars?.['$SYMBOL']?.abstract_content;
    const modulePath = record.extra.metavars?.['$MODULE']?.abstract_content;
    const file = record.path;
    if (symbol === undefined || modulePath === undefined || file === undefined) continue;
    out.push({ symbol, module_file: resolveModuleFile(file, modulePath), file });
  }
  return out;
}

/**
 * Turn a specifier like `./routes/users` (imported from `src/app.ts`) into
 * the project-relative file `src/routes/users.ts`. Extension-less specifiers
 * are probed against the extensions Node resolves.
 */
function resolveModuleFile(importingFile: string, specifier: string): string {
  if (!specifier.startsWith('.')) return specifier;
  const dir = importingFile.split('/').slice(0, -1).join('/');
  const parts = `${dir}/${specifier}`.split('/');
  const stack: string[] = [];
  for (const part of parts) {
    if (part === '.' || part === '') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const base = stack.join('/');
  return /\.[cm]?[jt]sx?$/.test(base) ? base : `${base}.ts`;
}

function buildCoverage(routes: RouteRecord[], ctx: PluginContext): CoverageEntry[] {
  const detected = ctx.storage.stack.getLatest()?.snapshot.languages ?? [];
  const languages = new Set<string>([...detected, ...routes.map((r) => r.language)]);
  languages.delete('unknown');

  const entries: CoverageEntry[] = [];
  for (const language of [...languages].sort()) {
    const found = routes.filter((r) => r.language === language).length;
    const hasRules = COVERED_LANGUAGES.has(language);
    entries.push({
      language,
      detected: detected.includes(language),
      routes_found: found,
      status: !hasRules ? 'no_rules' : found > 0 ? 'ok' : 'no_matches',
    });
  }
  return entries;
}

function summarize(
  snapshot: AttackSurfaceSnapshot,
  snapshotId: number,
  toolsRun: ToolRun[],
): ToolResult<Record<string, unknown>> {
  const byLanguage = new Map<string, number>();
  for (const route of snapshot.routes) {
    byLanguage.set(route.language, (byLanguage.get(route.language) ?? 0) + 1);
  }

  return {
    ok: true,
    routes_total: snapshot.routes.length,
    by_language: [...byLanguage].map(([language, routes]) => ({ language, routes })),
    coverage: snapshot.coverage,
    snapshot_id: snapshotId,
    sample: snapshot.routes.slice(0, SAMPLE_SIZE),
    env_vars_total: snapshot.env_vars.length,
    ports: snapshot.ports,
    webhooks_total: snapshot.webhooks.length,
    tools_run: toolsRun,
    missing_tools: snapshot.missing_tools,
  };
}
```

- [ ] **Step 4: Register the tool**

In `mcp/src/registerAll.ts`, add after the `scanSkill` import:

```ts
// Attack surface (Phase 18):
import './tools/mapAttackSurface.js';
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test -- test/integration/surfaceTools.test.ts`
Expected: PASS, 6 tests. If `toolSurface.test.ts` now fails, that is expected — Task 8 updates the snapshot.

- [ ] **Step 6: Commit**

```bash
npm run build
git add src/tools/mapAttackSurface.ts src/registerAll.ts test/integration/surfaceTools.test.ts dist/
git commit -m "feat(surface): add the map_attack_surface tool"
```

---

### Task 8: Resources, surface snapshot, and docs

**Files:**

- Create: `mcp/src/resources/surface.ts`
- Modify: `mcp/src/registerAll.ts`
- Modify: `mcp/test/integration/toolSurface.test.ts` (snapshot expectations)
- Modify: `README.md`, `CHANGELOG.md`

**Interfaces:**

- Consumes: `ctx.storage.surface` (Task 1), `registerResourceModule` from `resources/index.js`.
- Produces: resources `guardian-surface-latest` and `guardian-surface-by-id`.

- [ ] **Step 1: Write the failing test**

Append to `mcp/test/integration/surfaceTools.test.ts`:

```ts
import { RESOURCES } from '../../src/resources/index.js';
import '../../src/resources/surface.js';

describe('guardian://surface resources', () => {
  function resource(name: string) {
    const found = RESOURCES.find((r) => r.name === name);
    if (!found) throw new Error(`${name} is not registered`);
    return found;
  }

  it('returns { snapshot: null } before anything is captured', async () => {
    const ctx = makeCtx();
    const { json } = await resource('guardian-surface-latest').handler(
      new URL('guardian://surface/latest'),
      {},
      ctx,
    );
    expect(json).toEqual({ snapshot: null });
  });

  it('serves the latest snapshot with its full route list', async () => {
    const ctx = makeCtx();
    ctx.storage.surface.insert({
      project_path: '/p',
      tree_hash: 'h',
      snapshot: {
        routes: [], env_vars: [], ports: [], webhooks: [], coverage: [],
        tools_run: [], missing_tools: [],
      },
    });
    const { json } = await resource('guardian-surface-latest').handler(
      new URL('guardian://surface/latest'),
      {},
      ctx,
    );
    expect(json).toHaveProperty('captured_at');
    expect(json).toHaveProperty('snapshot.routes');
  });

  it('serves a snapshot by id and nulls an unknown id', async () => {
    const ctx = makeCtx();
    const inserted = ctx.storage.surface.insert({
      project_path: '/p',
      tree_hash: 'h',
      snapshot: {
        routes: [], env_vars: [], ports: [], webhooks: [], coverage: [],
        tools_run: [], missing_tools: [],
      },
    });

    const byId = resource('guardian-surface-by-id');
    const hit = await byId.handler(
      new URL(`guardian://surface/${inserted.id}`),
      { id: String(inserted.id) },
      ctx,
    );
    expect(hit.json).toHaveProperty('snapshot.routes');

    const miss = await byId.handler(new URL('guardian://surface/999'), { id: '999' }, ctx);
    expect(miss.json).toEqual({ snapshot: null });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/integration/surfaceTools.test.ts`
Expected: FAIL — `Cannot find module '../../src/resources/surface.js'`.

- [ ] **Step 3: Write the resources**

Create `mcp/src/resources/surface.ts`:

```ts
/**
 * Attack-surface resources:
 *   - guardian://surface/latest → the most recent snapshot
 *   - guardian://surface/{id}   → a specific snapshot
 *
 * The full route list lives here rather than in the tool result: a project
 * with hundreds of routes would exhaust the agent's context window if every
 * `map_attack_surface` call returned them all.
 *
 * Missing data is not an error — both return `{ snapshot: null }`.
 */

import { registerResourceModule } from './index.js';

registerResourceModule({
  name: 'guardian-surface-latest',
  uri: 'guardian://surface/latest',
  description:
    'Latest attack-surface snapshot from `map_attack_surface`: every route with its ' +
    'resolved path, method, params and auth hint, plus env vars, declared ports and ' +
    'per-language coverage. Returns `{ snapshot: null }` when none exists yet.',
  handler: async (_uri, _params, ctx) => {
    const latest = ctx.storage.surface.getLatest();
    if (!latest) return { json: { snapshot: null } };
    return {
      json: {
        snapshot_id: latest.id,
        captured_at: latest.captured_at,
        snapshot: latest.snapshot,
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-surface-by-id',
  uri: 'guardian://surface/{id}',
  isTemplate: true,
  description:
    'A specific attack-surface snapshot by id, as returned in `snapshot_id` by ' +
    '`map_attack_surface`. Returns `{ snapshot: null }` for an unknown id.',
  handler: async (_uri, params, ctx) => {
    const rawId = Array.isArray(params['id']) ? params['id'][0] : params['id'];
    const id = Number.parseInt(String(rawId ?? ''), 10);
    if (Number.isNaN(id)) return { json: { snapshot: null } };

    const found = ctx.storage.surface.getById(id);
    if (!found) return { json: { snapshot: null } };
    return {
      json: {
        snapshot_id: found.id,
        captured_at: found.captured_at,
        snapshot: found.snapshot,
      },
    };
  },
});
```

- [ ] **Step 4: Register the resources**

In `mcp/src/registerAll.ts`, add to the resources block:

```ts
import './resources/surface.js';
```

- [ ] **Step 5: Update the tool-surface snapshot**

Run: `npm test -- test/integration/toolSurface.test.ts`

Read the failure output, then update the expected tool and resource lists in that test to include `map_attack_surface`, `guardian-surface-latest` and `guardian-surface-by-id`. This is a deliberate, reviewed change to the public MCP surface — do not blanket-update a snapshot without reading what changed.

- [ ] **Step 6: Run the full suite, then the coverage gate**

Run: `npm test`
Expected: PASS — 402 pre-existing tests plus everything this plan added, 0 failures.

Run: `npm run test:coverage`
Expected: PASS — no threshold violation (statements 70, branches 62, functions 72, lines 70). This is the only run in the plan that checks coverage. If it fails, the gap is in whichever module this plan added without matching tests.

- [ ] **Step 7: Update the docs**

In `README.md`, in all three language sections:

- Change "50 tools" / "51 tools" to the new count and "16 resources" to 18.
- Add a bullet to the tool groups: **Attack surface (1)** — `map_attack_surface`: static inventory of routes, env vars and declared ports across all 8 stacks, with per-language coverage reporting.
- Add `guardian://surface/latest` and `guardian://surface/{id}` to the Resources line.

In `CHANGELOG.md`, add an entry under a new version heading describing the tool, the `surface_snapshots` table, and the two resources.

Markdownlint must stay clean for `README.md`: run `npx markdownlint-cli2 README.md` if available.

- [ ] **Step 8: Build and commit**

```bash
npm run build
git add src/resources/surface.ts src/registerAll.ts test/integration/ dist/ ../README.md ../CHANGELOG.md
git commit -m "feat(surface): serve attack-surface snapshots as MCP resources"
```

---

## Definition of Done

- [ ] `map_attack_surface` is registered and appears in the tool-surface snapshot.
- [ ] `configs/semgrep/routes.yml` covers all 8 stacks; uncovered frameworks report `no_rules`.
- [ ] Prefix resolution works for Express-style mounting and WP REST namespaces.
- [ ] `surface_snapshots` persists across runs; both resources serve.
- [ ] A run with Semgrep unavailable persists nothing and explains why.
- [ ] `npm test` passes with Semgrep absent from the machine; `npm run test:coverage` passes its thresholds.
- [ ] `mcp/dist/` rebuilt and staged in every commit that touched TypeScript.
- [ ] README tool/resource counts and CHANGELOG updated.
