/**
 * Attack-surface snapshots repository.
 *
 * Each successful `map_attack_surface` run persists one row. The resources
 * `guardian://surface/latest` and `guardian://surface/{id}` read from here,
 * and `findCacheHit` backs the tool's cache check.
 *
 * Mirrors `stackRepo.ts`; the additions are `getById` (the templated
 * resource needs it) and `findCacheHit` (the cache).
 *
 * The cache used to be `getByTreeHash`: the newest snapshot with that tree
 * hash, from ANY project, of ANY age, mapped with ANY rule pack. Two projects
 * whose trees hash the same (two empty directories, two checkouts of one
 * commit) were served each other's routes, and a snapshot taken with a
 * routes.yml that has since been fixed was served forever. A snapshot is now
 * stored under a `cache_key` (`treeHash/cacheKey.ts#surfaceCacheKey`) and
 * reused only under that exact key, within a freshness window.
 */

import type { DB, Statement } from './db.js';
import type { AttackSurfaceSnapshot, ExternalImportEntry, ExternalImports, RouteRecord } from '../types.js';
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
  /** What the snapshot was computed from; omitted (NULL) never matches a lookup. */
  cache_key?: string;
}

export interface PersistedSurfaceSnapshot {
  id: number;
  project_path: string;
  captured_at: string;
  tree_hash: string;
  snapshot: AttackSurfaceSnapshot;
}

/**
 * Snapshots kept per project; each insert deletes that project's older ones.
 * The table grew without bound — every forced or cache-missing
 * `map_attack_surface` run added a row of routes, imports and third-party
 * imports. What reads an older snapshot was checked first: `scan_dast`,
 * `validate_finding`, `prioritize_findings`, `export_vex` and
 * `guardian://surface/latest` read only the newest for their project, and the
 * cache only reuses the newest under its key; the spec diff lives inside each
 * snapshot. The one reader of an older row is `guardian://surface/{id}` —
 * a verdict stores its `snapshot_id` as provenance — which answers
 * `{ snapshot: null }` once that row is gone.
 */
export const SURFACE_SNAPSHOTS_KEPT = 10;

const EMPTY_SNAPSHOT: AttackSurfaceSnapshot = {
  routes: [],
  env_vars: [],
  ports: [],
  webhooks: [],
  coverage: [],
  tools_run: [],
  missing_tools: [],
  spec_files: [],
  spec_diff: null,
  imports: [],
};

export class SurfaceRepo {
  private readonly insertStmt: Statement<[string, string, string, string, string | null]>;
  private readonly getLatestStmt: Statement<[], SurfaceRow>;
  private readonly getLatestForProjectStmt: Statement<[string], SurfaceRow>;
  private readonly getByIdStmt: Statement<[number], SurfaceRow>;
  private readonly findCacheStmt: Statement<[string, string, string, string], SurfaceRow>;
  private readonly listRecentStmt: Statement<[number], SurfaceRow>;
  private readonly pruneStmt: Statement<[string, string, number]>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json, cache_key)
      VALUES (?, ?, ?, ?, ?)
    `);
    this.getLatestStmt = db.prepare<[], SurfaceRow>(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT 1
    `);
    this.getLatestForProjectStmt = db.prepare<[string], SurfaceRow>(`
      SELECT * FROM surface_snapshots WHERE project_path = ? ORDER BY id DESC LIMIT 1
    `);
    this.getByIdStmt = db.prepare<[number], SurfaceRow>(`
      SELECT * FROM surface_snapshots WHERE id = ?
    `);
    // The key already covers project and tree; both are matched again
    // explicitly so the statement says what it means. A NULL key (rows
    // written before migration 006) never equals anything.
    this.findCacheStmt = db.prepare<[string, string, string, string], SurfaceRow>(`
      SELECT * FROM surface_snapshots
      WHERE cache_key = ? AND project_path = ? AND tree_hash = ? AND captured_at >= ?
      ORDER BY id DESC LIMIT 1
    `);
    this.listRecentStmt = db.prepare<[number], SurfaceRow>(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT ?
    `);
    this.pruneStmt = db.prepare<[string, string, number]>(`
      DELETE FROM surface_snapshots
      WHERE project_path = ?
        AND id NOT IN (
          SELECT id FROM surface_snapshots WHERE project_path = ? ORDER BY id DESC LIMIT ?
        )
    `);
  }

  insert(input: InsertSurfaceSnapshotInput): PersistedSurfaceSnapshot {
    const capturedAt = nowIso();
    const info = this.insertStmt.run(
      input.project_path,
      capturedAt,
      input.tree_hash,
      JSON.stringify(input.snapshot),
      input.cache_key ?? null,
    );
    // Retention: see SURFACE_SNAPSHOTS_KEPT. After the insert, so the new
    // row always survives its own prune.
    this.pruneStmt.run(input.project_path, input.project_path, SURFACE_SNAPSHOTS_KEPT);
    return {
      id: Number(info.lastInsertRowid),
      project_path: input.project_path,
      captured_at: capturedAt,
      tree_hash: input.tree_hash,
      snapshot: input.snapshot,
    };
  }

  /**
   * The newest snapshot in the database, from ANY project. No production
   * caller: the `guardian://surface/latest` resource answers for the
   * server's own project (`getLatestForProject(serverProjectPath())`).
   *
   * Any consumer that relativizes paths against a specific project root,
   * keys anything by one, or TELLS THE CALLER it answered about their
   * project must use `getLatestForProject`: a snapshot of a different tree
   * relativizes into a different key space, so every comparison against it
   * silently answers "not found" rather than failing. `scan_dast`
   * (tools/scanDast.ts) used to call this method while its own refusal
   * message already claimed to be project-scoped — fixed alongside
   * `validate_finding`'s read, so this is no longer a mismatch to route
   * around, only a contract not to repeat.
   */
  getLatest(): PersistedSurfaceSnapshot | null {
    const row = this.getLatestStmt.get();
    return row ? rowToSnapshot(row) : null;
  }

  /**
   * The newest snapshot FOR ONE project. `project_path` is matched exactly,
   * against the value `map_attack_surface` persisted — which is
   * `resolveProjectPath()`'s output, the same normalisation every caller of
   * this method resolves its own argument through, so two callers naming the
   * same project agree on the string.
   */
  getLatestForProject(projectPath: string): PersistedSurfaceSnapshot | null {
    const row = this.getLatestForProjectStmt.get(projectPath);
    return row ? rowToSnapshot(row) : null;
  }

  getById(id: number): PersistedSurfaceSnapshot | null {
    const row = this.getByIdStmt.get(id);
    return row ? rowToSnapshot(row) : null;
  }

  /**
   * The newest snapshot stored under exactly `cache_key` for this project and
   * tree, captured no earlier than `freshThreshold` — see the module comment.
   */
  findCacheHit(args: {
    cache_key: string;
    project_path: string;
    tree_hash: string;
    freshThreshold: string;
  }): PersistedSurfaceSnapshot | null {
    const row = this.findCacheStmt.get(
      args.cache_key,
      args.project_path,
      args.tree_hash,
      args.freshThreshold,
    );
    return row ? rowToSnapshot(row) : null;
  }

  listRecent(limit = 10): PersistedSurfaceSnapshot[] {
    return this.listRecentStmt.all(limit).map(rowToSnapshot);
  }
}

function rowToSnapshot(row: SurfaceRow): PersistedSurfaceSnapshot {
  const parsed = parseJsonObject<Record<string, unknown>>(row.json, {});
  // `?? []` alone only catches a missing/null `routes` field — a row whose
  // `routes` is valid JSON but not an array (e.g. `{"routes": {}}`, from a
  // corrupted write) still reaches `.map` and throws a TypeError out of
  // getLatest()/getById(), i.e. out of the guardian://surface/* resource
  // handlers. This file's own convention (`parseJsonObject`) is to tolerate
  // malformed stored data rather than throw, so `routes` gets the same
  // treatment: anything that isn't an array reads back as no routes.
  const rawRoutes = parsed['routes'];
  const storedRoutes = Array.isArray(rawRoutes)
    ? (rawRoutes as Omit<RouteRecord, 'provenance'>[])
    : [];
  return {
    id: row.id,
    project_path: row.project_path,
    captured_at: row.captured_at,
    tree_hash: row.tree_hash,
    snapshot: {
      ...EMPTY_SNAPSHOT,
      ...(parsed as Partial<AttackSurfaceSnapshot>),
      // Snapshots written before provenance existed carry routes without it. A
      // snapshot is a point-in-time artifact and stale ones are history, so this
      // backfills on read rather than migrating: every pre-existing route came from
      // source extraction, because spec import did not exist yet. Typed without
      // `provenance` (rather than as `RouteRecord[]`) so the compiler does not
      // "know" every element already has it — otherwise it flags the fallback
      // below as dead code (TS2783), when the whole point is that it is live
      // for exactly the legacy rows that lack the field.
      routes: storedRoutes.map((r) => ({ provenance: 'code' as const, ...r })),
      // Validated, never trusted: an earlier shape of this field (a flat
      // list, written by a pre-release build) or a damaged one reads as
      // absent — the snapshot is then recomputed rather than read as "no
      // package is imported" — and an entry pointing at no file is dropped.
      external_imports: readExternalImports(parsed['external_imports']),
    },
  };
}

function readExternalImports(value: unknown): ExternalImports | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const rawFiles = record['files'];
  const rawPackages = record['packages'];
  if (!Array.isArray(rawFiles) || !Array.isArray(rawPackages)) return undefined;
  const files = rawFiles.filter((f): f is string => typeof f === 'string');
  if (files.length !== rawFiles.length) return undefined;
  const packages: ExternalImportEntry[] = [];
  for (const raw of rawPackages as unknown[]) {
    if (raw === null || typeof raw !== 'object') continue;
    const p = raw as Record<string, unknown>;
    const indices = p['files'];
    const count = p['file_count'];
    if (typeof p['specifier'] !== 'string' || typeof p['language'] !== 'string') continue;
    if (!Array.isArray(indices) || typeof count !== 'number') continue;
    const valid = indices.every((i) => Number.isInteger(i) && typeof i === 'number' && i >= 0 && i < files.length);
    if (!valid) continue;
    packages.push({
      specifier: p['specifier'],
      language: p['language'],
      files: indices as number[],
      file_count: Math.max(count, indices.length),
    });
  }
  return { files, packages };
}
