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
import type { AttackSurfaceSnapshot, RouteRecord } from '../types.js';
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
      routes: ((parsed['routes'] as Omit<RouteRecord, 'provenance'>[] | undefined) ?? []).map(
        (r) => ({ provenance: 'code' as const, ...r }),
      ),
    },
  };
}
