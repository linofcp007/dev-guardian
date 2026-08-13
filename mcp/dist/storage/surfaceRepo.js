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
import { nowIso, parseJsonObject } from './repoUtil.js';
const EMPTY_SNAPSHOT = {
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
    insertStmt;
    getLatestStmt;
    getLatestForProjectStmt;
    getByIdStmt;
    getByTreeHashStmt;
    listRecentStmt;
    constructor(db) {
        this.insertStmt = db.prepare(`
      INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
      VALUES (?, ?, ?, ?)
    `);
        this.getLatestStmt = db.prepare(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT 1
    `);
        this.getLatestForProjectStmt = db.prepare(`
      SELECT * FROM surface_snapshots WHERE project_path = ? ORDER BY id DESC LIMIT 1
    `);
        this.getByIdStmt = db.prepare(`
      SELECT * FROM surface_snapshots WHERE id = ?
    `);
        this.getByTreeHashStmt = db.prepare(`
      SELECT * FROM surface_snapshots WHERE tree_hash = ? ORDER BY id DESC LIMIT 1
    `);
        this.listRecentStmt = db.prepare(`
      SELECT * FROM surface_snapshots ORDER BY id DESC LIMIT ?
    `);
    }
    insert(input) {
        const capturedAt = nowIso();
        const info = this.insertStmt.run(input.project_path, capturedAt, input.tree_hash, JSON.stringify(input.snapshot));
        return {
            id: Number(info.lastInsertRowid),
            project_path: input.project_path,
            captured_at: capturedAt,
            tree_hash: input.tree_hash,
            snapshot: input.snapshot,
        };
    }
    /**
     * The newest snapshot in the database, from ANY project. Kept for the
     * callers whose contract is "whatever this server last mapped" — the
     * `guardian://surface/latest` resource and `scan_dast`'s route source.
     * A consumer that relativizes paths against a specific project root, or
     * keys anything by one, must use `getLatestForProject` instead: a snapshot
     * of a different tree relativizes into a different key space, and every
     * comparison against it silently answers "not found" rather than failing.
     */
    getLatest() {
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
    getLatestForProject(projectPath) {
        const row = this.getLatestForProjectStmt.get(projectPath);
        return row ? rowToSnapshot(row) : null;
    }
    getById(id) {
        const row = this.getByIdStmt.get(id);
        return row ? rowToSnapshot(row) : null;
    }
    getByTreeHash(treeHash) {
        const row = this.getByTreeHashStmt.get(treeHash);
        return row ? rowToSnapshot(row) : null;
    }
    listRecent(limit = 10) {
        return this.listRecentStmt.all(limit).map(rowToSnapshot);
    }
}
function rowToSnapshot(row) {
    const parsed = parseJsonObject(row.json, {});
    // `?? []` alone only catches a missing/null `routes` field — a row whose
    // `routes` is valid JSON but not an array (e.g. `{"routes": {}}`, from a
    // corrupted write) still reaches `.map` and throws a TypeError out of
    // getLatest()/getById(), i.e. out of the guardian://surface/* resource
    // handlers. This file's own convention (`parseJsonObject`) is to tolerate
    // malformed stored data rather than throw, so `routes` gets the same
    // treatment: anything that isn't an array reads back as no routes.
    const rawRoutes = parsed['routes'];
    const storedRoutes = Array.isArray(rawRoutes)
        ? rawRoutes
        : [];
    return {
        id: row.id,
        project_path: row.project_path,
        captured_at: row.captured_at,
        tree_hash: row.tree_hash,
        snapshot: {
            ...EMPTY_SNAPSHOT,
            ...parsed,
            // Snapshots written before provenance existed carry routes without it. A
            // snapshot is a point-in-time artifact and stale ones are history, so this
            // backfills on read rather than migrating: every pre-existing route came from
            // source extraction, because spec import did not exist yet. Typed without
            // `provenance` (rather than as `RouteRecord[]`) so the compiler does not
            // "know" every element already has it — otherwise it flags the fallback
            // below as dead code (TS2783), when the whole point is that it is live
            // for exactly the legacy rows that lack the field.
            routes: storedRoutes.map((r) => ({ provenance: 'code', ...r })),
        },
    };
}
//# sourceMappingURL=surfaceRepo.js.map