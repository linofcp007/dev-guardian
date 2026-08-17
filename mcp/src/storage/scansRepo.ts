/**
 * Scans repository — one row per scan invocation.
 *
 * Responsibilities live strictly at the persistence layer: every method here
 * maps directly to a SQL operation. Cache lookup, transition logic, and the
 * tree-hash freshness window all belong to the scan-tool factory upstream
 * (see [.specs/dev-guardian-mcp/design.md] → "Tool invocation flow").
 *
 * **`getLatestStmt` (the UNSCOPED "latest scan in the whole database" query)
 * excludes `create_fix_pr`'s own verification re-scans** — see
 * `findingsRepo.ts`'s own module comment (task-7-review.md I3) for the full
 * reasoning; the same contamination, the same fix, the same reason
 * `WORKTREE_PATH_EXCLUSION` is inlined here as a literal rather than
 * imported from `fixpr/worktree.ts` — see `findingsRepo.ts`'s own module
 * comment for why it is wrapped in `%` on both sides, not just trailing.
 * `getLatestForProject` needs no such exclusion: it is already scoped to an
 * exact `project_path`, which a worktree's path can never equal.
 */

import type { DB, Statement } from './db.js';
import type { ScanRecord, ScanStatus, ScanType, ToolRun } from '../types.js';
import { nowIso, parseJsonArray } from './repoUtil.js';

/** See the module comment. Wraps `fixpr/worktree.ts`'s `WORKTREE_DIR_PREFIX`. */
const WORKTREE_PATH_EXCLUSION = '%guardian-fixpr-wt-%';

interface ScanRow {
  id: string;
  scan_type: string;
  project_path: string;
  tree_hash: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  tools_run: string;
  missing_tools: string;
  report_dir: string | null;
  error: string | null;
  cached_from: string | null;
  meta: string;
}

export interface InsertScanInput {
  scan_id: string;
  scan_type: ScanType;
  project_path: string;
  tree_hash: string;
  report_dir?: string;
  meta?: Record<string, unknown>;
}

export interface FinalizeScanInput {
  scan_id: string;
  status: Extract<ScanStatus, 'completed' | 'failed' | 'cancelled'>;
  tools_run: ToolRun[];
  missing_tools: string[];
  report_dir?: string;
  meta?: Record<string, unknown>;
  error?: string;
}

export class ScansRepo {
  private readonly insertStmt: Statement<[
    string, string, string, string, string, string, string, string, string | null, string
  ]>;
  private readonly finalizeStmt: Statement<[
    string, string, string, string, string | null, string | null, string | null, string
  ]>;
  private readonly markCancelledStmt: Statement<[string, string]>;
  private readonly reapRunningStmt: Statement<[string]>;
  private readonly getByIdStmt: Statement<[string], ScanRow>;
  private readonly getLatestStmt: Statement<[], ScanRow>;
  private readonly getLatestForProjectStmt: Statement<[string], ScanRow>;
  private readonly listHistoryStmt: Statement<[number], ScanRow>;
  private readonly listHistoryForProjectStmt: Statement<[string, number], ScanRow>;
  private readonly findCacheStmt: Statement<[string, string, string], ScanRow>;
  private readonly attachCacheStmt: Statement<[string, string, string, string]>;

  constructor(db: DB) {
    this.insertStmt = db.prepare(`
      INSERT INTO scans (
        id, scan_type, project_path, tree_hash,
        started_at, status, tools_run, missing_tools, report_dir, meta
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.finalizeStmt = db.prepare(`
      UPDATE scans
      SET status = ?, finished_at = ?, tools_run = ?, missing_tools = ?,
          report_dir = COALESCE(?, report_dir), error = ?,
          meta = COALESCE(?, meta)
      WHERE id = ?
    `);

    this.markCancelledStmt = db.prepare(`
      UPDATE scans
      SET status = 'cancelled', finished_at = ?
      WHERE id = ? AND status = 'running'
    `);

    this.reapRunningStmt = db.prepare(`
      UPDATE scans
      SET status = 'failed', finished_at = ?, error = 'reaped on startup'
      WHERE status = 'running'
    `);

    this.getByIdStmt = db.prepare<[string], ScanRow>(`SELECT * FROM scans WHERE id = ?`);

    // rowid DESC is a tiebreaker for scans inserted in the same millisecond
    // (real risk on fast CI). It also guarantees "later insert wins" even if
    // a future migration drops millisecond resolution. `project_path NOT
    // LIKE …`: see this file's own module comment (task-7-review.md I3).
    this.getLatestStmt = db.prepare<[], ScanRow>(`
      SELECT * FROM scans
      WHERE status = 'completed' AND project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);

    // Identical predicate to getLatestStmt above, plus `project_path = ?` on
    // the WHERE clause — same relationship as surfaceRepo's / findingsRepo's
    // getLatestForProject / listOpenForProject siblings.
    this.getLatestForProjectStmt = db.prepare<[string], ScanRow>(`
      SELECT * FROM scans
      WHERE status = 'completed' AND project_path = ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);

    this.listHistoryStmt = db.prepare<[number], ScanRow>(`
      SELECT * FROM scans
      ORDER BY started_at DESC, rowid DESC
      LIMIT ?
    `);

    // Identical predicate to listHistoryStmt above, plus `project_path = ?` on
    // the WHERE clause — same relationship as getLatestForProjectStmt's own
    // pairing with getLatestStmt above. No `status` filter, matching
    // listHistory's own "any status" contract exactly: callers that need only
    // completed scans (e.g. the dashboard snapshot's "previous scan of the
    // same type") filter that in JS, the same way listHistory's own callers
    // already do.
    this.listHistoryForProjectStmt = db.prepare<[string, number], ScanRow>(`
      SELECT * FROM scans
      WHERE project_path = ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT ?
    `);

    this.findCacheStmt = db.prepare<[string, string, string], ScanRow>(`
      SELECT * FROM scans
      WHERE tree_hash = ? AND scan_type = ? AND status = 'completed' AND started_at >= ?
      ORDER BY started_at DESC, rowid DESC
      LIMIT 1
    `);

    this.attachCacheStmt = db.prepare(`
      INSERT OR REPLACE INTO tree_cache (tree_hash, scan_id, scan_type, computed_at)
      VALUES (?, ?, ?, ?)
    `);
  }

  insert(input: InsertScanInput): ScanRecord {
    const started = nowIso();
    this.insertStmt.run(
      input.scan_id,
      input.scan_type,
      input.project_path,
      input.tree_hash,
      started,
      'running',
      '[]',
      '[]',
      input.report_dir ?? null,
      JSON.stringify(input.meta ?? {}),
    );
    return {
      scan_id: input.scan_id,
      scan_type: input.scan_type,
      project_path: input.project_path,
      tree_hash: input.tree_hash,
      started_at: started,
      finished_at: null,
      status: 'running',
      tools_run: [],
      missing_tools: [],
      report_paths: input.report_dir ? [input.report_dir] : [],
    };
  }

  finalize(input: FinalizeScanInput): void {
    this.finalizeStmt.run(
      input.status,
      nowIso(),
      JSON.stringify(input.tools_run),
      JSON.stringify(input.missing_tools),
      input.report_dir ?? null,
      input.error ?? null,
      input.meta !== undefined ? JSON.stringify(input.meta) : null,
      input.scan_id,
    );
  }

  markCancelled(scanId: string): void {
    this.markCancelledStmt.run(nowIso(), scanId);
  }

  /**
   * Sweeps any scan left in `running` state by a previous server lifetime
   * (crash, kill -9). Called once on startup.
   */
  reapRunning(): number {
    const info = this.reapRunningStmt.run(nowIso());
    return info.changes;
  }

  getById(scanId: string): ScanRecord | null {
    const row = this.getByIdStmt.get(scanId);
    return row ? rowToRecord(row) : null;
  }

  /**
   * The latest completed scan in the WHOLE database, from ANY project — no
   * `project_path` filter. Correct for a caller with no project in scope
   * (most resources and tools here take no `project_path` input at all and
   * report on "whatever this server last scanned"). A caller that DID
   * resolve a `project_path` and attributes something to the scan it names
   * (e.g. `validate_finding`'s `findings_from_scan`) must use
   * `getLatestForProject` instead — see that method and
   * `findingsRepo.ts`'s `listOpen`/`listOpenForProject` for the identical
   * split.
   */
  getLatest(): ScanRecord | null {
    const row = this.getLatestStmt.get();
    return row ? rowToRecord(row) : null;
  }

  /** The latest completed scan FOR ONE project. Mirrors `surfaceRepo.ts`'s
   *  `getLatestForProject` and `findingsRepo.ts`'s `listOpenForProject`. */
  getLatestForProject(projectPath: string): ScanRecord | null {
    const row = this.getLatestForProjectStmt.get(projectPath);
    return row ? rowToRecord(row) : null;
  }

  listHistory(limit = 50): ScanRecord[] {
    return this.listHistoryStmt.all(limit).map(rowToRecord);
  }

  /**
   * `listHistory`, scoped to one project — never all scans filtered in JS,
   * which would silently truncate at whatever `limit` the caller used before
   * the JS-side filter even ran. Mirrors `getLatestForProject`'s relationship
   * to `getLatest`: same "this project" vs. "any project" split, for a
   * history list instead of a single latest row.
   */
  listHistoryForProject(projectPath: string, limit = 50): ScanRecord[] {
    return this.listHistoryForProjectStmt.all(projectPath, limit).map(rowToRecord);
  }

  /**
   * Returns the most recent completed scan of the given type whose tree_hash
   * matches and which started no earlier than `freshThreshold`. The factory
   * uses this to honour US-8 AC-2 (5-minute cache window).
   */
  findCacheHit(args: {
    tree_hash: string;
    scan_type: ScanType;
    freshThreshold: string;
  }): ScanRecord | null {
    const row = this.findCacheStmt.get(args.tree_hash, args.scan_type, args.freshThreshold);
    return row ? rowToRecord(row) : null;
  }

  attachTreeCache(args: { tree_hash: string; scan_id: string; scan_type: ScanType }): void {
    this.attachCacheStmt.run(args.tree_hash, args.scan_id, args.scan_type, nowIso());
  }
}

function rowToRecord(row: ScanRow): ScanRecord {
  const record: ScanRecord = {
    scan_id: row.id,
    scan_type: row.scan_type as ScanType,
    project_path: row.project_path,
    tree_hash: row.tree_hash,
    started_at: row.started_at,
    finished_at: row.finished_at,
    status: row.status as ScanStatus,
    tools_run: parseJsonArray<ToolRun>(row.tools_run),
    missing_tools: parseJsonArray<string>(row.missing_tools),
    report_paths: row.report_dir ? [row.report_dir] : [],
  };
  if (row.cached_from) record.cached_from = row.cached_from;
  if (row.meta && row.meta !== '{}') {
    try {
      record.meta = JSON.parse(row.meta) as Record<string, unknown>;
    } catch {
      /* ignore malformed meta */
    }
  }
  return record;
}
