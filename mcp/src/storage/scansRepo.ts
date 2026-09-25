/**
 * Scans repository — one row per scan invocation.
 *
 * Responsibilities live strictly at the persistence layer: every method here
 * maps directly to a SQL operation. Cache lookup, transition logic, and the
 * tree-hash freshness window all belong to the scan-tool factory upstream
 * (see [.specs/dev-guardian-mcp/design.md] → "Tool invocation flow").
 *
 * **`getLatestStmt` and `listHistoryStmt` (the UNSCOPED "any project" queries)
 * exclude `create_fix_pr`'s own verification re-scans** — see
 * `findingsRepo.ts`'s own module comment (task-7-review.md I3) for the full
 * reasoning; the same contamination, the same fix, the same reason
 * `WORKTREE_PATH_EXCLUSION` is inlined here as a literal rather than
 * imported from `fixpr/worktree.ts` — see `findingsRepo.ts`'s own module
 * comment for why it is wrapped in `%` on both sides, not just trailing.
 * **`listHistoryStmt` missed this exclusion when I3 first landed** — only
 * `getLatestStmt` here was covered, and `listHistoryStmt` shipped with no
 * `WHERE` clause at all. `risk_score` does not read `getLatest()`; it finds
 * its CVE source via `listHistory(50).find(...)`
 * (`tools/riskScore.ts#findLatestOfType`), so a dry run's own verification
 * re-scan could still win that unscoped search and silently zero out the
 * project's real CVE count — measured: a real score of 44 (high) read as 31
 * (medium), `active_cves` 5 read as 0, and it did not self-correct, because
 * the contaminating row is never deleted. `diff_scans` (`previous` scan
 * lookup) and `regression_alert` (fallback baseline) reach the exact same
 * unscoped list through this same method and are fixed by this same
 * statement — see the final review, 2026-08-16-create-fix-pr, finding C1.
 * `getLatestForProject` / `listHistoryForProject` need no such exclusion:
 * they are already scoped to an exact `project_path`, which a worktree's
 * path can never equal.
 */

import { hostname } from 'node:os';
import type { DB, Statement } from './db.js';
import type { ScanRecord, ScanStatus, ScanType, ToolRun } from '../types.js';
import { nowIso, parseJsonArray } from './repoUtil.js';

/** See the module comment. Wraps `fixpr/worktree.ts`'s `WORKTREE_DIR_PREFIX`. */
const WORKTREE_PATH_EXCLUSION = '%guardian-fixpr-wt-%';

/**
 * How old a `running` scan with an UNKNOWN owner must be before the startup
 * reaper fails it. Unknown means the owner cannot be checked from here: a row
 * written before owners were recorded (migration 004), or one started on
 * another host — a shared network drive, a container with its own hostname —
 * whose pid means nothing on this machine. Long enough that no real scan is
 * still running; short enough that a crashed one does not linger for days.
 */
export const UNKNOWN_OWNER_REAP_AFTER_MS = 6 * 60 * 60 * 1000;

/**
 * How old a `running` scan must be before the reaper fails it even though its
 * owner pid on this host still looks alive. Pids are reused — quickly on
 * Windows — so "a process with that pid exists" does not prove it is the
 * process that started the scan. Every scanner run is capped (10 min by
 * default, `GUARDIAN_SCAN_TIMEOUT_MS`), so a day is far beyond any real scan.
 */
export const LIVE_OWNER_REAP_AFTER_MS = 24 * 60 * 60 * 1000;

export interface ReapOptions {
  /** Epoch ms to measure age against. Default: `Date.now()`. */
  now?: number;
  /** This machine's name, compared with `owner_host`. Default: `os.hostname()`. */
  host?: string;
  /** This process's pid — see {@link ScansRepo.reapRunning}. Default: `process.pid`. */
  ownPid?: number;
  /** Whether a pid on this host is still running. Default: `process.kill(pid, 0)`. */
  isAlive?: (pid: number) => boolean;
}

interface RunningRow {
  id: string;
  started_at: string;
  owner_pid: number | null;
  owner_host: string | null;
}

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
    string, string, string, string, string, string, string, string, string | null, string,
    number, string,
  ]>;
  private readonly finalizeStmt: Statement<[
    string, string, string, string, string | null, string | null, string | null, string
  ]>;
  private readonly markCancelledStmt: Statement<[string, string]>;
  private readonly listRunningStmt: Statement<[], RunningRow>;
  private readonly reapOneStmt: Statement<[string, string, string]>;
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
        started_at, status, tools_run, missing_tools, report_dir, meta,
        owner_pid, owner_host
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    this.listRunningStmt = db.prepare<[], RunningRow>(`
      SELECT id, started_at, owner_pid, owner_host FROM scans WHERE status = 'running'
    `);

    // `AND status = 'running'`: the owner may have finalized the scan between
    // listRunningStmt and this update; a finished scan is never overwritten.
    this.reapOneStmt = db.prepare(`
      UPDATE scans
      SET status = 'failed', finished_at = ?, error = ?
      WHERE id = ? AND status = 'running'
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

    // No `status` filter — listHistory's contract is "any status" (a caller
    // that needs only completed scans filters that in JS; see
    // listHistoryForProjectStmt's own comment below). `project_path NOT
    // LIKE …` excludes create_fix_pr's own verification re-scans, the same
    // exclusion and the same reason as getLatestStmt above — see this file's
    // own module comment (task-7-review.md I3; this statement's own gap was
    // finding C1 of the final review, 2026-08-16-create-fix-pr).
    this.listHistoryStmt = db.prepare<[number], ScanRow>(`
      SELECT * FROM scans
      WHERE project_path NOT LIKE '${WORKTREE_PATH_EXCLUSION}'
      ORDER BY started_at DESC, rowid DESC
      LIMIT ?
    `);

    // Scoped to one project via `project_path = ?` — no `NOT LIKE` exclusion
    // needed, same reasoning as getLatestForProjectStmt's own relationship to
    // getLatestStmt above: an exact `project_path` match can never equal a
    // worktree's path, so the exclusion would be redundant. No `status`
    // filter either, matching listHistory's own "any status" contract
    // exactly: callers that need only completed scans (e.g. the dashboard
    // snapshot's "previous scan of the same type") filter that in JS, the
    // same way listHistory's own callers already do.
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
      process.pid,
      hostname(),
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
   * Fails scans left in `running` by a process that is gone (crash, kill -9).
   *
   * **Call it only at startup, before this process starts any scan** — the
   * rule for this process's own pid below depends on that.
   *
   * Only DEAD owners' scans: several servers share one database, and the old
   * sweep (`every running scan`) killed whatever another live server was
   * scanning at the time. For a scan whose owner is on this host:
   *   - the owner pid is THIS process's pid → reaped. This process has not
   *     started a scan yet, so an earlier process with the same pid wrote the
   *     row: a container restarted as pid 1 under the same hostname, or a pid
   *     Windows handed out again;
   *   - the pid no longer exists → reaped;
   *   - the pid exists → left alone, until the scan is older than
   *     {@link LIVE_OWNER_REAP_AFTER_MS} (the pid has been reused by then).
   * A scan whose owner cannot be checked from here (none recorded, or another
   * host) is reaped once older than {@link UNKNOWN_OWNER_REAP_AFTER_MS}.
   */
  reapRunning(options: ReapOptions = {}): number {
    const now = options.now ?? Date.now();
    const host = options.host ?? hostname();
    const ownPid = options.ownPid ?? process.pid;
    const isAlive = options.isAlive ?? pidIsAlive;
    let reaped = 0;
    for (const row of this.listRunningStmt.all()) {
      const reason = reapReason(row, { host, ownPid, now, isAlive });
      if (reason === null) continue;
      reaped += this.reapOneStmt.run(nowIso(), `reaped on startup: ${reason}`, row.id).changes;
    }
    return reaped;
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

  /**
   * Scan history across the WHOLE database, from ANY project — no
   * `project_path` filter and no `status` filter (unlike `getLatest`, every
   * status is included; see `listHistoryStmt`'s own comment). Excludes
   * `create_fix_pr`'s own verification re-scans, the same as `getLatest` —
   * see this file's own module comment. A caller that DID resolve a
   * `project_path` must use `listHistoryForProject` instead, for the same
   * reason `getLatest`'s own doc comment gives.
   */
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

/** Why `row` should be reaped, or null to leave it running. */
function reapReason(row: RunningRow, ctx: Required<ReapOptions>): string | null {
  // A timestamp that does not parse was not written by a live scan of ours.
  const started = Date.parse(row.started_at);
  const olderThan = (ms: number): boolean => Number.isNaN(started) || ctx.now - started > ms;

  const pid = row.owner_pid;
  if (pid !== null && Number.isInteger(pid) && pid > 0 && row.owner_host === ctx.host) {
    if (pid === ctx.ownPid) {
      return `owner pid ${pid} is this process's own pid, and this process has not started a scan yet`;
    }
    if (!ctx.isAlive(pid)) return `owner process ${pid} is no longer running`;
    if (olderThan(LIVE_OWNER_REAP_AFTER_MS)) {
      return `owner pid ${pid} still exists, but the scan started more than 24 h ago: the pid was reused`;
    }
    return null;
  }
  if (olderThan(UNKNOWN_OWNER_REAP_AFTER_MS)) {
    return 'owner unknown on this host and the scan started more than 6 h ago';
  }
  return null;
}

/**
 * `process.kill(pid, 0)` sends nothing; it only asks whether `pid` exists.
 * ESRCH is the one answer that means "gone". EPERM means it exists but
 * belongs to someone else — alive — and anything unexpected is treated as
 * alive too: wrongly leaving a scan `running` is recoverable, wrongly failing
 * a live one is not.
 */
function pidIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && 'code' in error && error.code === 'ESRCH');
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
