/**
 * Baselines repository.
 *
 * A baseline belongs to one project and one scan type (migration 008): the
 * active baseline of a project is its most recently inserted row, and a
 * reader that compares scans asks for the active baseline OF A TYPE, so a
 * SAST scan is never measured against a secrets baseline. Older rows are
 * kept for audit/history.
 *
 * `getActive()` — the newest row in the whole database, any project — is
 * kept only for callers that have no project in scope; every reader that
 * has one uses `getActiveForProject`.
 *
 * An imported SARIF log adds a third coordinate (migration 016): `slot`, the
 * open-set slot of the baseline's scan — `sarif_import:<source tool>` — so a
 * baseline of CodeQL's import is not replaced by Snyk's. Every other scan
 * type leaves it NULL and keeps its per-(project, type) baseline.
 *
 * Rows an older build inserts without the two columns are read through the
 * baseline's scan (`COALESCE` over the join), so they still belong to their
 * project.
 */

import type { DB, Statement } from './db.js';
import type { Baseline, ScanType } from '../types.js';
import { sarifSlotOfScan } from '../history/scanRoles.js';
import { nowIso } from './repoUtil.js';

interface BaselineRow {
  id: number;
  scan_id: string;
  set_at: string;
  note: string | null;
  project_path: string | null;
  scan_type: string | null;
  slot: string | null;
}

export interface SetBaselineInput {
  scan_id: string;
  note?: string;
}

/** A baseline with the project and scan type of the scan it points at. */
export interface ProjectBaseline extends Baseline {
  /** Null only when the scan row itself is gone. */
  project_path: string | null;
  scan_type: ScanType | null;
  /** `sarif_import:<source tool>` for an imported log's baseline; absent otherwise. */
  slot?: string;
}

const SELECT_SCOPED = `
  SELECT b.id, b.scan_id, b.set_at, b.note,
         COALESCE(b.project_path, s.project_path) AS project_path,
         COALESCE(b.scan_type, s.scan_type) AS scan_type,
         b.slot AS slot
  FROM baselines b LEFT JOIN scans s ON s.id = b.scan_id
`;

export class BaselinesRepo {
  private readonly scanScopeStmt: Statement<[string], { project_path: string; scan_type: string; meta: string }>;
  private readonly insertStmt: Statement<[string, string, string | null, string | null, string | null, string | null]>;
  private readonly getActiveStmt: Statement<[], BaselineRow>;
  private readonly getActiveForProjectStmt: Statement<[string], BaselineRow>;
  private readonly getActiveForProjectTypeStmt: Statement<[string, string], BaselineRow>;
  private readonly getActiveForProjectSlotStmt: Statement<[string, string, string], BaselineRow>;
  private readonly listAllStmt: Statement<[], BaselineRow>;

  constructor(db: DB) {
    this.scanScopeStmt = db.prepare<[string], { project_path: string; scan_type: string; meta: string }>(
      `SELECT project_path, scan_type, meta FROM scans WHERE id = ?`,
    );
    this.insertStmt = db.prepare(`
      INSERT INTO baselines (scan_id, set_at, note, project_path, scan_type, slot) VALUES (?, ?, ?, ?, ?, ?)
    `);
    this.getActiveStmt = db.prepare<[], BaselineRow>(`${SELECT_SCOPED} ORDER BY b.id DESC LIMIT 1`);
    this.getActiveForProjectStmt = db.prepare<[string], BaselineRow>(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ?
      ORDER BY b.id DESC LIMIT 1
    `);
    this.getActiveForProjectTypeStmt = db.prepare<[string, string], BaselineRow>(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND COALESCE(b.scan_type, s.scan_type) = ?
      ORDER BY b.id DESC LIMIT 1
    `);
    this.getActiveForProjectSlotStmt = db.prepare<[string, string, string], BaselineRow>(`
      ${SELECT_SCOPED}
      WHERE COALESCE(b.project_path, s.project_path) = ? AND COALESCE(b.scan_type, s.scan_type) = ? AND b.slot = ?
      ORDER BY b.id DESC LIMIT 1
    `);
    this.listAllStmt = db.prepare<[], BaselineRow>(`${SELECT_SCOPED} ORDER BY b.id DESC`);
  }

  /** Records the scan's own project and type beside it. */
  set(input: SetBaselineInput): ProjectBaseline {
    const setAt = nowIso();
    const scope = this.scanScopeStmt.get(input.scan_id);
    // An unknown scan_id still reaches the INSERT, where the foreign key
    // rejects it — the same error this method always raised.
    const slot = scope?.scan_type === 'sarif_import' ? sarifSlotOfScan({ meta: parseMeta(scope.meta) }) : null;
    const info = this.insertStmt.run(
      input.scan_id,
      setAt,
      input.note ?? null,
      scope?.project_path ?? null,
      scope?.scan_type ?? null,
      slot,
    );
    const b: ProjectBaseline = {
      id: Number(info.lastInsertRowid),
      scan_id: input.scan_id,
      set_at: setAt,
      project_path: scope?.project_path ?? null,
      scan_type: (scope?.scan_type ?? null) as ScanType | null,
    };
    if (input.note !== undefined) b.note = input.note;
    if (slot !== null) b.slot = slot;
    return b;
  }

  /** The newest baseline in the database, from ANY project — see the module comment. */
  getActive(): ProjectBaseline | null {
    const row = this.getActiveStmt.get();
    return row ? rowToBaseline(row) : null;
  }

  /**
   * The newest baseline of one project — of one scan type, when given; of one
   * slot of that type (an import's source tool, `sarif_import:<tool>`), when given too.
   */
  getActiveForProject(projectPath: string, scanType?: ScanType, slot?: string): ProjectBaseline | null {
    const row =
      scanType === undefined
        ? this.getActiveForProjectStmt.get(projectPath)
        : slot === undefined
          ? this.getActiveForProjectTypeStmt.get(projectPath, scanType)
          : this.getActiveForProjectSlotStmt.get(projectPath, scanType, slot);
    return row ? rowToBaseline(row) : null;
  }

  listAll(): ProjectBaseline[] {
    return this.listAllStmt.all().map(rowToBaseline);
  }
}

function rowToBaseline(row: BaselineRow): ProjectBaseline {
  const b: ProjectBaseline = {
    id: row.id,
    scan_id: row.scan_id,
    set_at: row.set_at,
    project_path: row.project_path,
    scan_type: row.scan_type as ScanType | null,
  };
  if (row.note !== null) b.note = row.note;
  if (row.slot !== null) b.slot = row.slot;
  return b;
}

function parseMeta(text: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined; // a scan whose meta is unreadable has no source tool: the empty-name slot
  }
}
