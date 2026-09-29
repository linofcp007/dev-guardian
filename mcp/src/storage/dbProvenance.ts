/**
 * Where a project's `.guardian/guardian.db` came from — the questions
 * `db.ts#openDatabase` asks before it trusts one.
 *
 * A database is the data of whoever wrote it. Its schema can carry SQL that
 * runs on every write (a trigger that deletes each finding as it lands), and
 * its DATA can carry a suppression with no project (`project_path` NULL
 * matches every project) or scans dated to outrank the user's own, with no
 * schema object at all. So the one database trusted is one THIS user's
 * dev-guardian created, or one this user registered by hand: it carries a
 * random `db_id` registered in the per-user registry (`dbRegistry.ts`) for
 * the very path it is opened at. Anything else is FOREIGN — a database from
 * before 3.0.1 (no id), a clone, an archive of a repository, a copy of a
 * registered one, a submodule, a link to somewhere else — and goes to the
 * per-user fallback, the project file left as it is.
 *
 * There is no automatic adoption. Rounds 3 to 5 of the 3.0 review built one
 * — the project's own untracking repository, a scan filed under the
 * project's path, a scan finished after the project directory was created —
 * and round 6 broke the last of it twice: extractors restore a directory's
 * creation time (Windows' own `tar.exe` restored a 2020 CreationTime with
 * its defaults; 7-Zip does when the archive was built with `-mtc=on`), and a
 * dense series of future-dated scans always has one inside any window around
 * "now". Nothing in a file tells its owner from whoever wrote it. So the
 * only way to trust an existing database is a person's decision after
 * seeing what it holds: `dev-guardian db adopt` ({@link summarizeDatabase},
 * `db.ts#registerProjectDatabase`).
 *
 * Asked of every existing project database, before its bytes are read:
 *   - `.guardian` and the database files are not links or junctions, and the
 *     database's real path lies inside the project ({@link locationProblem});
 *   - git tracks neither the database nor its `-wal`, `-shm` or `-journal`
 *     under a CASE-INSENSITIVE pathspec — `.Guardian/guardian.db` committed
 *     is served as `.guardian/guardian.db` by a case-insensitive file system,
 *     and `git ls-files` prints nothing for the exact spelling under
 *     `core.ignorecase` — and `.guardian` is not a gitlink ({@link gitProblem}).
 * Then its id is read, read-only ({@link probeDatabase}).
 *
 * Git runs with a 3 s bound, `core.fsmonitor` off (a repository's own config
 * could name a program to run), GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE
 * dropped from its environment, in the C locale.
 */

import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, lstatSync, type Stats } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { canonicalPath } from '../platform/projectPath.js';
import { GuardianDbError } from './dbError.js';
import { DB_ID_KEY, DB_ID_SHAPE } from './dbRegistry.js';
import { datedInFutureSql } from './scanClock.js';

/** How long git may take to answer. */
export const GIT_TIMEOUT_MS = 3000;

/** The database and the files SQLite reads with it, relative to `.guardian/`. */
export const DATABASE_FILES = ['guardian.db', 'guardian.db-wal', 'guardian.db-shm', 'guardian.db-journal'] as const;

const TRACKED_FILE = /^\.guardian\/guardian\.db(?:-wal|-shm|-journal)?$/i;

export interface GitIndexAnswer {
  /** `ok`: git listed the index; `no-repo`: not a repository; `unavailable`: git did not answer. */
  state: 'ok' | 'no-repo' | 'unavailable';
  /** The database files git tracks, as git spells them (any case). */
  tracked: string[];
  /** `.guardian` (any case) is a gitlink — a submodule. */
  gitlink: boolean;
  detail: string;
}

export interface GitOptions {
  /** The git executable; tests pass one that does not exist. */
  git?: string;
  timeoutMs?: number;
}

/**
 * What the index of the repository `projectPath` is in says about
 * `.guardian`: `git ls-files -s -z -- ':(icase).guardian'`, one call. Never
 * throws.
 */
export function gitIndexAt(projectPath: string, opts: GitOptions = {}): GitIndexAnswer {
  const r = spawnSync(
    opts.git ?? 'git',
    ['-c', 'core.fsmonitor=false', '-c', 'core.quotepath=off', 'ls-files', '-s', '-z', '--', ':(icase).guardian'],
    {
      cwd: projectPath,
      encoding: 'utf8',
      timeout: opts.timeoutMs ?? GIT_TIMEOUT_MS,
      windowsHide: true,
      env: gitEnvironment(),
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  if (r.error !== undefined) {
    const code = (r.error as NodeJS.ErrnoException).code;
    const detail =
      code === 'ENOENT'
        ? 'git is not installed'
        : code === 'ETIMEDOUT'
          ? `git took longer than ${opts.timeoutMs ?? GIT_TIMEOUT_MS} ms`
          : `git failed to run (${code ?? r.error.message})`;
    return { state: 'unavailable', tracked: [], gitlink: false, detail };
  }
  const stderr = typeof r.stderr === 'string' ? r.stderr : '';
  if (r.status === 128 && /not a git repository/i.test(stderr)) {
    return { state: 'no-repo', tracked: [], gitlink: false, detail: 'not a git repository' };
  }
  if (r.status !== 0) {
    const first = stderr.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? '';
    return {
      state: 'unavailable',
      tracked: [],
      gitlink: false,
      detail: `git exited ${r.status ?? 'on a signal'}${first !== '' ? ` (${first})` : ''}`,
    };
  }
  const tracked: string[] = [];
  let gitlink = false;
  for (const entry of r.stdout.split('\0')) {
    const tab = entry.indexOf('\t');
    if (tab < 0) continue;
    const mode = entry.slice(0, entry.indexOf(' '));
    const path = entry.slice(tab + 1);
    if (mode === '160000' && path.toLowerCase() === '.guardian') gitlink = true;
    if (TRACKED_FILE.test(path)) tracked.push(path);
  }
  return { state: 'ok', tracked, gitlink, detail: 'git answered' };
}

/** process.env minus what would point git at another repository, in the C locale. */
function gitEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, LC_ALL: 'C', LANGUAGE: 'C', GIT_OPTIONAL_LOCKS: '0' };
  for (const key of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_NAMESPACE']) delete env[key];
  return env;
}

/** Why git says the database cannot be this user's own, or null. */
export function gitProblem(index: GitIndexAnswer): string | null {
  if (index.gitlink) return '`.guardian` is a git submodule, whose files come from another repository';
  if (index.tracked.length > 0) return `git tracks ${index.tracked.join(', ')}`;
  return null;
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

/**
 * Why `.guardian` or the database is reached through a link, or lies
 * outside the project — or null. Asked of every project database, whoever
 * made it: a `.guardian` that points elsewhere puts the database where
 * someone else may write it.
 */
export function locationProblem(projectPath: string, dbPath: string): string | null {
  const guardian = join(projectPath, '.guardian');
  const dir = lstatOrNull(guardian);
  if (dir !== null && dir.isSymbolicLink()) return '`.guardian` is a link (or a junction) to somewhere else';
  if (dir !== null && !dir.isDirectory()) return '`.guardian` is not a directory';
  for (const name of DATABASE_FILES) {
    const st = lstatOrNull(join(guardian, name));
    if (st === null) continue;
    if (st.isSymbolicLink()) return `.guardian/${name} is a link (or a junction) to somewhere else`;
    if (!st.isFile()) return `.guardian/${name} is not a regular file`;
  }
  // Judged on what exists — the database, else `.guardian`: a path that does
  // not exist yet cannot be resolved, and its lexical spelling would differ
  // from the project's real one whenever the project is reached through an
  // alias (an 8.3 name, macOS's /var -> /private/var).
  const existing = existsSync(dbPath) ? dbPath : dir !== null ? guardian : null;
  if (existing === null) return null;
  try {
    const rel = relative(canonicalPath(projectPath), canonicalPath(existing));
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return 'the database lies outside the project';
  } catch {
    return 'the database path could not be resolved';
  }
  return null;
}

// ---- Reading a database without changing it ---------------------------------

type SqliteModule = typeof import('node:sqlite');
type RawDatabase = InstanceType<SqliteModule['DatabaseSync']>;
let sqlite: SqliteModule | undefined;

/**
 * Runs `read` on a READ-ONLY connection to `dbPath` with `trusted_schema`
 * off: nothing in the file runs, nothing is written, the journal mode is left
 * alone. A file SQLite cannot read is a `GuardianDbError` of kind `corrupt`.
 */
function readOnly<T>(dbPath: string, read: (db: RawDatabase, isTable: (name: string) => boolean) => T): T {
  sqlite ??= createRequire(import.meta.url)('node:sqlite') as SqliteModule;
  let db: RawDatabase | undefined;
  try {
    const raw = new sqlite.DatabaseSync(dbPath, { readOnly: true });
    db = raw;
    raw.exec('PRAGMA busy_timeout = 5000');
    raw.exec('PRAGMA trusted_schema = OFF');
    raw.exec('PRAGMA cell_size_check = ON');
    // Read only real tables, never through a view of the same name.
    const isTable = (name: string): boolean =>
      (raw.prepare('SELECT type FROM sqlite_master WHERE name = ?').get(name) as { type: string } | undefined)?.type ===
      'table';
    return read(raw, isTable);
  } catch (error) {
    const code = sqliteCode(error);
    if (code === 11 || code === 26) {
      throw new GuardianDbError(
        'corrupt',
        dbPath,
        `the database '${dbPath}' cannot be read (${error instanceof Error ? error.message : String(error)})`,
      );
    }
    throw error;
  } finally {
    try {
      db?.close();
    } catch {
      /* nothing was written */
    }
  }
}

export interface DatabaseProbe {
  /** The file holds no schema object at all: a database being created, or an empty file. */
  empty: boolean;
  /** Its `schema_meta` db_id when it is a well-formed one, else null. */
  dbId: string | null;
}

/**
 * What {@link DatabaseProbe} names, read without changing the file
 * ({@link readOnly}). A file SQLite cannot read is a `GuardianDbError` of kind
 * `corrupt`, whose message is the reason alone.
 */
export function probeDatabase(dbPath: string): DatabaseProbe {
  return readOnly(dbPath, (db, isTable) => {
    const count = db.prepare('SELECT COUNT(*) AS n FROM sqlite_master').get() as { n: number } | undefined;
    if ((count?.n ?? 0) === 0) return { empty: true, dbId: null };
    let id: string | null = null;
    if (isTable('schema_meta')) {
      const row = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get(DB_ID_KEY) as
        | { value: unknown }
        | undefined;
      id = typeof row?.value === 'string' && DB_ID_SHAPE.test(row.value) ? row.value : null;
    }
    return { empty: false, dbId: id };
  });
}

/** One project a database holds scans of ({@link DatabaseContents}). */
export interface ProjectScans {
  project_path: string;
  scans: number;
  completed: number;
  first_started: string | null;
  last_finished: string | null;
}

/**
 * The tables that key rows by project, and so what `db adopt --rehome`
 * rewrites (`db.ts#rehomeProjectRows`). A table added later with a
 * `project_path` belongs here; `test/e2e/dbAdoptCli.test.ts` holds this list to the
 * schema.
 */
export const PROJECT_KEYED_TABLES = [
  'scans',
  'suppressions',
  'baselines',
  'stack_snapshots',
  'surface_snapshots',
  'finding_validations',
  'agent_config_hashes',
  'mcp_tool_pins',
  'mcp_server_pins',
] as const;

/**
 * What a database holds, for a person deciding whether it is theirs
 * (`dev-guardian db adopt`): whose scans, how many, over what dates, the
 * suppressions — those with no project first, since they apply to every
 * project — and scans dated in the future, which outrank every real one.
 */
export interface DatabaseContents {
  /** The projects with the most scans, at most {@link SHOWN_PROJECTS}. */
  projects: ProjectScans[];
  /** How many more projects it holds scans of. */
  more_projects: number;
  scans: number;
  completed: number;
  first_started: string | null;
  last_finished: string | null;
  suppressions: number;
  null_scoped_suppressions: number;
  baselines: number;
  /**
   * Scans dated beyond this machine's clock (`scanClock.ts`), and the
   * furthest date among them — a database with any is not registered.
   */
  future_dated: { scans: number; latest: string | null };
  /** Every distinct `project_path` in {@link PROJECT_KEYED_TABLES}, with its row count. */
  paths: Array<{ project_path: string; rows: number }>;
}

const SHOWN_PROJECTS = 20;

/** {@link DatabaseContents}, read without changing the file ({@link readOnly}). */
export function summarizeDatabase(dbPath: string): DatabaseContents {
  return readOnly(dbPath, (db, isTable) => {
    const count = (sql: string): number => (db.prepare(sql).get() as { n: number | null } | undefined)?.n ?? 0;
    const text = (v: unknown): string | null => (typeof v === 'string' ? v : null);
    const contents: DatabaseContents = {
      projects: [],
      more_projects: 0,
      scans: 0,
      completed: 0,
      first_started: null,
      last_finished: null,
      suppressions: 0,
      null_scoped_suppressions: 0,
      baselines: 0,
      future_dated: { scans: 0, latest: null },
      paths: [],
    };
    const columnsOf = (table: string): string[] =>
      (db.prepare(`SELECT name FROM pragma_table_info(?)`).all(table) as Array<{ name: unknown }>)
        .map((c) => c.name)
        .filter((n): n is string => typeof n === 'string');
    if (isTable('scans')) {
      const all = db
        .prepare(
          `SELECT project_path AS p, COUNT(*) AS n, SUM(status = 'completed') AS c,
                  MIN(started_at) AS first, MAX(finished_at) AS last
             FROM scans GROUP BY project_path ORDER BY n DESC, p`,
        )
        .all() as Array<{ p: unknown; n: number; c: number | null; first: unknown; last: unknown }>;
      for (const row of all) {
        contents.scans += row.n;
        contents.completed += row.c ?? 0;
        const first = text(row.first);
        const last = text(row.last);
        if (first !== null && (contents.first_started === null || first < contents.first_started)) {
          contents.first_started = first;
        }
        if (last !== null && (contents.last_finished === null || last > contents.last_finished)) {
          contents.last_finished = last;
        }
      }
      contents.projects = all.slice(0, SHOWN_PROJECTS).map((row) => ({
        project_path: typeof row.p === 'string' ? row.p : String(row.p),
        scans: row.n,
        completed: row.c ?? 0,
        first_started: text(row.first),
        last_finished: text(row.last),
      }));
      contents.more_projects = Math.max(0, all.length - SHOWN_PROJECTS);
      const future = db
        .prepare(
          `SELECT COUNT(*) AS n, MAX(MAX(COALESCE(started_at, ''), COALESCE(finished_at, ''))) AS latest
             FROM scans WHERE ${datedInFutureSql()}`,
        )
        .get() as { n: number; latest: unknown } | undefined;
      contents.future_dated = { scans: future?.n ?? 0, latest: (future?.n ?? 0) > 0 ? text(future?.latest) : null };
    }
    if (isTable('suppressions')) {
      contents.suppressions = count('SELECT COUNT(*) AS n FROM suppressions');
      // Before migration 011 no suppression had a project: every one applied everywhere.
      contents.null_scoped_suppressions = columnsOf('suppressions').includes('project_path')
        ? count('SELECT COUNT(*) AS n FROM suppressions WHERE project_path IS NULL')
        : contents.suppressions;
    }
    if (isTable('baselines')) contents.baselines = count('SELECT COUNT(*) AS n FROM baselines');
    const rows = new Map<string, number>();
    for (const table of PROJECT_KEYED_TABLES) {
      if (!isTable(table) || !columnsOf(table).includes('project_path')) continue;
      for (const r of db
        .prepare(`SELECT project_path AS p, COUNT(*) AS n FROM "${table}" WHERE project_path IS NOT NULL GROUP BY project_path`)
        .all() as Array<{ p: unknown; n: number }>) {
        if (typeof r.p === 'string') rows.set(r.p, (rows.get(r.p) ?? 0) + r.n);
      }
    }
    contents.paths = [...rows.entries()]
      .map(([project_path, n]) => ({ project_path, rows: n }))
      .sort((a, b) => b.rows - a.rows || a.project_path.localeCompare(b.project_path));
    return contents;
  });
}

function sqliteCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('errcode' in error)) return undefined;
  const code: unknown = error.errcode;
  return typeof code === 'number' ? code & 0xff : undefined;
}
