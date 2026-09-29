/**
 * Where a project's `.guardian/guardian.db` came from — the questions
 * `db.ts#openDatabase` asks before it trusts one.
 *
 * A database is the data of whoever wrote it. Its schema can carry SQL that
 * runs on every write (a trigger that deletes each finding as it lands), and
 * its DATA can carry a suppression with no project (`project_path` NULL
 * matches every project) that hides every finding with no schema object at
 * all. So the one database trusted without question is one THIS user's
 * dev-guardian created: it carries a random `db_id` registered in the
 * per-user registry (`dbRegistry.ts`). Anything else is FOREIGN — a clone, a
 * ZIP of a repository, a submodule, a link to somewhere else — and goes to the
 * per-user fallback, the project file left as it is.
 *
 * A database written by dev-guardian 3.0.0 or earlier has no id. It is
 * ADOPTED once, and only when every one of these holds
 * ({@link adoptionProblem}):
 *   - the project has a `.git` of its own (not a link): a repository
 *     downloaded as an archive has none, and one found further up (a home
 *     directory kept in git) is not this project's;
 *   - git answers, and tracks neither the database nor its `-wal`, `-shm` or
 *     `-journal` under a CASE-INSENSITIVE pathspec — `.Guardian/guardian.db`
 *     committed is served as `.guardian/guardian.db` by a case-insensitive
 *     file system, and `git ls-files` prints nothing for the exact spelling
 *     under `core.ignorecase`;
 *   - `.guardian` is not a gitlink (a submodule brings its own files);
 *   - `.guardian` and the database files are not links or junctions, and the
 *     database's real path lies inside the project;
 *   - it holds at least one completed scan filed under THIS project's
 *     canonical path, or a spelling of it (2.0.0's lower-case drive letter;
 *     never a path through a link — `platform/pathSpelling.ts`, which
 *     derives the spellings from the project's own path and compares the
 *     stored ones as strings: a path read from the database is never given
 *     to the file system, where a `\\host\share` costs a network timeout
 *     and the user's credentials). Git state
 *     cannot tell an attacker's `.git` from the user's — an archive can ship
 *     one whose index omits the database, or a gitfile naming another
 *     repository — but a database written on another machine carries that
 *     machine's paths, and an attacker would have to guess this one's;
 *   - its schema is clean (`schemaCheck.ts`, asked by `db.ts`).
 * Adoption then registers a fresh id, once.
 *
 * Git runs with a 3 s bound, `core.fsmonitor` off (a repository's own config
 * could name a program to run), GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE
 * dropped from its environment, in the C locale.
 */

import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, lstatSync, type Stats } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { spellingMatcher } from '../platform/pathSpelling.js';
import { canonicalPath } from '../platform/projectPath.js';
import { GuardianDbError } from './dbError.js';
import { DB_ID_KEY, DB_ID_SHAPE } from './dbRegistry.js';

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

/**
 * Why a database with no registered id cannot be adopted as this user's
 * legacy database, or null when it can (see the module comment). The schema
 * check is asked by the caller, after this.
 */
export function adoptionProblem(
  projectPath: string,
  dbPath: string,
  index: GitIndexAnswer,
  scanProjects: readonly string[],
): string | null {
  // A `.git` DIRECTORY, or a gitfile (`gitdir: …`): a linked worktree's
  // `.git` is a file, and a worktree is a legitimate layout (this repository
  // is developed in them). What makes it count is that git answers below —
  // `ls-files` fails when the gitdir does not resolve to a repository. Git
  // state alone cannot tell an attacker's `.git` from the user's, though (an
  // archive can ship either), which is what the scan check at the end is for.
  const git = lstatOrNull(join(projectPath, '.git'));
  if (git === null) {
    return 'the project has no .git of its own (a repository downloaded as an archive, or not a repository at all)';
  }
  if (git.isSymbolicLink()) return "the project's .git is a link";
  if (index.state !== 'ok') return `git could not be asked whether it tracks the database (${index.detail})`;
  const fromGit = gitProblem(index) ?? locationProblem(projectPath, dbPath);
  if (fromGit !== null) return fromGit;
  return scanProblem(projectPath, scanProjects);
}

/**
 * Why the database's own scans do not show it was written for THIS project,
 * or null: it must hold a completed scan filed under the project's canonical
 * path or a spelling of it (`platform/pathSpelling.ts` — 2.0.0's lower-case
 * drive letter among them, never a path through a link). A database made on
 * another machine, or for another project, carries other paths, and an
 * attacker would have to guess this machine's.
 */
function scanProblem(projectPath: string, scanProjects: readonly string[]): string | null {
  let canonical: string;
  try {
    canonical = canonicalPath(projectPath);
  } catch {
    return 'the project path could not be resolved';
  }
  // Lexical: a path read from the database is never given to the file system.
  const isThisProject = spellingMatcher(canonical);
  if (scanProjects.some(isThisProject)) return null;
  if (scanProjects.length === 0) return 'it holds no completed scan of this project (no completed scan at all)';
  const shown = scanProjects.slice(0, 2).join("', '");
  return (
    `it holds no completed scan of this project — its scans are filed under ${scanProjects.length} other ` +
    `path(s) ('${shown}'${scanProjects.length > 2 ? ', …' : ''}): a database written elsewhere`
  );
}

// ---- Reading a database without changing it ---------------------------------

type SqliteModule = typeof import('node:sqlite');
let sqlite: SqliteModule | undefined;

export interface DatabaseProbe {
  /** The file holds no schema object at all: a database being created, or an empty file. */
  empty: boolean;
  /** Its `schema_meta` db_id when it is a well-formed one, else null. */
  dbId: string | null;
  /**
   * The distinct `project_path` of its completed scans (at most
   * {@link MAX_SCAN_PROJECTS}), for the legacy adoption's "written for this
   * project" check. Empty when it has none, or no `scans` table.
   */
  scanProjects: string[];
}

/** Project paths a probe reads; a database written for one project holds one or a few. */
const MAX_SCAN_PROJECTS = 200;

/**
 * Reads what {@link DatabaseProbe} names through a READ-ONLY connection with
 * `trusted_schema` off: nothing in the file runs, nothing is written, the
 * journal mode is left alone. A file SQLite cannot read is a
 * `GuardianDbError` of kind `corrupt`.
 */
export function probeDatabase(dbPath: string): DatabaseProbe {
  sqlite ??= createRequire(import.meta.url)('node:sqlite') as SqliteModule;
  let db: InstanceType<SqliteModule['DatabaseSync']> | undefined;
  try {
    db = new sqlite.DatabaseSync(dbPath, { readOnly: true });
    db.exec('PRAGMA busy_timeout = 5000');
    db.exec('PRAGMA trusted_schema = OFF');
    db.exec('PRAGMA cell_size_check = ON');
    const count = db.prepare('SELECT COUNT(*) AS n FROM sqlite_master').get() as { n: number } | undefined;
    if ((count?.n ?? 0) === 0) return { empty: true, dbId: null, scanProjects: [] };
    // Read only real tables, never through a view of the same name.
    const isTable = (name: string): boolean =>
      (db?.prepare('SELECT type FROM sqlite_master WHERE name = ?').get(name) as { type: string } | undefined)?.type ===
      'table';
    let id: string | null = null;
    if (isTable('schema_meta')) {
      const row = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get(DB_ID_KEY) as
        | { value: unknown }
        | undefined;
      id = typeof row?.value === 'string' && DB_ID_SHAPE.test(row.value) ? row.value : null;
    }
    const scanProjects = isTable('scans')
      ? (db
          .prepare(`SELECT DISTINCT project_path AS p FROM scans WHERE status = 'completed' LIMIT ?`)
          .all(MAX_SCAN_PROJECTS) as Array<{ p: unknown }>)
          .map((r) => r.p)
          .filter((p): p is string => typeof p === 'string')
      : [];
    return { empty: false, dbId: id, scanProjects };
  } catch (error) {
    const code = sqliteCode(error);
    if (code === 11 || code === 26) {
      throw new GuardianDbError(
        'corrupt',
        dbPath,
        `the database '${dbPath}' cannot be read (${error instanceof Error ? error.message : String(error)}). ` +
          'Move it aside (rename it, for example to guardian.db.corrupt) and restart: a new, empty database is ' +
          'created in its place, and the old file stays available for recovery.',
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

function sqliteCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('errcode' in error)) return undefined;
  const code: unknown = error.errcode;
  return typeof code === 'number' ? code & 0xff : undefined;
}
