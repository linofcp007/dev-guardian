/**
 * SQLite connection management for the dev-guardian MCP server.
 *
 * Backed by Node's built-in `node:sqlite` (`DatabaseSync`) — no native module,
 * so the server runs from a self-contained bundle with **zero** runtime
 * `node_modules`. A thin adapter (`GuardianDatabase` / `GuardianStatement`)
 * preserves the small, better-sqlite3-shaped surface the repos rely on:
 * `prepare<P, R>()`, `run()/get()/all()`, `exec()`, `pragma()` and a
 * nesting-aware `transaction()`. This stays the only module that knows the
 * engine is node:sqlite; swapping it again only touches files in this folder.
 *
 * The DB lives at `<project_root>/.guardian/guardian.db`, and is used only
 * when it is THIS user's (`dbProvenance.ts`, `dbRegistry.ts`): one this
 * build creates gets a random `db_id`, registered in the per-user registry
 * before it is written; an existing one is trusted when its id is registered,
 * or — a database from 3.0.0 or earlier, with no id — when it passes the
 * one-time legacy adoption. It is REFUSED otherwise, and the per-user
 * fallback used instead, with a warning the caller includes in tool
 * responses (`health_status`'s `storage_warning`, every scan's `warnings`)
 * saying why and where the history now goes. Refused, too, when:
 *   - the location is not writable (read-only mounts, missing permissions, a
 *     database left behind by a `sudo` or Docker run). Writability is PROBED
 *     — a file is created in `.guardian/` and the database takes a real
 *     write — not asked of `accessSync`, which on Windows ignores ACLs;
 *   - git tracks it (any case) or `.guardian` is a submodule, or `.guardian`
 *     or the database is a link, whoever made it;
 *   - it holds a schema object, or a table or index definition, that the
 *     migrations never create (`schemaCheck.ts#untrustedObjects`) — a
 *     trigger that deletes every finding as it is inserted was reproduced.
 * A refused project database is never written to: it is read through a
 * read-only connection to learn its id, and left exactly as it was.
 *
 * The fallback is `<user data dir>/<sha1(project_root)>/guardian.db`
 * ({@link userDataDir}: `%LOCALAPPDATA%\dev-guardian` on Windows,
 * `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian` elsewhere,
 * `GUARDIAN_DATA_DIR` when set). It used to be `os.tmpdir()/dev-guardian/…`:
 * a predictable path in a directory every user can write, which another user
 * could create first and fill, and which nothing checked the owner of. Its
 * directories are created 0700 and, on POSIX, must belong to this user —
 * checked before anything is created inside them (`userData.ts`).
 *
 * Every connection opens with `trusted_schema = OFF` (no function the schema
 * names runs unless SQLite marks it innocuous), `cell_size_check = ON`
 * (malformed pages are caught as corruption rather than read) and no memory
 * map (a file read through `mmap` bypasses those checks). A file SQLite
 * cannot read at all is one {@link GuardianDbError} naming it and saying to
 * move it aside — the server prints it without a stack trace.
 *
 * The connection opens in WAL mode with foreign keys on; the resolver uses
 * `:memory:` when the caller asks for it, which the unit tests rely on.
 */

import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import type { StatementSync, SQLInputValue } from 'node:sqlite';
import { canonicalPath } from '../platform/projectPath.js';
import { GuardianDbError } from './dbError.js';
import {
  adoptionProblem,
  gitIndexAt,
  gitProblem,
  locationProblem,
  probeDatabase,
  type GitIndexAnswer,
} from './dbProvenance.js';
import { DB_ID_KEY, forgetDbId, lookupDbId, newDbId, registerDbId } from './dbRegistry.js';
import { listMigrations, runMigrations } from './migrations/runner.js';
import { assertOwnedRegularFileIfPresent, ensurePrivateSubdir, userDataDir } from './userData.js';
import {
  missingIndexSql,
  missingObjects,
  readSchema,
  recordsNewerMigrations,
  untrustedObjects,
  type SchemaSnapshot,
} from './schemaCheck.js';

// `node:sqlite` is pulled in via createRequire rather than a static value
// import on purpose: the production bundler (esbuild) and the test runner
// (vite-node, whose bundled Vite predates node:sqlite and would try to resolve
// a bare `sqlite`) both leave a runtime require untouched, so Node resolves the
// builtin natively in every context. The type-only import above is erased.
//
// And LAZILY, on first use rather than at import: on a Node without it
// (< 22.13, or 22.5-22.12 without --experimental-sqlite) a top-level require
// threw ERR_UNKNOWN_BUILTIN_MODULE while the server's modules were still
// loading, before it could say what was wrong. See nodeSqliteAvailable().
type SqliteModule = typeof import('node:sqlite');
type DatabaseSync = InstanceType<SqliteModule['DatabaseSync']>;

let sqliteModule: SqliteModule | undefined;
function loadSqlite(): SqliteModule {
  sqliteModule ??= createRequire(import.meta.url)('node:sqlite') as SqliteModule;
  return sqliteModule;
}

/** What the server prints, and exits 1 with, when `node:sqlite` is unavailable. */
export const NODE_SQLITE_REQUIRED = 'dev-guardian requires Node.js >= 22.13 (node:sqlite)';

/**
 * Whether this Node can load `node:sqlite` without flags — Node >= 22.13
 * (22.5-22.12 have it only behind `--experimental-sqlite`, which this project
 * never requires). Entry points check it before touching storage.
 */
export function nodeSqliteAvailable(): boolean {
  try {
    loadSqlite();
    return true;
  } catch {
    return false;
  }
}

/**
 * How long every connection waits for another connection's lock before
 * failing with `database is locked`. SQLite's own default is 0 — fail at
 * once — and several processes share one database file in real use (the
 * plugin's MCP server, a project-level one, the CLI): with 0, 15 of 20
 * fresh-database opens by 4 concurrent processes failed, and a write lock
 * held by one server made the next one's startup exit 1.
 */
export const BUSY_TIMEOUT_MS = 5000;

/** Result of a write statement — matches better-sqlite3's `RunResult` shape. */
export interface RunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

/**
 * Prepared-statement wrapper over `node:sqlite`'s `StatementSync`.
 *
 * Methods are declared as methods (not arrow properties) on purpose: that keeps
 * their parameter types bivariant, so a `GuardianStatement<unknown[]>` returned
 * by an un-generic `prepare()` stays assignable to a typed
 * `GuardianStatement<[string, ...]>` field — exactly how better-sqlite3's
 * `Statement` behaved.
 */
export class GuardianStatement<P extends unknown[] = unknown[], R = unknown> {
  constructor(private readonly stmt: StatementSync) {}

  run(...params: P): RunResult {
    const info = this.stmt.run(...(params as SQLInputValue[]));
    return { changes: Number(info.changes), lastInsertRowid: info.lastInsertRowid };
  }

  get(...params: P): R | undefined {
    return this.stmt.get(...(params as SQLInputValue[])) as R | undefined;
  }

  all(...params: P): R[] {
    return this.stmt.all(...(params as SQLInputValue[])) as R[];
  }
}

/** Public statement type — the name the repos import. */
export type Statement<P extends unknown[] = unknown[], R = unknown> = GuardianStatement<P, R>;

/**
 * Minimal database handle over `node:sqlite`, exposing exactly what the storage
 * repos use. Construct from a path (or `':memory:'`) — tests build these
 * directly; the server goes through {@link openDatabase}.
 */
export class GuardianDatabase {
  private readonly raw: DatabaseSync;
  private txDepth = 0;

  /**
   * The path passed to the constructor (or `':memory:'`). Mirrors
   * better-sqlite3's `db.name`, which `healthStatus` reads to stat the DB file.
   */
  readonly name: string;

  constructor(source: string | DatabaseSync) {
    if (typeof source === 'string') {
      this.raw = new (loadSqlite().DatabaseSync)(source);
      this.name = source;
    } else {
      this.raw = source;
      this.name = '';
    }
    // First statement on every connection, before anything that can take a
    // lock (switching a fresh file to WAL does). A PRAGMA rather than the
    // constructor's `timeout` option, which only exists from Node 22.16 —
    // on 22.13 an unknown option is silently ignored.
    this.raw.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
  }

  prepare<P extends unknown[] = unknown[], R = unknown>(source: string): GuardianStatement<P, R> {
    return new GuardianStatement<P, R>(this.raw.prepare(source));
  }

  /** Run one or more statements for their side effects (DDL, PRAGMA, BEGIN…). */
  exec(sql: string): void {
    this.raw.exec(sql);
  }

  /** better-sqlite3-style PRAGMA setter. Any returned row is intentionally ignored. */
  pragma(source: string): void {
    this.raw.exec(`PRAGMA ${source}`);
  }

  /**
   * Wraps `fn` in a transaction and returns a callable, mirroring
   * better-sqlite3's `db.transaction(fn)`. Nesting-aware: the outermost call
   * uses BEGIN IMMEDIATE/COMMIT/ROLLBACK, inner calls use SAVEPOINTs — so the
   * repos' `tx(args)` semantics carry over unchanged.
   *
   * `BEGIN IMMEDIATE`, not a deferred `BEGIN`: a deferred transaction takes
   * the write lock only at its first write, and if another connection wrote
   * in between, that upgrade fails with SQLITE_BUSY without ever consulting
   * the busy timeout. Taking the lock up front is what lets the timeout work.
   *
   * On failure, the ORIGINAL error is what the caller sees. SQLite rolls the
   * whole transaction back by itself on some errors (`RAISE(ROLLBACK)`, a full
   * disk, I/O errors); an unconditional `ROLLBACK` then throws
   * `cannot rollback - no transaction is active`, which replaced the error
   * that explained what went wrong and skipped the depth reset, leaving every
   * later "transaction" on this connection a deferred SAVEPOINT.
   */
  transaction<Args extends unknown[], R>(fn: (...args: Args) => R): (...args: Args) => R {
    return (...args: Args): R => {
      const depth = this.txDepth;
      const top = depth === 0;
      this.raw.exec(top ? 'BEGIN IMMEDIATE' : `SAVEPOINT sp_${depth}`);
      this.txDepth = depth + 1;
      try {
        const result = fn(...args);
        this.raw.exec(top ? 'COMMIT' : `RELEASE sp_${depth}`);
        return result;
      } catch (error) {
        this.rollbackAfterFailure(top, depth);
        throw error;
      } finally {
        this.txDepth = depth;
      }
    };
  }

  /** Best-effort undo for {@link transaction}; never throws over the caller's error. */
  private rollbackAfterFailure(top: boolean, depth: number): void {
    if (this.inTransaction() === false) return; // SQLite already rolled it back
    try {
      if (top) {
        this.raw.exec('ROLLBACK');
      } else {
        this.raw.exec(`ROLLBACK TO sp_${depth}`);
        this.raw.exec(`RELEASE sp_${depth}`);
      }
    } catch {
      // The error that made us roll back is the one worth reporting.
    }
  }

  /**
   * `DatabaseSync#isTransaction` exists from Node 22.16 / 24.0. On 22.13–22.15
   * it reads `undefined` at runtime (whatever the type declarations say), and
   * the answer is "unknown": the rollback is then attempted and its own
   * failure swallowed.
   */
  private inTransaction(): boolean | undefined {
    const flag: unknown = this.raw.isTransaction;
    return typeof flag === 'boolean' ? flag : undefined;
  }

  close(): void {
    this.raw.close();
  }
}

/** The handle type the repos and the Storage facade pass around. */
export type DB = GuardianDatabase;

export { GuardianDbError } from './dbError.js';
export { userDataDir } from './userData.js';

let referenceSchema: SchemaSnapshot | undefined;

/**
 * The schema the shipped migrations build on an empty database, read once
 * per process. Every database, whatever its age, holds a subset of it —
 * migrations only ever add — so it is both what a database may hold and
 * what it must hold once migrated.
 */
export function expectedSchema(): SchemaSnapshot {
  if (referenceSchema !== undefined) return referenceSchema;
  const db = new GuardianDatabase(':memory:');
  try {
    runMigrations(db);
    referenceSchema = readSchema(db);
  } finally {
    db.close();
  }
  return referenceSchema;
}

/** Throws a {@link GuardianDbError} naming what the migrated `db` still lacks. */
function assertSchemaComplete(db: GuardianDatabase, dbPath: string): void {
  const missing = missingObjects(db, expectedSchema());
  if (missing.length === 0) return;
  const shown = missing.slice(0, 8).join(', ') + (missing.length > 8 ? `, and ${missing.length - 8} more` : '');
  throw new GuardianDbError(
    'schema',
    dbPath,
    `the database '${dbPath}' is missing ${shown} after its migrations ran — ` +
      'it was changed outside dev-guardian, or copied from an incomplete file. ' +
      'Move it aside (rename it) and restart: a new database is created in its place, ' +
      'and the old file stays readable for recovery.',
  );
}

/**
 * Recreates, from the reference, every index the migrated `db` lacks on a
 * table it has: a 3.0 development database that ran 005's first cut never
 * got three of them, and 005 is recorded as applied. An index changes speed,
 * never an answer, so it is repaired rather than refused.
 */
function recreateMissingIndexes(db: GuardianDatabase): void {
  const statements = missingIndexSql(db, expectedSchema());
  if (statements.length === 0) return;
  db.transaction(() => {
    for (const sql of statements) db.exec(sql);
  })();
}

/**
 * Refuses `db` when its schema holds anything the migrations never create —
 * see `schemaCheck.ts#untrustedObjects`. Runs BEFORE the migrations, which
 * write to the very tables a trigger would sit on.
 */
function assertTrustedSchema(db: GuardianDatabase, dbPath: string): void {
  // A later build migrated it (a downgrade): what its additive migrations can
  // create, and cannot hide a row with, is accepted (`schemaCheck.ts`).
  const newerBuild = recordsNewerMigrations(db, latestMigration());
  const found = untrustedObjects(db, expectedSchema(), { newerBuild });
  if (found.length === 0) return;
  const shown = found.slice(0, 5).join('; ') + (found.length > 5 ? `; and ${found.length - 5} more` : '');
  throw new GuardianDbError(
    'untrusted',
    dbPath,
    `'${dbPath}' holds schema objects dev-guardian's migrations never create (${shown}). ` +
      'SQL stored in a database runs on every write the server makes — a trigger, or a constraint an ' +
      'INSERT OR IGNORE obeys, can hide findings from every reader — so it is not used' +
      (newerBuild
        ? '. It records migrations from a newer dev-guardian than this one: an object of that kind is refused ' +
          'from any build, and the newer dev-guardian reads this database'
        : ''),
  );
}

let latestKnownMigration: number | undefined;

/** The highest migration number this build ships. */
function latestMigration(): number {
  latestKnownMigration ??= Math.max(0, ...listMigrations().map((m) => m.version));
  return latestKnownMigration;
}

/**
 * Pragmas, the trust check, migrations and the completeness check: what makes
 * a handle usable. A file SQLite cannot read at all becomes one
 * {@link GuardianDbError} of kind `corrupt`.
 */
function prepareForUse(db: GuardianDatabase, dbPath: string, afterPragmas?: (db: GuardianDatabase) => void): void {
  try {
    applyPragmas(db);
    afterPragmas?.(db);
    assertTrustedSchema(db, dbPath);
    runMigrations(db);
    recreateMissingIndexes(db);
    assertSchemaComplete(db, dbPath);
  } catch (error) {
    throw asCorruptionError(error, dbPath);
  }
}

/** SQLITE_CORRUPT (11) or SQLITE_NOTADB (26) as a {@link GuardianDbError}; anything else unchanged. */
function asCorruptionError(error: unknown, dbPath: string): unknown {
  const code = sqliteErrorCode(error);
  if (code !== 11 && code !== 26) return error;
  const detail = error instanceof Error ? error.message : String(error);
  return new GuardianDbError(
    'corrupt',
    dbPath,
    `the database '${dbPath}' cannot be read (${detail}). Move it aside (rename it, for example to ` +
      'guardian.db.corrupt) and restart: a new, empty database is created in its place, and the old file ' +
      'stays available for recovery.',
  );
}

export interface OpenOptions {
  /**
   * Project root used to resolve `.guardian/guardian.db`. Ignored when
   * `inMemory: true`.
   */
  projectPath: string;
  /**
   * Opens the database in `:memory:`. Used by tests; never by the server.
   */
  inMemory?: boolean;
  /**
   * Opens the database the server would use for `projectPath` only if it
   * already exists, and never creates one: when there is none (or the
   * project's is refused and no fallback exists yet), an empty in-memory
   * database. The CLI's read-only `status` / `dashboard` use it, so they
   * decide exactly as the server does — a foreign database is never read —
   * without creating a database anywhere. (A legacy database it adopts gets
   * its id written, as the server would.)
   */
  existingOnly?: boolean;
}

export interface OpenedDatabase {
  db: DB;
  /** Absolute path to the .db file, or ":memory:" for in-memory DBs. */
  path: string;
  /**
   * Set when the project's database was not used: it is foreign (not this
   * user's), not writable, or holds objects the migrations never create.
   * Says why, where the history goes instead, and how to get the project's
   * own back; tools surface it (`health_status.storage_warning`, every
   * scan's `warnings`).
   */
  warning?: string;
  /** One line worth logging once: a legacy database was adopted. */
  notice?: string;
}

/** What {@link judgeProjectDatabase} decided about `.guardian/guardian.db`. */
type Verdict =
  | { kind: 'create' }
  | { kind: 'trusted'; dbId: string }
  | { kind: 'adopt' }
  | { kind: 'foreign'; why: string; tracked: boolean };

/**
 * Open (and migrate) a guardian database. Idempotent — calling twice on the
 * same path returns two independent connections to the same file.
 */
export function openDatabase(options: OpenOptions): OpenedDatabase {
  if (options.inMemory) return openInMemory();

  const projectPath = resolve(options.projectPath);
  const preferredPath = join(projectPath, '.guardian', 'guardian.db');
  const existingOnly = options.existingOnly === true;

  let refusal: string | undefined;
  if (!isDirectory(projectPath)) {
    // Caller's responsibility to have a real project dir; if it doesn't
    // exist, we can't write there.
    refusal = `Project path '${projectPath}' is not writable (it is not an existing directory)`;
  } else if (!existingOnly || existsSync(preferredPath)) {
    const verdict = judgeProjectDatabase(projectPath, preferredPath);
    if (verdict.kind === 'foreign') {
      refusal = foreignReason(preferredPath, verdict);
    } else if (!(existingOnly && verdict.kind === 'create')) {
      try {
        return openProjectDatabase(projectPath, preferredPath, verdict);
      } catch (error) {
        if (error instanceof GuardianDbError && error.kind === 'untrusted') {
          refusal =
            `${error.message}. The file is left as it is; ` +
            'delete it or move it aside to have dev-guardian start a new one there';
        } else if (isNotWritableError(error)) {
          const reason = error instanceof Error ? error.message : String(error);
          refusal = `Project path '${projectPath}' is not writable (${reason})`;
        } else {
          throw error;
        }
      }
    }
  }

  const chosenPath = resolveFallbackDbPath(projectPath);
  if (existingOnly && !existsSync(chosenPath)) {
    return { ...openInMemory(), ...(refusal !== undefined ? { warning: `${refusal}.` } : {}) };
  }
  ensurePrivateSubdir(shortHash(projectPath));
  const db = openFallback(chosenPath);
  if (refusal === undefined) return { db, path: chosenPath };
  return {
    db,
    path: chosenPath,
    warning:
      `${refusal}. This project's scans are kept in '${chosenPath}' instead, and stay there: they are not ` +
      'merged back into the project file later.',
  };
}

/**
 * Whether `.guardian/guardian.db` is this user's — see the module comment and
 * `dbProvenance.ts`. Reads it only through a read-only connection; asks git
 * once when the file exists.
 */
function judgeProjectDatabase(projectPath: string, dbPath: string): Verdict {
  const location = locationProblem(projectPath, dbPath);
  if (location !== null) return { kind: 'foreign', why: location, tracked: false };
  if (!existsSync(dbPath)) return { kind: 'create' };

  const probe = probeDatabase(dbPath);
  const index: GitIndexAnswer = gitIndexAt(projectPath);
  const fromGit = gitProblem(index);
  if (fromGit !== null) return { kind: 'foreign', why: fromGit, tracked: index.tracked.length > 0 };
  // Nothing in it yet: another process is creating it this very moment (or
  // the file is empty). Either way it holds nothing to trust or distrust.
  if (probe.empty) return { kind: 'create' };
  if (probe.dbId !== null && lookupDbId(probe.dbId) !== null) return { kind: 'trusted', dbId: probe.dbId };

  const adoption = adoptionProblem(projectPath, dbPath, index, probe.scanProjects);
  if (adoption === null) return { kind: 'adopt' };
  return {
    kind: 'foreign',
    why:
      probe.dbId === null
        ? `it carries no dev-guardian id (it was not created by this user's dev-guardian, and cannot be adopted as an earlier version's: ${adoption})`
        : `its dev-guardian id is not one this user's dev-guardian registered (it was created elsewhere, and cannot be adopted: ${adoption})`,
    tracked: false,
  };
}

/** The refusal of a foreign database: why, that the file is untouched, and how to recover. */
function foreignReason(dbPath: string, verdict: Extract<Verdict, { kind: 'foreign' }>): string {
  const recovery = verdict.tracked
    ? 'One that came with the repository is not yours: delete it, and dev-guardian starts a new one there. ' +
      'One you committed yourself: stop tracking it (git rm --cached .guardian/guardian.db)'
    : 'If it is yours, delete it or move it aside, and dev-guardian starts a new one there — there is no way ' +
      'to mark a database as trusted';
  return (
    `'${dbPath}' is not used: ${verdict.why}. A database that is not this user's own is not trusted — SQL or ` +
    'data stored in it (a trigger, a constraint, a suppression that matches every project) can hide findings ' +
    `from every reader. The file is left as it is. ${recovery}`
  );
}

/**
 * Opens the project's database on the verdict's terms: a new one gets its id
 * registered and written before anything else, a legacy one is adopted (id
 * registered and written) only after its schema passed.
 */
function openProjectDatabase(projectPath: string, dbPath: string, verdict: Exclude<Verdict, { kind: 'foreign' }>): OpenedDatabase {
  const entryFor = (id: string): { db_id: string; db_path: string; project_path: string; created_at: string } => ({
    db_id: id,
    db_path: safeCanonical(dbPath),
    project_path: safeCanonical(projectPath),
    created_at: new Date().toISOString(),
  });
  if (verdict.kind === 'create') {
    // Registered BEFORE it is written, so a process that reads the id from
    // the file always finds it registered; written before the migrations, so
    // no other process sees tables with no id.
    const db = openWritable(dbPath, (raw) => claimDbId(raw, entryFor, 'keep'));
    return { db, path: dbPath };
  }
  const db = openWritable(dbPath);
  if (verdict.kind === 'adopt') {
    try {
      claimDbId(db, entryFor, 'replace');
    } catch (error) {
      closeQuietly(db);
      throw error;
    }
    return {
      db,
      path: dbPath,
      notice:
        `adopted '${dbPath}', written by an earlier dev-guardian (untracked in this project's own repository, ` +
        'not a link): registered as this user\'s database',
    };
  }
  return { db, path: dbPath };
}

/**
 * Writes a freshly registered id into `schema_meta` and returns the id the
 * database ends up with. `keep`: an id another process wrote first wins (it
 * registered it before writing) and ours is forgotten; `replace`: ours
 * overwrites an unregistered one (adoption).
 */
function claimDbId(
  db: GuardianDatabase,
  entryFor: (id: string) => { db_id: string; db_path: string; project_path: string; created_at: string },
  mode: 'keep' | 'replace',
): string {
  const mine = newDbId();
  registerDbId(entryFor(mine));
  const kept = db.transaction((): string => {
    db.exec('CREATE TABLE IF NOT EXISTS schema_meta (\n  key   TEXT PRIMARY KEY,\n  value TEXT NOT NULL\n)');
    const sql =
      mode === 'keep'
        ? 'INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)'
        : 'INSERT INTO schema_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value';
    db.prepare<[string, string]>(sql).run(DB_ID_KEY, mine);
    return db.prepare<[string], { value: string }>('SELECT value FROM schema_meta WHERE key = ?').get(DB_ID_KEY)?.value ?? mine;
  })();
  if (kept !== mine) forgetDbId(mine);
  return kept;
}

function safeCanonical(path: string): string {
  try {
    return canonicalPath(path);
  } catch {
    return resolve(path);
  }
}

function openInMemory(): OpenedDatabase {
  const db = new GuardianDatabase(':memory:');
  applyPragmas(db);
  runMigrations(db);
  return { db, path: ':memory:' };
}

/**
 * Opens (and migrates) `dbPath` only if it can really be written: creates
 * its directory, creates and removes a probe file there, then makes the
 * database take a write. Throws otherwise — see {@link isNotWritableError}
 * for the failures that mean "use the fallback". `afterPragmas` runs on the
 * connection before the schema is judged and migrated.
 */
function openWritable(dbPath: string, afterPragmas?: (db: GuardianDatabase) => void): GuardianDatabase {
  const dir = dirname(dbPath);
  ensureDir(dir);
  probeDirectoryWritable(dir);
  const db = new GuardianDatabase(dbPath);
  try {
    prepareForUse(db, dbPath, afterPragmas);
    probeDatabaseWritable(db);
    return db;
  } catch (error) {
    closeQuietly(db);
    throw error;
  }
}

/** Opens `dbPath` and makes it usable ({@link prepareForUse}); closes it again on failure. */
function openPrepared(dbPath: string): GuardianDatabase {
  const db = new GuardianDatabase(dbPath);
  try {
    prepareForUse(db, dbPath);
    return db;
  } catch (error) {
    closeQuietly(db);
    throw error;
  }
}

/**
 * The per-user fallback: checked for ownership (POSIX) before it is opened,
 * and refused outright — there is nowhere further to fall back to — when it
 * is not ours or holds objects the migrations never create.
 */
function openFallback(dbPath: string): GuardianDatabase {
  assertOwnedRegularFileIfPresent(dbPath);
  try {
    return openPrepared(dbPath);
  } catch (error) {
    if (error instanceof GuardianDbError && error.kind === 'untrusted') {
      throw new GuardianDbError(
        'untrusted',
        dbPath,
        `${error.message}. It is dev-guardian's per-user database for this project: move it aside and restart.`,
      );
    }
    throw error;
  }
}

function closeQuietly(db: GuardianDatabase): void {
  try {
    db.close();
  } catch {
    /* the open failure is the one worth reporting */
  }
}

function probeDirectoryWritable(dir: string): void {
  const probe = join(dir, `.write-probe-${process.pid}-${randomBytes(4).toString('hex')}`);
  writeFileSync(probe, '', { flag: 'wx' });
  try {
    rmSync(probe, { force: true });
  } catch {
    /* a probe we could create but not delete is harmless; .guardian/ is git-ignored */
  }
}

/**
 * A read-only database FILE opens without complaint and serves every read —
 * SQLite quietly opens it read-only — so only a write reveals it. An UPDATE
 * that matches nothing still has to begin a write transaction, which is
 * where SQLite answers SQLITE_READONLY, before and regardless of any lock.
 *
 * The busy timeout is dropped to 0 for the probe: SQLITE_BUSY means another
 * process is writing this same file right now — proof enough that it is
 * writable, and no reason to stall startup for 5 s.
 */
function probeDatabaseWritable(db: GuardianDatabase): void {
  db.exec('PRAGMA busy_timeout = 0');
  try {
    db.exec('UPDATE schema_meta SET value = value WHERE 0');
  } catch (error) {
    if (!isBusyError(error)) throw error;
  } finally {
    db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
  }
}

/**
 * Failures that mean "this location cannot be written by us": the OS
 * refusing (EACCES/EPERM, or EROFS on a read-only mount) or SQLite refusing
 * (SQLITE_READONLY = 8, SQLITE_CANTOPEN = 14 — what an ACL-denied directory
 * produces on Windows). Anything else is a real error and propagates.
 */
function isNotWritableError(error: unknown): boolean {
  if (error instanceof Error && 'code' in error) {
    const code = error.code;
    if (code === 'EACCES' || code === 'EPERM' || code === 'EROFS') return true;
  }
  const sqlite = sqliteErrorCode(error);
  return sqlite === 8 || sqlite === 14;
}

/**
 * Where {@link openDatabase} redirects a project's database when
 * `<projectPath>/.guardian/guardian.db` is not writable or not trusted:
 * `<userDataDir()>/<sha1(project)>/guardian.db`, keyed by {@link shortHash}
 * of the RESOLVED project path — mirrors `openDatabase`'s own internal
 * `resolve()` exactly, so a caller that passes a relative path still lands
 * on the same file `openDatabase` itself would open for it. Pure path
 * arithmetic, no I/O.
 *
 * It was `os.tmpdir()/dev-guardian/<sha1(project)>/guardian.db` — a path
 * anyone could compute, in a directory anyone can write, opened by the CLI
 * whenever it existed. A database there from before this change is not
 * carried over: that location is exactly what could not be trusted.
 */
export function resolveFallbackDbPath(projectPath: string): string {
  return join(userDataDir(), shortHash(resolve(projectPath)), 'guardian.db');
}

/**
 * Open a database at an EXACT, already-known path — no writability probe, no
 * primary/fallback decision, and (unlike {@link openDatabase}'s own
 * non-memory branch) no directory creation: the caller has already
 * established, by checking the filesystem itself, that `path` exists and is
 * the one to read.
 *
 * Exists for `status`/`dashboard`'s own read-only detection: once it has
 * found a database sitting at the FALLBACK location (see
 * `resolveFallbackDbPath`) rather than the primary one, re-running
 * `openDatabase`'s own writability probe would be pointless at best (the
 * answer is already known from the filesystem) and WRONG at worst — if the
 * project directory happens to be writable again by the time `status` runs
 * (permissions fixed, a different mount, …), `openDatabase({ projectPath })`
 * would pick the PRIMARY path instead (writable wins), silently ignoring the
 * very fallback database this function was called to read and, worse,
 * creating a fresh EMPTY primary file in its place. Opening the exact path
 * already located sidesteps that re-derivation entirely.
 *
 * Still applies the same pragmas and runs migrations `openDatabase` would
 * have, so a database that predates a later migration is brought current
 * before use — this is a genuine open, not a bypass of either.
 */
export function openDatabaseAtPath(path: string): DB {
  return openPrepared(path);
}

function applyPragmas(db: GuardianDatabase): void {
  // First, before anything reads the schema: a function the file's schema
  // names (in a view, a trigger, a default, an index expression) runs only if
  // SQLite marks it innocuous.
  db.pragma('trusted_schema = OFF');
  // A page whose cell sizes do not add up is reported as corruption instead
  // of being read — a crafted file is the case that matters.
  db.pragma('cell_size_check = ON');
  // No memory map: reads through mmap skip the page checks above, and a file
  // another process truncates under a mapping faults the whole process. It
  // was 64 MB; the page cache serves the same reads.
  db.pragma('mmap_size = 0');
  // WAL gives concurrent readers + one writer without the classic SQLITE_BUSY
  // storm. Required because the server reads from resources while tools write.
  retryWhileBusy(() => db.pragma('journal_mode = WAL'));
  db.pragma('foreign_keys = ON');
  // Synchronous=NORMAL is the documented WAL pairing for durability vs. speed.
  db.pragma('synchronous = NORMAL');
}

/**
 * Runs `op`, retrying on SQLITE_BUSY until {@link BUSY_TIMEOUT_MS} has passed.
 *
 * For the few statements the busy timeout does not cover. SQLite skips the
 * busy handler when waiting could deadlock — two connections that both hold
 * a read lock and both want to upgrade it, which is exactly what several
 * processes switching one fresh file to WAL at the same moment do. Measured:
 * with the busy timeout alone, 7 of 20 concurrent fresh opens still failed
 * `database is locked` on `journal_mode = WAL`. Retrying after the statement
 * has released its read lock breaks the tie.
 */
function retryWhileBusy(op: () => void): void {
  const deadline = Date.now() + BUSY_TIMEOUT_MS;
  for (;;) {
    try {
      op();
      return;
    } catch (error) {
      if (!isBusyError(error) || Date.now() >= deadline) throw error;
      sleepSync(20 + Math.floor(Math.random() * 30));
    }
  }
}

/** SQLITE_BUSY (5) or SQLITE_LOCKED (6), including their extended codes. */
function isBusyError(error: unknown): boolean {
  const primary = sqliteErrorCode(error);
  return primary === 5 || primary === 6;
}

/** The primary SQLite result code of a `node:sqlite` error, if it is one. */
function sqliteErrorCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('errcode' in error)) return undefined;
  const code: unknown = error.errcode;
  // Extended result codes carry the primary code in their low byte.
  return typeof code === 'number' ? code & 0xff : undefined;
}

/** Blocks this thread for `ms` without spinning. */
export function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function shortHash(input: string): string {
  return createHash('sha1').update(input).digest('hex').slice(0, 16);
}
