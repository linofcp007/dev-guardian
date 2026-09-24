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
 * The DB lives at `<project_root>/.guardian/guardian.db`. When that path is
 * not writable (read-only mounts, missing permissions), we fall back to
 * `os.tmpdir()/dev-guardian/<sha1(project_root)>/guardian.db` and surface a
 * warning the caller can include in tool responses.
 *
 * The connection opens in WAL mode with foreign keys on; the resolver uses
 * `:memory:` when the caller asks for it, which the unit tests rely on.
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, accessSync, constants } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { StatementSync, SQLInputValue } from 'node:sqlite';
import { runMigrations } from './migrations/runner.js';

// `node:sqlite` is pulled in via createRequire rather than a static value
// import on purpose: the production bundler (esbuild) and the test runner
// (vite-node, whose bundled Vite predates node:sqlite and would try to resolve
// a bare `sqlite`) both leave a runtime require untouched, so Node resolves the
// builtin natively in every context. The type-only import above is erased.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');
type DatabaseSync = InstanceType<typeof DatabaseSync>;

/**
 * How long every connection waits for another connection's lock before
 * failing with `database is locked`. SQLite's own default is 0 — fail at
 * once — and several processes share one database file in real use (the
 * plugin's MCP server, a project-level one, the CLI): with 0, 14 of 20
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
      this.raw = new DatabaseSync(source);
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
}

export interface OpenedDatabase {
  db: DB;
  /** Absolute path to the .db file, or ":memory:" for in-memory DBs. */
  path: string;
  /**
   * When set, the configured project path was not writable and we fell back
   * to a temp location. Tools should surface this in their responses so the
   * user knows scans are not being persisted alongside the project.
   */
  warning?: string;
}

/**
 * Open (and migrate) a guardian database. Idempotent — calling twice on the
 * same path returns two independent connections to the same file.
 */
export function openDatabase(options: OpenOptions): OpenedDatabase {
  if (options.inMemory) {
    const db = new GuardianDatabase(':memory:');
    applyPragmas(db);
    runMigrations(db);
    return { db, path: ':memory:' };
  }

  const projectPath = resolve(options.projectPath);
  const preferredDir = join(projectPath, '.guardian');
  const preferredPath = join(preferredDir, 'guardian.db');

  let chosenPath: string;
  let warning: string | undefined;

  if (isWritable(projectPath)) {
    ensureDir(preferredDir);
    chosenPath = preferredPath;
  } else {
    chosenPath = resolveFallbackDbPath(projectPath);
    ensureDir(dirname(chosenPath));
    warning =
      `Project path '${projectPath}' is not writable; ` +
      `dev-guardian DB persisted to '${chosenPath}' instead. ` +
      `Scans will not be visible alongside the project.`;
  }

  const db = new GuardianDatabase(chosenPath);
  applyPragmas(db);
  runMigrations(db);

  const result: OpenedDatabase = { db, path: chosenPath };
  if (warning !== undefined) {
    result.warning = warning;
  }
  return result;
}

/**
 * Where {@link openDatabase} redirects a project's database when
 * `<projectPath>/.guardian` is not writable: `os.tmpdir()/dev-guardian/
 * <sha1(project)>/guardian.db`, keyed by {@link shortHash} of the RESOLVED
 * project path — mirrors `openDatabase`'s own internal `resolve()` exactly,
 * so a caller that passes a relative path still lands on the same file
 * `openDatabase` itself would open for it. Pure path arithmetic, no I/O.
 *
 * Exported so a caller that needs to know WHERE a fallback database would
 * live — without wanting `openDatabase`'s own writability probe or its
 * side effect of creating one — does not reimplement the hash and directory
 * layout itself, which would silently drift the moment either changed here.
 * `status`/`dashboard`'s own read-only detection is the motivating caller:
 * see `resolveDbHandle` in `cli/dev-guardian.mjs`.
 */
export function resolveFallbackDbPath(projectPath: string): string {
  return join(tmpdir(), 'dev-guardian', shortHash(resolve(projectPath)), 'guardian.db');
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
  const db = new GuardianDatabase(path);
  applyPragmas(db);
  runMigrations(db);
  return db;
}

function applyPragmas(db: GuardianDatabase): void {
  // WAL gives concurrent readers + one writer without the classic SQLITE_BUSY
  // storm. Required because the server reads from resources while tools write.
  retryWhileBusy(() => db.pragma('journal_mode = WAL'));
  db.pragma('foreign_keys = ON');
  // 64 MB memory map — modest, predictable, fits the largest expected scan.
  db.pragma('mmap_size = 67108864');
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
export function sqliteErrorCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('errcode' in error)) return undefined;
  const code: unknown = error.errcode;
  // Extended result codes carry the primary code in their low byte.
  return typeof code === 'number' ? code & 0xff : undefined;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function isWritable(dir: string): boolean {
  try {
    if (!existsSync(dir)) {
      // Caller's responsibility to have a real project dir; if it doesn't
      // exist, we can't write there.
      return false;
    }
    accessSync(dir, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function shortHash(input: string): string {
  return createHash('sha1').update(input).digest('hex').slice(0, 16);
}
