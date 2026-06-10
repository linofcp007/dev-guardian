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
import { join, resolve } from 'node:path';
import type { StatementSync, SQLInputValue } from 'node:sqlite';
import { runMigrations } from './migrations/runner.js';

// `node:sqlite` is pulled in via createRequire rather than a static value
// import on purpose: the production bundler (esbuild) and the test runner
// (vite-node, whose bundled Vite predates node:sqlite and would try to resolve
// a bare `sqlite`) both leave a runtime require untouched, so Node resolves the
// builtin natively in every context. The type-only import above is erased.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');
type DatabaseSync = InstanceType<typeof DatabaseSync>;

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
   * uses BEGIN/COMMIT/ROLLBACK, inner calls use SAVEPOINTs — so the repos'
   * `tx(args)` semantics carry over unchanged.
   */
  transaction<Args extends unknown[], R>(fn: (...args: Args) => R): (...args: Args) => R {
    return (...args: Args): R => {
      const depth = this.txDepth;
      const top = depth === 0;
      this.raw.exec(top ? 'BEGIN' : `SAVEPOINT sp_${depth}`);
      this.txDepth = depth + 1;
      try {
        const result = fn(...args);
        this.raw.exec(top ? 'COMMIT' : `RELEASE sp_${depth}`);
        this.txDepth = depth;
        return result;
      } catch (error) {
        if (top) {
          this.raw.exec('ROLLBACK');
        } else {
          this.raw.exec(`ROLLBACK TO sp_${depth}`);
          this.raw.exec(`RELEASE sp_${depth}`);
        }
        this.txDepth = depth;
        throw error;
      }
    };
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
    const fallbackDir = join(tmpdir(), 'dev-guardian', shortHash(projectPath));
    ensureDir(fallbackDir);
    chosenPath = join(fallbackDir, 'guardian.db');
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

function applyPragmas(db: GuardianDatabase): void {
  // WAL gives concurrent readers + one writer without the classic SQLITE_BUSY
  // storm. Required because the server reads from resources while tools write.
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  // 64 MB memory map — modest, predictable, fits the largest expected scan.
  db.pragma('mmap_size = 67108864');
  // Synchronous=NORMAL is the documented WAL pairing for durability vs. speed.
  db.pragma('synchronous = NORMAL');
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
