/**
 * SQLite connection management for the dev-guardian MCP server.
 *
 * The DB lives at `<project_root>/.guardian/guardian.db`. When that path is
 * not writable (read-only mounts, missing permissions), we fall back to
 * `os.tmpdir()/dev-guardian/<sha1(project_root)>/guardian.db` and surface a
 * warning the caller can include in tool responses.
 *
 * The connection itself opens in WAL mode with foreign keys on; the resolver
 * uses `:memory:` when the caller asks for it, which the unit tests rely on.
 */

import Database, { type Database as DB } from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, accessSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runMigrations } from './migrations/runner.js';

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
    const db = new Database(':memory:');
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

  const db = new Database(chosenPath);
  applyPragmas(db);
  runMigrations(db);

  const result: OpenedDatabase = { db, path: chosenPath };
  if (warning !== undefined) {
    result.warning = warning;
  }
  return result;
}

function applyPragmas(db: DB): void {
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
