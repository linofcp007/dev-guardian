/**
 * A project on a file system SQLite's WAL cannot use — a mapped network
 * drive — never stops the server.
 *
 * Round 7 of the database-trust review: a NEW project on `W:` (SMB) exited
 * on its first start with `fatal: Error: disk I/O error` from the project
 * database's open (3.0.0 did too): WAL needs shared memory a network file
 * system does not give, and the error was not one the fallback knew. Later
 * starts fell back. There is no SMB share in a test, so `node:sqlite` is
 * wrapped here: a connection to a path under {@link SHARE} fails the way
 * the share did — `PRAGMA journal_mode = WAL` with SQLITE_IOERR, and a
 * read-only connection's first statement likewise (reading a WAL database
 * needs the same shared memory).
 */

import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

const SHARE = vi.hoisted(() => 'smb-share-');

vi.mock('node:module', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:module')>();
  type Sqlite = typeof import('node:sqlite');
  let wrapped: Sqlite | undefined;
  const ioError = (): Error =>
    Object.assign(new Error('disk I/O error'), { code: 'ERR_SQLITE_ERROR', errcode: 10, errstr: 'disk I/O error' });
  const wrap = (real: Sqlite): Sqlite => {
    class DatabaseSync extends real.DatabaseSync {
      private readonly onShare: boolean;
      private readonly readOnly: boolean;
      constructor(path: string, options?: import('node:sqlite').DatabaseSyncOptions) {
        // node:sqlite refuses an explicit `undefined` for its options.
        if (options === undefined) super(path);
        else super(path, options);
        this.onShare = path.includes(SHARE);
        this.readOnly = options?.readOnly === true;
      }
      override exec(sql: string): void {
        if (this.onShare && /journal_mode\s*=\s*WAL/i.test(sql)) throw ioError();
        super.exec(sql);
      }
      override prepare(sql: string): import('node:sqlite').StatementSync {
        if (this.onShare && this.readOnly) throw ioError();
        return super.prepare(sql);
      }
    }
    return { ...real, DatabaseSync };
  };
  const createRequire = (url: string | URL): NodeJS.Require => {
    const req = actual.createRequire(url);
    const patched = ((id: string): unknown => {
      if (id !== 'node:sqlite') return req(id);
      wrapped ??= wrap(req('node:sqlite') as Sqlite);
      return wrapped;
    }) as NodeJS.Require;
    return Object.assign(patched, req);
  };
  return { ...actual, createRequire, default: { ...actual, createRequire } };
});

import { inspectProjectDatabase, openDatabase, registerProjectDatabase, resolveFallbackDbPath } from '../../../src/storage/db.js';
import { listMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../../helpers/tempDir.js';

vi.setConfig({ testTimeout: 30_000 });

const undo: Array<() => void> = [];
afterEach(() => {
  for (const fn of undo.splice(0).reverse()) fn();
});
afterAll(cleanupTempDirs);

function onShare(): string {
  const dir = makeTempDir(SHARE);
  undo.push(() => rmDir(join(resolveFallbackDbPath(dir), '..')));
  return dir;
}

const UNFIT = /is on a file system SQLite's WAL can't use \(network drive\?\) — SQLite said "disk I\/O error"/;

describe('a project on a file system WAL cannot use (a mapped network drive)', () => {
  it('a new project: its first start and every later one fall back, never exit', () => {
    const dir = onShare();
    for (const start of ['first', 'second']) {
      const opened = openDatabase({ projectPath: dir });
      try {
        expect(opened.path, start).toBe(resolveFallbackDbPath(dir));
        expect(opened.warning, start).toMatch(UNFIT);
        expect(opened.warning, start).toContain(`; history is kept in '${resolveFallbackDbPath(dir)}'.`);
        opened.db.exec('SELECT 1');
      } finally {
        opened.db.close();
      }
    }
  });

  it('db adopt says why a database there cannot be read, and registers nothing', () => {
    const dir = onShare();
    mkdirSync(join(dir, '.guardian'));
    // Written as 3.0.0 wrote it (rollback journal: the wrapper fails only WAL).
    const { DatabaseSync } = (
      process.getBuiltinModule('node:module') as typeof import('node:module')
    ).createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');
    const raw = new DatabaseSync(join(dir, '.guardian', 'guardian.db'));
    for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
    raw.close();

    const report = inspectProjectDatabase(dir);
    expect(report.status).toBe('foreign');
    expect(report.why).toMatch(UNFIT);
    expect(report.blockers.join('\n')).toMatch(UNFIT);
    expect(report.blockers.join('\n')).not.toMatch(/cannot be read \(disk I\/O error\)$/);
    expect(() => registerProjectDatabase(dir)).toThrow(UNFIT);
  });
});
