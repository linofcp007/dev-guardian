/**
 * `openDatabase`'s choice between `<project>/.guardian/guardian.db` and the
 * user-level fallback, when the project location cannot actually be written.
 *
 * A database left behind by a `sudo` or Docker run is the common real case:
 * the file (or `.guardian/`) belongs to another user. It used to open without
 * a warning — SQLite opens a read-only file read-only, silently — and then
 * crash startup at the first write. On Windows `accessSync(W_OK)` consults
 * only the read-only attribute, never the ACL, so the old up-front check
 * passed there too.
 */

import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { openDatabase, resolveFallbackDbPath } from '../../../src/storage/db.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../../helpers/tempDir.js';
import { holdWriteLock } from '../../helpers/writeLockHolder.js';

const undo: Array<() => void> = [];
afterEach(() => {
  for (const fn of undo.splice(0).reverse()) {
    try {
      fn();
    } catch {
      /* best-effort cleanup */
    }
  }
});
afterAll(cleanupTempDirs);

const isWindows = process.platform === 'win32';
// root ignores file modes, so a mode-based read-only fixture is writable to it.
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

function project(): string {
  const dir = makeTempDir('guardian-open-');
  undo.push(() => rmDir(dirname(resolveFallbackDbPath(dir))));
  return dir;
}

/** A primary database that opens and migrates normally, then closes. */
function existingDatabase(dir: string): string {
  const { db, path } = openDatabase({ projectPath: dir });
  db.close();
  return path;
}

/** Proves the handle can really be written through, not merely opened. */
function assertWritable(db: ReturnType<typeof openDatabase>['db']): void {
  db.prepare("INSERT INTO runtime_meta (key, value, updated_at) VALUES ('probe', '1', 'now')").run();
}

describe('openDatabase writability', () => {
  it('uses <project>/.guardian/guardian.db when it is writable, with no warning', () => {
    const dir = project();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(join(dir, '.guardian', 'guardian.db'));
      expect(opened.warning).toBeUndefined();
      assertWritable(opened.db);
    } finally {
      opened.db.close();
    }
  });

  it.skipIf(isRoot)('falls back, with a warning, when the database FILE is read-only', () => {
    const dir = project();
    const primary = existingDatabase(dir);
    chmodSync(primary, 0o444);
    undo.push(() => chmodSync(primary, 0o666));

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(/not writable/);
      assertWritable(opened.db);
    } finally {
      opened.db.close();
    }
  });

  it.runIf(isWindows)('falls back when an ACL denies writing to .guardian/ (accessSync cannot see ACLs)', () => {
    const dir = project();
    const guardian = join(dir, '.guardian');
    mkdirSync(guardian);
    const deny = spawnSync('icacls', [guardian, '/deny', '*S-1-1-0:(OI)(CI)(W,D,DC)'], { encoding: 'utf8' });
    expect(deny.status, deny.stderr).toBe(0);
    undo.push(() => spawnSync('icacls', [guardian, '/remove:d', '*S-1-1-0']));

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(/not writable/);
      assertWritable(opened.db);
    } finally {
      opened.db.close();
    }
  });

  it.runIf(!isWindows && !isRoot)('falls back when .guardian/ itself is not writable', () => {
    const dir = project();
    const guardian = join(dir, '.guardian');
    mkdirSync(guardian);
    chmodSync(guardian, 0o555);
    undo.push(() => chmodSync(guardian, 0o755));

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(/not writable/);
      assertWritable(opened.db);
    } finally {
      opened.db.close();
    }
  });

  it('does not mistake a write lock held by another process for a read-only database', async () => {
    const dir = project();
    const primary = existingDatabase(dir);
    const holder = await holdWriteLock(primary, 'stdin');
    try {
      const opened = openDatabase({ projectPath: dir });
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
      opened.db.close();
    } finally {
      holder.release();
      await holder.released;
    }
  }, 20_000);

  it('leaves no probe file behind in .guardian/', () => {
    const dir = project();
    openDatabase({ projectPath: dir }).db.close();
    expect(readdirSync(join(dir, '.guardian')).filter((f) => f.includes('probe'))).toEqual([]);
  });
});
