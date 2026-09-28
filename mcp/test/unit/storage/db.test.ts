import { createRequire } from 'node:module';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { holdWriteLock } from '../../helpers/writeLockHolder.js';

afterAll(cleanupTempDirs);

// A raw second connection, deliberately NOT a GuardianDatabase: it must not
// wait for locks, so "is the write lock held right now?" is answered
// immediately rather than after the busy timeout.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

function tempDbPath(): string {
  return join(makeTempDir('guardian-db-'), 'guardian.db');
}

/** True when another connection currently holds the write lock on `path`. */
function writeLockIsHeld(path: string): boolean {
  const probe = new DatabaseSync(path);
  try {
    probe.exec('PRAGMA busy_timeout = 0');
    probe.exec('BEGIN IMMEDIATE');
    probe.exec('ROLLBACK');
    return false;
  } catch (error) {
    if (error instanceof Error && /database is locked/.test(error.message)) return true;
    throw error;
  } finally {
    probe.close();
  }
}

/** A table whose trigger makes SQLite itself roll back the whole transaction. */
function withRollbackTrigger(db: GuardianDatabase): void {
  db.exec(`
    CREATE TABLE t (x TEXT);
    CREATE TRIGGER t_guard BEFORE INSERT ON t WHEN NEW.x = 'boom'
    BEGIN SELECT RAISE(ROLLBACK, 'guard fired'); END;
  `);
}

describe('GuardianDatabase busy timeout', () => {
  it('opens every connection with a 5000 ms busy timeout', () => {
    const db = new GuardianDatabase(tempDbPath());
    const row = db.prepare<[], { timeout: number }>('PRAGMA busy_timeout').get();
    expect(row?.timeout).toBe(5000);
    db.close();
  });

  it('waits for another process to release its write lock instead of failing at once', async () => {
    const path = tempDbPath();
    const setup = new GuardianDatabase(path);
    setup.exec('PRAGMA journal_mode = WAL; CREATE TABLE t (x TEXT)');
    setup.close();

    const holder = await holdWriteLock(path, 1000);
    const db = new GuardianDatabase(path);
    try {
      expect(() => db.prepare("INSERT INTO t VALUES ('after the lock')").run()).not.toThrow();
    } finally {
      db.close();
      await holder.released;
    }
  }, 20_000);
});

describe('GuardianDatabase.transaction', () => {
  it('takes the write lock when the transaction starts (BEGIN IMMEDIATE), not at its first write', () => {
    const path = tempDbPath();
    const db = new GuardianDatabase(path);
    db.exec('PRAGMA journal_mode = WAL; CREATE TABLE t (x TEXT)');
    let heldInside = false;
    db.transaction(() => {
      heldInside = writeLockIsHeld(path);
    })();
    expect(heldInside).toBe(true);
    expect(writeLockIsHeld(path)).toBe(false);
    db.close();
  });

  it('rethrows the original error when SQLite has already rolled the transaction back', () => {
    const db = new GuardianDatabase(':memory:');
    withRollbackTrigger(db);
    const tx = db.transaction(() => {
      db.prepare("INSERT INTO t VALUES ('kept?')").run();
      db.prepare("INSERT INTO t VALUES ('boom')").run();
    });
    expect(() => tx()).toThrow(/guard fired/);
    expect(db.prepare<[], { n: number }>('SELECT COUNT(*) AS n FROM t').get()?.n).toBe(0);
  });

  it('rethrows the original error from a nested transaction whose outer one SQLite rolled back', () => {
    const db = new GuardianDatabase(':memory:');
    withRollbackTrigger(db);
    const inner = db.transaction(() => {
      db.prepare("INSERT INTO t VALUES ('boom')").run();
    });
    const outer = db.transaction(() => {
      db.prepare("INSERT INTO t VALUES ('outer')").run();
      inner();
    });
    expect(() => outer()).toThrow(/guard fired/);
    expect(db.prepare<[], { n: number }>('SELECT COUNT(*) AS n FROM t').get()?.n).toBe(0);
  });

  it('restores its nesting depth after a failure, so the next transaction is a real one again', () => {
    const path = tempDbPath();
    const db = new GuardianDatabase(path);
    db.exec('PRAGMA journal_mode = WAL');
    withRollbackTrigger(db);
    expect(() =>
      db.transaction(() => {
        db.prepare("INSERT INTO t VALUES ('boom')").run();
      })(),
    ).toThrow(/guard fired/);

    // A leaked depth would make this a SAVEPOINT — a deferred transaction
    // that holds no write lock until its first write.
    let heldInside = false;
    db.transaction(() => {
      heldInside = writeLockIsHeld(path);
      db.prepare("INSERT INTO t VALUES ('after')").run();
    })();
    expect(heldInside).toBe(true);
    expect(db.prepare<[], { x: string }>('SELECT x FROM t').all()).toEqual([{ x: 'after' }]);
    db.close();
  });

  it('still rolls back and rethrows an ordinary error thrown by the callback', () => {
    const db = new GuardianDatabase(':memory:');
    db.exec('CREATE TABLE t (x TEXT)');
    expect(() =>
      db.transaction(() => {
        db.prepare("INSERT INTO t VALUES ('gone')").run();
        throw new Error('callback failed');
      })(),
    ).toThrow('callback failed');
    expect(db.prepare<[], { n: number }>('SELECT COUNT(*) AS n FROM t').get()?.n).toBe(0);
  });
});
