/**
 * A second PROCESS holding a SQLite write lock.
 *
 * Several processes open the same `.guardian/guardian.db` in real use (the
 * plugin's MCP server, a project-level one, the CLI). SQLite locks are held
 * per process, so the only honest way to test what one of them does while
 * another is mid-write is to have another process actually be mid-write. A
 * second connection in the same process would not do: the test thread would
 * block in the busy handler waiting for a lock that only the same, now
 * blocked, thread could release.
 */

import { spawn, type ChildProcess } from 'node:child_process';

// Commits after `ms` milliseconds, or — when `ms` is 'stdin' — as soon as a
// line arrives on stdin (see WriteLockHolder.release).
const HOLDER_SOURCE = `
const { DatabaseSync } = require('node:sqlite');
const [path, ms] = process.argv.slice(1);
const db = new DatabaseSync(path);
db.exec('PRAGMA busy_timeout = 5000');
db.exec('PRAGMA journal_mode = WAL');
db.exec('BEGIN IMMEDIATE');
const done = () => { db.exec('COMMIT'); db.close(); process.exit(0); };
process.stdout.write('locked\\n');
if (ms === 'stdin') process.stdin.once('data', done);
else setTimeout(done, Number(ms));
`;

export interface WriteLockHolder {
  child: ChildProcess;
  /** Commits and exits now (only meaningful for a holder started with 'stdin'). */
  release(): void;
  /** Resolves with the holder's exit code once it has released the lock. */
  released: Promise<number | null>;
}

/**
 * Starts a child that opens `dbPath`, takes the write lock with
 * `BEGIN IMMEDIATE`, and commits after `holdMs` — or, with `'stdin'`, when
 * `release()` is called. Resolves once the lock is actually held.
 */
export function holdWriteLock(dbPath: string, holdMs: number | 'stdin'): Promise<WriteLockHolder> {
  const child = spawn(process.execPath, ['-e', HOLDER_SOURCE, dbPath, String(holdMs)], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const released = new Promise<number | null>((resolve) => {
    child.on('exit', (code) => resolve(code));
  });
  const release = (): void => {
    child.stdin?.write('release\n');
  };
  return new Promise((resolve, reject) => {
    let out = '';
    let err = '';
    child.stdout?.on('data', (d: Buffer) => {
      out += d.toString();
      if (out.includes('locked')) resolve({ child, release, released });
    });
    child.stderr?.on('data', (d: Buffer) => {
      err += d.toString();
    });
    child.on('exit', (code) => {
      if (!out.includes('locked')) reject(new Error(`lock holder exited ${code} before locking: ${err}`));
    });
  });
}
