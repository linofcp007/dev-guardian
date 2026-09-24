/**
 * A second PROCESS holding a SQLite write lock for a fixed time.
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

const HOLDER_SOURCE = `
const { DatabaseSync } = require('node:sqlite');
const [path, ms] = process.argv.slice(1);
const db = new DatabaseSync(path);
db.exec('PRAGMA busy_timeout = 5000');
db.exec('PRAGMA journal_mode = WAL');
db.exec('BEGIN IMMEDIATE');
process.stdout.write('locked\\n');
setTimeout(() => { db.exec('COMMIT'); db.close(); process.exit(0); }, Number(ms));
`;

export interface WriteLockHolder {
  child: ChildProcess;
  /** Resolves with the holder's exit code once it has released the lock. */
  released: Promise<number | null>;
}

/**
 * Starts a child that opens `dbPath`, takes the write lock with
 * `BEGIN IMMEDIATE`, and commits after `holdMs`. Resolves once the lock is
 * actually held.
 */
export function holdWriteLock(dbPath: string, holdMs: number): Promise<WriteLockHolder> {
  const child = spawn(process.execPath, ['-e', HOLDER_SOURCE, dbPath, String(holdMs)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const released = new Promise<number | null>((resolve) => {
    child.on('exit', (code) => resolve(code));
  });
  return new Promise((resolve, reject) => {
    let out = '';
    let err = '';
    child.stdout?.on('data', (d: Buffer) => {
      out += d.toString();
      if (out.includes('locked')) resolve({ child, released });
    });
    child.stderr?.on('data', (d: Buffer) => {
      err += d.toString();
    });
    child.on('exit', (code) => {
      if (!out.includes('locked')) reject(new Error(`lock holder exited ${code} before locking: ${err}`));
    });
  });
}
