/**
 * The MCP server's own process lifecycle — startup against a shared
 * database, and exits. Runs `src/server.ts` in a real child process: every
 * behaviour here is about the process (its exit code, its stderr, a lock
 * another process holds), which nothing in-process can observe.
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { GuardianDatabase, openDatabase } from '../../src/storage/db.js';
import { listMigrations } from '../../src/storage/migrations/runner.js';
import { registerInPlace } from '../helpers/registerInPlace.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../helpers/tsxNode.js';
import { holdWriteLock } from '../helpers/writeLockHolder.js';

afterAll(cleanupTempDirs);

const SERVER = join(MCP_ROOT, 'src', 'server.ts');

interface ServerRun {
  child: ChildProcess;
  stderr(): string;
  exited: Promise<number | null>;
  /** Resolves once stderr matches `pattern`; rejects if the server exits first or on timeout. */
  waitFor(pattern: RegExp, timeoutMs?: number): Promise<void>;
}

const running: ChildProcess[] = [];
afterEach(() => {
  for (const child of running.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
});

function startServer(cwd: string, nodeArgs: string[] = [], env: Record<string, string> = {}): ServerRun {
  const child = spawn(process.execPath, [...nodeArgs, ...TSX_NODE_ARGS, SERVER], {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, ...env },
  });
  running.push(child);
  let err = '';
  const waiters: Array<() => void> = [];
  child.stderr?.on('data', (d: Buffer) => {
    err += d.toString();
    for (const w of waiters) w();
  });
  const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)));
  return {
    child,
    stderr: () => err,
    exited,
    waitFor(pattern, timeoutMs = 30_000) {
      return new Promise((resolve, reject) => {
        const check = (): void => {
          if (pattern.test(err)) resolve();
        };
        waiters.push(check);
        check();
        const timer = setTimeout(() => reject(new Error(`timed out waiting for ${pattern}; stderr:\n${err}`)), timeoutMs);
        void exited.then((code) => {
          clearTimeout(timer);
          if (!pattern.test(err)) reject(new Error(`server exited ${code} before ${pattern}; stderr:\n${err}`));
        });
      });
    },
  };
}

/** The pid of a process that has already exited. */
function deadPid(): number {
  const r = spawnSync(process.execPath, ['-e', '']);
  if (typeof r.pid !== 'number') throw new Error('could not spawn a short-lived child');
  return r.pid;
}

describe('server startup against a database another process is writing to', () => {
  it('waits out a held write lock, reaps the dead scan and starts, instead of exiting 1', async () => {
    const project = makeTempDir('guardian-server-lock-');
    const { db, path } = openDatabase({ projectPath: project });
    db.prepare(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, status, owner_pid, owner_host)
       VALUES ('orphan', 'sast', ?, 'h', ?, 'running', ?, ?)`,
    ).run(project, new Date().toISOString(), deadPid(), hostname());
    db.close();

    const holder = await holdWriteLock(path, 'stdin');
    const server = startServer(project);
    try {
      await server.waitFor(/db opened/);
      // The reaper is now waiting for the lock. Hold it a little longer, then let go.
      await new Promise((r) => setTimeout(r, 500));
      holder.release();
      await server.waitFor(/listening on stdio/);
      expect(server.stderr()).toMatch(/reaped 1 orphaned scan/);
    } finally {
      holder.release();
      await holder.released;
    }
  }, 60_000);
});

describe('server startup with a retention backlog', () => {
  // Retention used to run synchronously before the transport connected, and
  // to loop until nothing was left — measured 21.5 s for 2950 scans over 60k
  // legacy CVE rows — so a large backlog delayed the server's first answer.
  it('connects first and prunes afterwards, in the background', async () => {
    const project = makeTempDir('guardian-server-retention-');
    const { db } = openDatabase({ projectPath: project });
    for (let i = 0; i < 3; i++) {
      db.prepare(
        `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, status)
         VALUES (?, 'sast', ?, 'h', ?, 'completed')`,
      ).run(`old-${i}`, project, new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString());
    }
    db.close();

    const server = startServer(project, [], { GUARDIAN_RETENTION_SCANS: '1' });
    await server.waitFor(/pruned 2 scan\(s\)/);

    const log = server.stderr();
    expect(log.indexOf('listening on stdio')).toBeGreaterThan(-1);
    expect(log.indexOf('listening on stdio')).toBeLessThan(log.indexOf('pruned 2 scan(s)'));
  }, 60_000);
});

describe('server startup against a 3.0 development database', () => {
  // A database a 3.0 development branch left at schema version 14 without
  // 012's tables: 3.0.0's runner skipped 012 for good, `new Storage()` died
  // on `no such table: mcp_tool_pins`, and the server exited 1 at startup.
  it('applies the migrations a registered database never ran, and starts', async () => {
    const project = makeTempDir('guardian-server-devdb-');
    expect(spawnSync('git', ['init', '-q'], { cwd: project }).status).toBe(0);
    const dbPath = join(project, '.guardian', 'guardian.db');
    mkdirSync(join(project, '.guardian'));
    const raw = new GuardianDatabase(dbPath);
    for (const m of listMigrations().filter((x) => x.version <= 14 && x.version !== 12 && x.version !== 13)) {
      raw.exec(readFileSync(m.filePath, 'utf8'));
    }
    raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '14')`);
    raw.close();
    // Registered as the user's (what `db adopt --yes` does; nothing is
    // adopted automatically), not migrated.
    registerInPlace(dbPath, project);

    const server = startServer(project);
    await server.waitFor(/listening on stdio/);
    expect(server.stderr()).not.toMatch(/fatal/);
    expect(server.stderr()).toContain(`db opened: ${dbPath}`);
    expect(server.stderr()).not.toMatch(/db warning/);
  }, 60_000);

  it('a database from 3.0.0 is not opened: the server starts on the fallback and names `db adopt --yes`', async () => {
    const project = makeTempDir('guardian-server-legacy-');
    expect(spawnSync('git', ['init', '-q'], { cwd: project }).status).toBe(0);
    const dbPath = join(project, '.guardian', 'guardian.db');
    mkdirSync(join(project, '.guardian'));
    const raw = new GuardianDatabase(dbPath);
    for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
    raw.close();

    const server = startServer(project);
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toContain(`db opened: ${dbPath}`);
    expect(err).toMatch(/db warning: This project's database .* was created before dev-guardian 3\.0\.1/);
    expect(err).toMatch(/db adopt --project ".+" --yes` once/);
  }, 60_000);

  it('a registered database the migrations cannot repair is never fatal: in memory, naming the file and what is missing', async () => {
    const project = makeTempDir('guardian-server-badschema-');
    const { db, path } = openDatabase({ projectPath: project });
    db.exec('ALTER TABLE findings DROP COLUMN cwe');
    db.close();

    const server = startServer(project);
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toMatch(/fatal/);
    expect(err).toContain('db opened: :memory:');
    expect(err).toContain(`the database '${path}' is missing column findings.cwe`);
    expect(err).toMatch(/history will not persist/);
  }, 60_000);

  it('a database git tracks is not opened: the server starts on the per-user fallback and says why', async () => {
    const project = makeTempDir('guardian-server-tracked-');
    expect(spawnSync('git', ['init', '-q'], { cwd: project }).status).toBe(0);
    const { db, path } = openDatabase({ projectPath: project });
    db.close();
    expect(spawnSync('git', ['add', '-f', '.guardian/guardian.db'], { cwd: project }).status).toBe(0);

    const server = startServer(project);
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toContain(`db opened: ${path}`);
    expect(err).toMatch(/db warning: .*git tracks \.guardian\/guardian\.db/);
  }, 60_000);

  it('a per-user data directory that cannot be created is never fatal: the server starts on an in-memory database and says so', async () => {
    // Round 5, reproduced in Docker node:22 as uid 4242 with no passwd
    // entry (HOME=/): `fatal: Error: EACCES: permission denied, mkdir
    // '/.local/share/dev-guardian'`, exit 1, where 3.0.0 opened the project
    // database. A file where the directory should be is the same failure on
    // every platform.
    const project = makeTempDir('guardian-server-nodatadir-');
    const blocker = join(makeTempDir('guardian-server-blocker-'), 'not-a-directory');
    writeFileSync(blocker, 'x');

    const server = startServer(project, [], { GUARDIAN_DATA_DIR: join(blocker, 'dev-guardian') });
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toMatch(/fatal/);
    expect(err).toContain('db opened: :memory:');
    expect(err).toMatch(/db warning: .*history will not persist: .*; set GUARDIAN_DATA_DIR to a writable directory/);
    // Not silently the project's own database either: nothing written there.
    expect(existsSync(join(project, '.guardian', 'guardian.db'))).toBe(false);
  }, 60_000);

  // Round 6: an unreadable database stopped the server (exit 1). It never
  // does now — in a clone of a repository that committed one, git decides
  // before the bytes are read; the user's own registered one gives way to an
  // in-memory database with a warning saying to move it aside.
  it('8 KB of random bytes committed, in a clone: the server starts on the fallback', async () => {
    const origin = makeTempDir('guardian-server-origin-');
    expect(spawnSync('git', ['init', '-q'], { cwd: origin }).status).toBe(0);
    mkdirSync(join(origin, '.guardian'));
    writeFileSync(join(origin, '.guardian', 'guardian.db'), randomBytes(8 * 1024));
    expect(spawnSync('git', ['add', '-f', '.guardian/guardian.db'], { cwd: origin }).status).toBe(0);
    expect(
      spawnSync('git', ['-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '-m', 'db'], { cwd: origin })
        .status,
    ).toBe(0);
    const clone = `${origin}-clone`;
    expect(spawnSync('git', ['clone', '-q', origin, clone]).status).toBe(0);

    const server = startServer(clone);
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toMatch(/fatal/);
    expect(err).toMatch(/db warning: .*git tracks \.guardian\/guardian\.db/);
  }, 60_000);

  it("the user's own database, corrupted: the server starts in memory, and the warning names the file and says to move it aside", async () => {
    const project = makeTempDir('guardian-server-corrupt-');
    const { db, path } = openDatabase({ projectPath: project });
    db.close();
    for (const side of ['-wal', '-shm']) rmSync(`${path}${side}`, { force: true });
    writeFileSync(path, Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), Buffer.alloc(8 * 1024 - 16)]));

    const server = startServer(project);
    await server.waitFor(/listening on stdio/);
    const err = server.stderr();
    expect(err).not.toMatch(/fatal/);
    expect(err).toContain('db opened: :memory:');
    expect(err).toContain(`the database '${path}' cannot be read`);
    expect(err).toMatch(/Move it aside/);
    expect(err).not.toMatch(/\n\s+at /);
  }, 60_000);
});

// Stands in for Node < 22.13, where `node:sqlite` is missing (or needs
// --experimental-sqlite): any require of it fails the way Node itself does.
const BLOCK_NODE_SQLITE = `
const Module = require('node:module');
const load = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'node:sqlite') {
    const error = new Error('No such built-in module: node:sqlite');
    error.code = 'ERR_UNKNOWN_BUILTIN_MODULE';
    throw error;
  }
  return load.call(this, request, ...rest);
};
`;

const INITIALIZE =
  JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
  }) + '\n';

describe('server exits', () => {
  it('exits 1 with a one-line explanation when node:sqlite is unavailable', async () => {
    const project = makeTempDir('guardian-server-nosqlite-');
    const preload = join(project, 'no-node-sqlite.cjs');
    writeFileSync(preload, BLOCK_NODE_SQLITE);

    const server = startServer(project, ['--require', preload]);
    expect(await server.exited).toBe(1);
    expect(server.stderr()).toContain('dev-guardian requires Node.js >= 22.13 (node:sqlite)');
    expect(server.stderr()).not.toContain('ERR_UNKNOWN_BUILTIN_MODULE');
  }, 60_000);

  it('exits 0 when the client closes stdout, instead of crashing on an unhandled EPIPE', async () => {
    const project = makeTempDir('guardian-server-epipe-');
    const server = startServer(project);
    await server.waitFor(/listening on stdio/);

    // The client goes away: its end of our stdout closes. The next response
    // the server writes hits a closed pipe.
    server.child.stdout?.destroy();
    server.child.stdin?.write(INITIALIZE);

    expect(await server.exited).toBe(0);
    expect(server.stderr()).not.toMatch(/Unhandled 'error' event/);
    expect(server.stderr()).toMatch(/EPIPE/);
  }, 60_000);
});
