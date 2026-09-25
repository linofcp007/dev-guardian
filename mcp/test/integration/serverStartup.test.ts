/**
 * The MCP server's own process lifecycle — startup against a shared
 * database, and exits. Runs `src/server.ts` in a real child process: every
 * behaviour here is about the process (its exit code, its stderr, a lock
 * another process holds), which nothing in-process can observe.
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { openDatabase } from '../../src/storage/db.js';
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

function startServer(cwd: string, nodeArgs: string[] = []): ServerRun {
  const child = spawn(process.execPath, [...nodeArgs, ...TSX_NODE_ARGS, SERVER], {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
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
