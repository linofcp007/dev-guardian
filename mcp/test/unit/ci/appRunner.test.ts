/**
 * `startApp`/`RunningApp.stop` tested against REAL child processes — small
 * `node -e` programs, never a mock (design doc §8, task brief). What this
 * module exists to prove is PROCESS BEHAVIOUR — did the tree actually die,
 * did a metacharacter actually reach the child as inert data — and a mock
 * proves none of that.
 *
 * Every "server" fixture also spawns its OWN grandchild and reports both
 * pids to a file, so "stop() kills the tree" is checked against a SECOND,
 * independently-verifiable process, not just the one `startApp` spawned
 * directly. That is the exact gap the brief calls out: `npm start` spawns a
 * grandchild that does the actual listening; an implementation that kills
 * only the direct child would pass a test that only inspects that one pid
 * while leaving the real server running and the port held.
 *
 * ---- Platform note (see the task report for the full discussion) --------
 *
 * This suite runs on whatever platform executes it. `appRunner.ts` branches
 * internally on `process.platform`: Windows kills the tree via
 * `taskkill /T /F`; POSIX signals a negative pid (the process group made by
 * `detached: true` at spawn). On THIS machine (Windows), every test below
 * exercises the `taskkill` branch. The POSIX branch is implemented against
 * the standard, documented technique but is NOT exercised by any run in this
 * environment — only a Linux runner executing this same file would prove it.
 */
import { createServer, type Server } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startApp } from '../../../src/ci/appRunner.js';

/* ------------------------------------------------------------------ */
/* Fixture scripts — plain `node -e` programs, no dependencies.        */
/* ------------------------------------------------------------------ */

/**
 * Spawns a grandchild immediately, reports `{ parent, grandchild }` pids to
 * `argv[2]` (a file path), then — after an optional `argv[3]` millisecond
 * delay (default 0) — starts listening on `argv[1]` and answers 200 to
 * anything. The delay exists for exactly one test: proving `startApp`
 * genuinely WAITS for the health check rather than resolving the instant
 * the process is spawned.
 *
 * The grandchild is spawned `detached: true` — DELIBERATELY, not
 * incidentally. Verified directly (see the task report) that on Windows,
 * Node's OWN default (non-detached) child spawning already wraps every
 * descendant in a cascading Job Object, so killing only a direct child
 * ALSO kills a plain, non-detached grandchild automatically — a fixture
 * built that way would pass even against a wrong, non-tree-aware kill and
 * prove nothing. A `detached` grandchild breaks that incidental cascade
 * (confirmed empirically) and is itself a realistic stand-in for a process
 * manager that intentionally detaches what it launches — which is exactly
 * the case `killTree`'s Windows `/T` flag (a PPID-table walk, independent
 * of Job Object membership) exists to still reach.
 */
const GOOD_APP_SCRIPT = `
const { createServer } = require('node:http');
const { spawn } = require('node:child_process');
const { writeFileSync } = require('node:fs');
const port = Number(process.argv[1]);
const pidfile = process.argv[2];
const delayMs = Number(process.argv[3] || '0');
const gc = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60000);'], { stdio: 'ignore', detached: true });
gc.unref();
gc.on('spawn', () => {
  writeFileSync(pidfile, JSON.stringify({ parent: process.pid, grandchild: gc.pid }));
  setTimeout(() => {
    createServer((req, res) => { res.writeHead(200); res.end('ok'); }).listen(port, '127.0.0.1');
  }, delayMs);
});
`;

/**
 * Spawns a `detached` grandchild immediately (see GOOD_APP_SCRIPT's comment
 * on why), reports pids to `argv[1]`, then never listens anywhere and never
 * exits on its own — for the timeout tests.
 */
const NEVER_ANSWERS_SCRIPT = `
const { spawn } = require('node:child_process');
const { writeFileSync } = require('node:fs');
const pidfile = process.argv[1];
const gc = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60000);'], { stdio: 'ignore', detached: true });
gc.unref();
gc.on('spawn', () => {
  writeFileSync(pidfile, JSON.stringify({ parent: process.pid, grandchild: gc.pid }));
});
setInterval(() => {}, 60000);
`;

/** Exits immediately with a nonzero code, never listening — for the
 *  "detects a crash before it wastes the full timeout" test. No grandchild:
 *  irrelevant to what that test checks. */
const CRASHES_IMMEDIATELY_SCRIPT = `process.exit(7);`;

/**
 * Writes `argv[3]` (a caller-supplied value, verbatim) to `argv[2]`, then
 * listens on `argv[1]`. Used to prove an argument survives exactly as given
 * — the load-bearing fixture for the no-shell test.
 */
const ECHO_ARGV_SCRIPT = `
const { createServer } = require('node:http');
const { writeFileSync } = require('node:fs');
const port = Number(process.argv[1]);
const outFile = process.argv[2];
const sentinel = process.argv[3] === undefined ? '' : process.argv[3];
writeFileSync(outFile, sentinel);
createServer((req, res) => { res.writeHead(200); res.end('ok'); }).listen(port, '127.0.0.1');
`;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

async function getFreePort(): Promise<number> {
  const probe: Server = createServer();
  await new Promise<void>((resolvePort, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => resolvePort());
  });
  const addr = probe.address();
  await new Promise<void>((resolveClose) => probe.close(() => resolveClose()));
  if (addr === null || typeof addr === 'string') {
    throw new Error('getFreePort: no address');
  }
  return addr.port;
}

/** `process.kill(pid, 0)` sends no signal — it is a pure existence check,
 *  and Node implements it consistently on Windows and POSIX alike (verified
 *  directly against a real spawned/killed process on this machine before
 *  relying on it here — see the task report). */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitUntilDead(pid: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (isAlive(pid)) {
    if (Date.now() >= deadline) {
      throw new Error(`pid ${pid} is still alive ${timeoutMs}ms after it should have been killed`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

interface PidPair {
  parent: number;
  grandchild: number;
}

function isPidPair(x: unknown): x is PidPair {
  if (typeof x !== 'object' || x === null) return false;
  const rec = x as Record<string, unknown>;
  return typeof rec['parent'] === 'number' && typeof rec['grandchild'] === 'number';
}

/** Polls for the fixture's pidfile rather than assuming a fixed delay —
 *  spawning the grandchild is a single OS call, not the thing under test,
 *  so it is always ready long before any of this suite's timeouts. */
async function waitForPidfile(path: string, timeoutMs = 5_000): Promise<PidPair> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (existsSync(path)) {
      try {
        const data: unknown = JSON.parse(readFileSync(path, 'utf8'));
        if (isPidPair(data)) return data;
      } catch {
        /* write still in flight; retry */
      }
    }
    if (Date.now() >= deadline) {
      throw new Error(`pidfile ${path} did not appear within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

/* ------------------------------------------------------------------ */

describe('startApp', () => {
  let workDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), 'guardian-app-runner-'));
  });

  afterEach(() => {
    try {
      rmSync(workDir, { recursive: true, force: true });
    } catch {
      /* best-effort — a locked handle here is a leak to notice, not a
       * reason to fail an unrelated test */
    }
  });

  it('resolves once the health url answers', async () => {
    const port = await getFreePort();
    const pidfile = join(workDir, 'pids.json');
    // Guards the wrong implementation that resolves the instant the process
    // is spawned instead of actually polling: the fixture only starts
    // listening 300ms after spawn, so a premature resolve would make this
    // assertion fail, not merely leave it unproven.
    const delayMs = 300;
    const started = Date.now();
    const app = await startApp({
      command: ['node', '-e', GOOD_APP_SCRIPT, String(port), pidfile, String(delayMs)],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    try {
      const elapsed = Date.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(delayMs - 75);

      // "Resolved" alone would also be true of a stub that never spawns
      // anything real. Prove the process this command names is genuinely
      // running: the pidfile only exists once the fixture's own
      // spawn-then-listen sequence has completed.
      const pids: PidPair = JSON.parse(readFileSync(pidfile, 'utf8'));
      expect(typeof pids.parent).toBe('number');
      expect(isAlive(pids.parent)).toBe(true);
    } finally {
      await app.stop();
    }
  });

  it('rejects with a clear error when the health url never answers', async () => {
    const pidfile = join(workDir, 'pids.json');
    // A hang is the worst failure mode in CI: the job burns its whole
    // budget and the log says nothing. Port 1 is reserved and never
    // listening (same convention as dast/probe.test.ts's own
    // "records a network error" test).
    await expect(
      startApp({
        command: ['node', '-e', NEVER_ANSWERS_SCRIPT, pidfile],
        cwd: workDir,
        healthUrl: 'http://127.0.0.1:1/',
        timeoutMs: 300,
      }),
    ).rejects.toThrow(/timed out/i);
  });

  it('kills the process on timeout, leaving nothing running', async () => {
    const pidfile = join(workDir, 'pids.json');
    const pending = startApp({
      command: ['node', '-e', NEVER_ANSWERS_SCRIPT, pidfile],
      cwd: workDir,
      healthUrl: 'http://127.0.0.1:1/',
      timeoutMs: 500,
    });
    // Attach a handler immediately so the eventual rejection is never
    // "unhandled" while this test is busy polling for the pidfile below,
    // concurrently, before `pending` itself is awaited.
    const settled = pending.then(
      () => {
        throw new Error('expected startApp to reject');
      },
      (e: unknown) => e,
    );

    const pids = await waitForPidfile(pidfile);
    // Confirms the fixture is genuinely alive BEFORE the kill — otherwise
    // "dead afterward" would be true for a reason that has nothing to do
    // with `startApp`'s own cleanup.
    expect(isAlive(pids.parent)).toBe(true);
    expect(isAlive(pids.grandchild)).toBe(true);

    const error = await settled;
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/timed out/i);

    // The assertion that matters: capture the pid, await the rejection,
    // then assert the process is genuinely gone. A wrong implementation
    // that kills only the direct child leaves `pids.grandchild` alive —
    // exactly the `npm start` scenario the brief names — and only THIS
    // second check catches it; an assertion that only checks the rejection
    // proves nothing about either process.
    await waitUntilDead(pids.parent);
    await waitUntilDead(pids.grandchild);
  });

  it('rejects immediately — not after the full timeout — when the process exits before ever answering', async () => {
    // Guards a DIFFERENT wrong implementation than the timeout test above:
    // one that only polls the health url and never notices the process
    // underneath it already died, so a crash-on-boot (missing dependency,
    // syntax error) would look exactly like a hang for the FULL timeout
    // instead of failing fast with a specific reason.
    const started = Date.now();
    await expect(
      startApp({
        command: ['node', '-e', CRASHES_IMMEDIATELY_SCRIPT],
        cwd: workDir,
        healthUrl: 'http://127.0.0.1:1/',
        timeoutMs: 5_000,
      }),
    ).rejects.toThrow(/exit(ed)? code 7/i);
    // "Immediately" pinned as a real number, not just inferred from the
    // message: a generous ceiling well under the 5s timeoutMs above — if
    // this ever regresses to waiting out the full timeout, this assertion
    // fails even though the rejection message alone would still look right.
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('stop() leaves nothing running, and is safe to call twice', async () => {
    const port = await getFreePort();
    const pidfile = join(workDir, 'pids.json');
    const app = await startApp({
      command: ['node', '-e', GOOD_APP_SCRIPT, String(port), pidfile],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    const pids: PidPair = JSON.parse(readFileSync(pidfile, 'utf8'));

    await app.stop();
    await waitUntilDead(pids.parent);
    await waitUntilDead(pids.grandchild);

    // Idempotent: the CLI calls stop() in a `finally`, and it may already
    // have run once on a timeout path. Must not throw, hang, or attempt to
    // re-signal an already-dead pid in a way that surfaces as a rejection.
    await expect(app.stop()).resolves.toBeUndefined();
  });

  it('never uses a shell — a metacharacter in an argument is passed literally', async () => {
    // Guards the wrong implementation that joins argv into a string (and,
    // realistically, would need `shell: true` to do anything useful with
    // it): the child must receive this exact string as ONE argv element,
    // never interpreted. Meaningful to both POSIX sh (`;`, `&&`, `|`,
    // `$()`, backticks) and Windows cmd.exe (`&`, `|`), so the property
    // holds regardless of which shell a broken implementation would reach.
    const sentinel = 'inject; rm -rf . && echo pwned | tee owned.txt & echo $(whoami) `id`';
    const port = await getFreePort();
    const outFile = join(workDir, 'argv-out.txt');
    const app = await startApp({
      command: ['node', '-e', ECHO_ARGV_SCRIPT, String(port), outFile, sentinel],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    try {
      expect(readFileSync(outFile, 'utf8')).toBe(sentinel);
      // Belt-and-braces: confirm the sentinel's own "pwned" side effect
      // never actually happened, not just that the file compares equal.
      expect(existsSync(join(workDir, 'owned.txt'))).toBe(false);
    } finally {
      await app.stop();
    }
  });
});
