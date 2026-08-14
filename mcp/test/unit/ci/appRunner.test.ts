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
 * exercises the `taskkill` branch. A prior round of this task ran the
 * identical fixtures inside a real `node:22` Linux container to exercise the
 * POSIX branch directly (see the task report) — that run is what caught a
 * real defect in the FIXTURES below, not the runtime: see the grandchild's
 * `detached` comment.
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
 * The grandchild's OWN `detached` flag is platform-conditional —
 * `process.platform === 'win32'` — and this is corrective, not
 * decorative: a prior round shipped it unconditionally `true`, reasoned
 * to be "the harder case everywhere". A real `node:22` Linux container
 * proved that reasoning wrong (coordinator review, Finding 1): on POSIX,
 * `detached: true` calls `setsid()`, which puts the grandchild in *its
 * own* new process group — `killTree`'s negative-pid signal targets the
 * PARENT's group and can never reach a process that left it, by
 * construction. The container's own process table showed it plainly:
 * grandchild PGID 23 vs parent PGID 15. Making the grandchild
 * `detached: true` on POSIX does not model `npm start` harder; it models
 * something `killTree` was never able to reach, on any platform, and
 * asserts that it does. On WINDOWS specifically, `detached: true` for the
 * grandchild is still exactly right and still necessary: Node's own
 * default (non-detached) child spawning already wraps every descendant in
 * a cascading Job Object there, so a PLAIN grandchild would be killed
 * incidentally by the OS regardless of whether `killTree`'s `/T` flag
 * does anything at all — confirmed empirically (three levels of plain
 * Node-spawns-Node, killing only the top pid, still killed all three) —
 * so only a `detached` grandchild defeats that incidental cascade and
 * makes the Windows assertion mean anything. Each platform's fixture
 * therefore has to defeat THAT platform's own incidental cleanup, which is
 * a different flag on each: `win32` needs `detached: true` to escape the
 * Job Object; POSIX needs `detached: false` (default) to STAY in the
 * parent's process group, because that is the one `killTree` can reach and
 * the one a real `npm start` grandchild is actually in.
 */
const GOOD_APP_SCRIPT = `
const { createServer } = require('node:http');
const { spawn } = require('node:child_process');
const { writeFileSync } = require('node:fs');
const port = Number(process.argv[1]);
const pidfile = process.argv[2];
const delayMs = Number(process.argv[3] || '0');
const gc = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60000);'], { stdio: 'ignore', detached: process.platform === 'win32' });
gc.unref();
gc.on('spawn', () => {
  writeFileSync(pidfile, JSON.stringify({ parent: process.pid, grandchild: gc.pid }));
  setTimeout(() => {
    createServer((req, res) => { res.writeHead(200); res.end('ok'); }).listen(port, '127.0.0.1');
  }, delayMs);
});
`;

/**
 * Spawns a grandchild immediately (platform-conditional `detached` — see
 * GOOD_APP_SCRIPT's comment on why), reports pids to `argv[1]`, then never
 * listens anywhere and never exits on its own — for the timeout tests.
 */
const NEVER_ANSWERS_SCRIPT = `
const { spawn } = require('node:child_process');
const { writeFileSync } = require('node:fs');
const pidfile = process.argv[1];
const gc = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60000);'], { stdio: 'ignore', detached: process.platform === 'win32' });
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
 * Writes a distinctive line to stderr, then exits nonzero — for the
 * output-tail test (coordinator review, Finding 7). Sets `exitCode` rather
 * than calling `process.exit()` directly so the write is never racing its
 * own exit — the same truncation risk this task's own `unref()` finding is
 * a cousin of; a test fixture is not exempt from it.
 *
 * The marker string is assembled with `.join(': ')` rather than written as
 * one literal — DELIBERATELY: `startApp`'s error messages always echo the
 * command itself (`opts.command.join(' ')`, which for a `-e` command
 * includes this very script's source text), so a literal
 * `'FATAL: port 9999 already in use'` in the source would make the
 * test's regex match the ECHOED COMMAND even with NO output captured at
 * all — a vacuous assertion that would have shipped were it not for the
 * mutation check in the task report: reverting the capture to
 * `stdio: 'ignore'` did NOT turn this test red on the first attempt, for
 * exactly that reason. Assembled at runtime, the joined phrase exists only
 * in the child's actual stderr output, never in its own source text, so
 * the assertion can only be satisfied by output this module genuinely
 * captured.
 */
const CRASHES_WITH_MESSAGE_SCRIPT = `
process.stderr.write(['FATAL', 'port 9999 already in use'].join(': ') + '\\n');
process.exitCode = 1;
`;

/**
 * Writes ~110 MB to stdout — comfortably past execa's own default
 * `maxBuffer` (100 MB) — respecting backpressure (`'drain'`), then a
 * marker, then exits with its own chosen code. For the "output larger than
 * the tail can hold does not kill the app" test (coordinator review,
 * Finding 7 follow-up).
 *
 * The marker is assembled at runtime (`.join('-')`), not written as one
 * literal, for the identical reason `CRASHES_WITH_MESSAGE_SCRIPT`'s own
 * comment gives: a literal would also appear in the echoed `-e` command
 * text every `startApp` error already includes, making a bare
 * `.includes(marker)` check pass even if nothing was genuinely captured.
 * Caught here the same way — by mutating and watching a wrong assertion
 * stay green — before this test was finalised; see the task report.
 */
const HUGE_OUTPUT_THEN_EXIT_SCRIPT = `
const { writeFileSync } = require('node:fs');
writeFileSync(process.argv[1], String(process.pid));
const chunk = 'x'.repeat(1024 * 1024);
const targetBytes = 110 * 1024 * 1024;
let written = 0;
function pump() {
  while (written < targetBytes) {
    const ok = process.stdout.write(chunk);
    written += chunk.length;
    if (!ok) { process.stdout.once('drain', pump); return; }
  }
  process.stdout.write(['MARKER', 'END', 'OF', 'OUTPUT', '7f3a9c'].join('-') + '\\n');
  process.exitCode = 1;
}
pump();
`;

/** Listens immediately, but delays every response by `argv[2]`ms — for the
 *  "a slow-but-healthy app is not wrongly declared unreachable" test
 *  (coordinator review, Finding 2). No grandchild: irrelevant to what that
 *  test checks. */
const SLOW_RESPONSE_SCRIPT = `
const { createServer } = require('node:http');
const port = Number(process.argv[1]);
const delayMs = Number(process.argv[2] || '0');
createServer((req, res) => {
  setTimeout(() => { res.writeHead(200); res.end('ok'); }, delayMs);
}).listen(port, '127.0.0.1');
`;

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

/** `JSON.parse` returns `any` — reading its result straight into a typed
 *  `const` (this file's own earlier shape, at two call sites) asserts a
 *  shape nothing checked, which is exactly what `noUncheckedIndexedAccess`'s
 *  `unknown` + guard discipline elsewhere in this file exists to prevent
 *  (coordinator review, Finding 8: "the no-`any` constraint binds tests
 *  too"). Used once the pidfile is already known to exist (the caller has
 *  already awaited `startApp`, which cannot resolve before the fixture's
 *  own write completes), so this throws — deliberately, there is nothing
 *  sensible to retry — rather than looping like `waitForPidfile` above. */
function readPidPair(path: string): PidPair {
  const data: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!isPidPair(data)) {
    throw new Error(`${path} did not contain a { parent, grandchild } pid pair: ${readFileSync(path, 'utf8')}`);
  }
  return data;
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
      const pids = readPidPair(pidfile);
      expect(typeof pids.parent).toBe('number');
      expect(isAlive(pids.parent)).toBe(true);
    } finally {
      await app.stop();
    }
  });

  it('a healthy app that answers slower than the poll interval is not wrongly declared unreachable', async () => {
    // Coordinator review, Finding 2: this module's own first version reused
    // the 100ms poll INTERVAL (the gap between attempts) as each attempt's
    // own abort deadline, so every request against this fixture — up and
    // answering the whole time — was aborted 100ms after it started and
    // never had a chance to complete. Reproduced there with exactly this
    // shape: "response delay 300ms -> FAILED after 4709ms: timed out after
    // 4000ms". 300ms is comfortably past the old 100ms bug and comfortably
    // under the real per-request budget, so this fails against the old
    // conflated-timeout implementation and passes against the fix.
    const port = await getFreePort();
    const app = await startApp({
      command: ['node', '-e', SLOW_RESPONSE_SCRIPT, String(port), '300'],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    await app.stop();
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

  it('a startup failure surfaces the app’s own output for diagnosis', async () => {
    // Coordinator review, Finding 7: `stdio: 'ignore'` (this module's own
    // first version) discarded exactly the information a CI user needs to
    // fix a failed start — the stack trace, "port already in use", the
    // missing env var — for a tool whose whole product IS the diagnosis.
    // Guards a wrong implementation that still discards the app's output:
    // the fixture writes a distinctive line to stderr before exiting, and
    // the thrown error must contain it, not just the exit code.
    await expect(
      startApp({
        command: ['node', '-e', CRASHES_WITH_MESSAGE_SCRIPT],
        cwd: workDir,
        healthUrl: 'http://127.0.0.1:1/',
        timeoutMs: 5_000,
      }),
    ).rejects.toThrow(/FATAL: port 9999 already in use/);
  });

  it('output larger than the tail can hold does not kill the app, and the tail is still correct', async () => {
    // Coordinator review, Finding 7 follow-up: the diagnosability fix
    // itself introduced a regression. `stdio: ['ignore','pipe','pipe']`
    // was added without also setting `buffer: false`, so execa's OWN
    // default (`buffer: true`, `maxBuffer: 100_000_000`) kept a SECOND,
    // genuinely unbounded copy of the stream behind `attachOutputTail`'s
    // back — and once that second copy passed 100 MB, execa KILLED the
    // subprocess to enforce the limit. Measured directly: a healthy,
    // merely chatty app was killed mid-scan (RSS 184 MB -> 491 MB in one
    // second, then the app gone) and the resulting error read as the APP
    // dying, not as this module having killed it.
    //
    // This fixture writes ~110 MB — comfortably past that 100 MB default —
    // then a marker, then exits with its own chosen code (1). Guards
    // exactly the wrong implementation named above: with `buffer: true`
    // restored, execa kills the child before it ever reaches the marker
    // write (confirmed directly: the child crashes with an uncaught EPIPE
    // when its own `stdout.write()` fails against a pipe execa has already
    // torn down), so the marker is absent from the captured tail and an
    // EPIPE stack trace is present in its place instead — the assertions
    // below check both directions, not just one.
    //
    // A bare `expect(execaCall).toHaveBeenCalledWith({ buffer: false })`
    // would test the call, not the behaviour (the same distinction the
    // no-shell test's own comment makes) — this asserts the OBSERVABLE
    // outcome: the app reaches ITS OWN intended exit rather than being cut
    // off by this module's own dependency, and the tail this module
    // captured independently is still exactly right despite the stream
    // being ~28,000x larger than what the tail retains.
    const pidfile = join(workDir, 'pids.json');
    const error = await startApp({
      command: ['node', '-e', HUGE_OUTPUT_THEN_EXIT_SCRIPT, pidfile],
      cwd: workDir,
      healthUrl: 'http://127.0.0.1:1/',
      timeoutMs: 30_000,
    }).then(
      () => {
        throw new Error('expected startApp to reject');
      },
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(Error);
    const message = (error as Error).message;
    // The fixture's own pidfile write happens before any of the 110 MB is
    // written, so its presence alone already proves the process was real
    // and started — the assertions below are about what happened to it
    // AFTERWARDS, while the flood of output was in flight.
    expect(existsSync(pidfile)).toBe(true);
    expect(message).toMatch(/exit code 1\)/);
    expect(message).not.toMatch(/EPIPE/);
    // The load-bearing assertion: the marker was the LAST thing the
    // fixture ever wrote, after all 110 MB — its presence in the captured
    // tail is only possible if the process ran to ITS OWN completion
    // rather than being killed by this module's own dependency partway
    // through, AND proves the 4 KB tail correctly kept the actual last
    // bytes of a vastly larger stream, not a stale or corrupted fragment.
    expect(message).toMatch(/MARKER-END-OF-OUTPUT-7f3a9c/);
  }, 20_000);

  it('stop() leaves nothing running, and is safe to call twice', async () => {
    const port = await getFreePort();
    const pidfile = join(workDir, 'pids.json');
    const app = await startApp({
      command: ['node', '-e', GOOD_APP_SCRIPT, String(port), pidfile],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    const pids = readPidPair(pidfile);

    await app.stop();
    await waitUntilDead(pids.parent);
    await waitUntilDead(pids.grandchild);

    // Idempotent: the CLI calls stop() in a `finally`, and it may already
    // have run once on a timeout path. Must not throw, hang, or attempt to
    // re-signal an already-dead pid in a way that surfaces as a rejection.
    await expect(app.stop()).resolves.toBeUndefined();
  });

  it('a concurrent second stop() does not resolve before the tree is actually gone', async () => {
    // Guards the wrong implementation this module shipped with initially: a
    // boolean `stopped` flag set BEFORE the `await killTree(...)` call, so a
    // second call that overlaps the first sees the flag already true and
    // returns immediately — while the tree is still alive (coordinator
    // review, Finding 6, reproduced: "after the 2nd stop() resolved, app
    // alive = true"). The sequential test above cannot catch this: by the
    // time it makes its SECOND call, the first has already been fully
    // awaited, so there is nothing left in flight to race.
    const port = await getFreePort();
    const pidfile = join(workDir, 'pids.json');
    const app = await startApp({
      command: ['node', '-e', GOOD_APP_SCRIPT, String(port), pidfile],
      cwd: workDir,
      healthUrl: `http://127.0.0.1:${port}/`,
      timeoutMs: 5_000,
    });
    const pids = readPidPair(pidfile);

    const first = app.stop();
    const second = app.stop();
    // Await ONLY the second call — the one a wrong implementation resolves
    // early. Awaiting `Promise.all([first, second])` instead would still
    // wait for the real teardown `first` kicked off and hide the bug; the
    // whole point is to check the instant `second` itself settles.
    await second;
    expect(isAlive(pids.parent)).toBe(false);
    expect(isAlive(pids.grandchild)).toBe(false);
    // Let the real teardown finish before this test (and its `afterEach`)
    // ends, rather than leaving a dangling handle.
    await first;
  });

  it('an aborted signal cancels an in-progress health-check wait and kills whatever was already spawned', async () => {
    // The CLI's SIGINT/SIGTERM handling (coordinator review, Finding 3)
    // needs to be able to give up on a still-starting app without waiting
    // for its own timeout — this is the mechanism that makes that possible,
    // tested directly rather than only through the CLI. Guards a wrong
    // implementation that accepts `signal` but never checks it: that
    // version would ignore the abort below and only stop waiting once the
    // full (deliberately generous) `timeoutMs` elapsed.
    const pidfile = join(workDir, 'pids.json');
    const controller = new AbortController();
    const pending = startApp({
      command: ['node', '-e', NEVER_ANSWERS_SCRIPT, pidfile],
      cwd: workDir,
      healthUrl: 'http://127.0.0.1:1/',
      timeoutMs: 30_000,
      signal: controller.signal,
    });
    const settled = pending.then(
      () => {
        throw new Error('expected startApp to reject');
      },
      (e: unknown) => e,
    );

    const pids = await waitForPidfile(pidfile);
    const abortedAt = Date.now();
    controller.abort();

    const error = await settled;
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/cancelled/i);
    // The ABORT, not the 30s timeoutMs, must be what ended this — pinned as
    // a real elapsed-time number, not just inferred from the message.
    expect(Date.now() - abortedAt).toBeLessThan(2_000);

    // Same load-bearing shape as the timeout test: an abort must kill what
    // was already spawned, including the grandchild, not merely reject.
    await waitUntilDead(pids.parent);
    await waitUntilDead(pids.grandchild);
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
