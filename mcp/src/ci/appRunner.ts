/**
 * Application lifecycle for the DAST pass of the headless CI entry point.
 *
 * Starts the target application the caller wants `scan_dast` to probe, waits
 * for it to answer its own health URL, and hands back a `stop()` that kills
 * the WHOLE process tree — not just the process this module spawned
 * directly. That distinction is the reason this module exists: `npm start`
 * (the canonical `--start-command` value) spawns a grandchild that does the
 * actual listening, and signalling only the direct child leaves that
 * grandchild running and the port held for the rest of the CI job.
 *
 * Deliberately separate from `runScans.ts`: the caller (`cli/dev-guardian.mjs`)
 * starts the app, then runs the scan pipeline, then stops the app in a
 * `finally` — `runScans` itself never touches a child process, and this
 * module never touches the scan pipeline. See the design of record for why
 * `--start-command` lives here and not as an MCP tool parameter: a human
 * types a CLI flag; an MCP tool's parameters can be filled by a model
 * reading the very repository under scan.
 *
 * No shell, ever (`shell: false`, argv as an array end to end, never
 * joined into a string). A metacharacter in an argument must reach the
 * child as inert data, not as a command separator — the whole safety
 * argument for letting a CLI flag start a process collapses the moment a
 * shell is in the path.
 *
 * ---- The tree kill, and its one honest limit -------------------------------
 *
 * The app is started and stopped the way every child is
 * (`runners/childProcess.ts`, review 8 finding 4): on POSIX the leader of its
 * own process group, whose NEGATIVE pid reaches every descendant that stayed
 * in it — what an ordinary `npm start` grandchild does (confirmed against a
 * real Linux container: a plain, non-detached grandchild shares the parent's
 * pgid and dies with it); on Windows `taskkill /T /F` plus the MSYS
 * descendants the table loses. A grandchild that ITSELF calls `setsid()` (or
 * spawns with its own `detached: true`) leaves that group and forms its own —
 * `-pid` cannot reach it, by construction, on any platform; this is inherent
 * to signal-based POSIX process-group kills, not a gap specific to this
 * implementation. `mcp/test/unit/ci/appRunner.ts` mirrors this: its POSIX
 * fixtures spawn a plain (non-detached) grandchild, which is both the
 * realistic case and the one this module can actually reach.
 */

import { findOnPath, isBareName } from '../platform/binaryPath.js';
import { readText, startChild, stopTree, type Child, type ChildExit } from '../runners/childProcess.js';

export interface StartAppOptions {
  /** argv array — never a shell string. `command[0]` is the executable. */
  command: readonly string[];
  cwd: string;
  /** Polled with a plain request until it answers (any HTTP response, any
   *  status — see `answers` below) or `timeoutMs` expires. */
  healthUrl: string;
  timeoutMs: number;
  /** Aborting cancels an in-progress health-check wait — whatever was
   *  already spawned is killed before the rejection — and is otherwise
   *  inert: `startApp` never reads it again once resolved. The caller stays
   *  responsible for a RUNNING application after that point via the
   *  returned `stop()` (see `cli/dev-guardian.mjs`'s SIGINT/SIGTERM
   *  handling, which does both — abort a still-starting app, stop an
   *  already-started one). */
  signal?: AbortSignal;
}

export interface RunningApp {
  /** Kills the process tree. Idempotent — safe to call more than once,
   *  including CONCURRENTLY, including after `startApp` itself already
   *  called it on a failed health check, and the CLI calls it again in a
   *  `finally`. Every caller's promise settles only once the tree is
   *  actually gone, regardless of which call is the one that started the
   *  teardown. */
  stop: () => Promise<void>;
}

/** Gap between failed health-check attempts. Short enough that a
 *  fast-booting app is detected almost immediately; long enough that
 *  polling a refused connection — which fails near-instantly, not on its
 *  own timeout — does not spin the event loop. Distinct from
 *  `REQUEST_TIMEOUT_MS` below — conflating the two was a real defect, see
 *  its comment. */
const POLL_INTERVAL_MS = 100;

/**
 * Ceiling for ONE health-check request — independent of `POLL_INTERVAL_MS`,
 * which is the GAP between attempts, not how long any single attempt gets to
 * answer. This module's own first version reused `POLL_INTERVAL_MS` for
 * both (`Math.min(POLL_INTERVAL_MS, remaining)` as the per-request
 * deadline), so every request was aborted 100ms after it started — a
 * genuinely healthy app whose first byte takes longer than that (a
 * server-rendered route, a health check that touches a database, a
 * framework compiling on first hit) was wrongly declared unreachable, timed
 * out, and killed after burning the FULL `timeoutMs` budget on 100ms-capped
 * attempts that never had a chance to succeed (coordinator review,
 * reproduced: a fixture with a 300ms response delay failed with "timed out
 * after 4000ms" despite answering on every single attempt). A few seconds
 * is enough for a slow-but-real response and still short enough that a
 * request against a genuinely dead port fails fast; always capped by
 * whatever is left of the overall `timeoutMs` budget.
 */
const REQUEST_TIMEOUT_MS = 5_000;

/** How long the tree gets to exit cleanly after the first signal before it
 *  is killed outright — the runner's own grace (`processRunner.ts`). */
const KILL_GRACE_MS = 5_000;
/** After the kill, how long to wait for pipes something outside the tree
 *  holds before they are no longer read (`childProcess.ts#stopTree`). */
const PIPE_ABANDON_MS = 1_000;

/**
 * Bounded tail of the app's own stdout+stderr, surfaced only inside the
 * thrown error when it never becomes healthy. For a CI tool the diagnosis
 * IS the product: without this, a failed start reports only "exited (exit
 * code 1)" or "timed out after 60000ms" and discards the stack trace,
 * the "port already in use", the missing env var that would have made the
 * fix five minutes instead of an hour. Small on purpose — a diagnosis aid,
 * not a second copy of the app's own logs.
 */
const OUTPUT_TAIL_BYTES = 4 * 1024;

export async function startApp(opts: StartAppOptions): Promise<RunningApp> {
  if (opts.signal?.aborted === true) {
    throw new Error('startApp: aborted before the application was started');
  }

  const [file, ...args] = opts.command;
  if (file === undefined) {
    throw new Error('startApp: command must not be empty');
  }
  const commandLabel = opts.command.join(' ');
  const env = { ...process.env };
  // A bare name by the absolute path it resolves to on PATH, never one in the
  // project directory the app starts in (platform/binaryPath.ts).
  const command = isBareName(file) ? findOnPath(file, env) : file;
  if (command === null) {
    throw new Error(`startApp: ${file} was not found on PATH (started: ${commandLabel})`);
  }

  // No shell (`startChild` never uses one), this process's environment, and
  // both streams piped and drained for the process's whole lifetime by
  // `attachOutputTail` below — so the child can never block on a full OS
  // pipe, however chatty or long-lived. Only that bounded tail is kept, and
  // only ever surfaced inside a thrown error: the app's output never reaches
  // THIS process's stdout, so a `--format json`/`--sarif` consumer parsing it
  // is unaffected. Nothing else keeps a copy — execa's own `buffer: true`
  // once kept a second, unbounded one, and killed a merely chatty app (RSS
  // 184 MB -> 491 MB in one second) when it passed 100 MB. A spawn failure (a
  // binary that does not exist) is not a throw: `waitForHealthy` reads it
  // from the settled exit as "exited before healthy".
  const child = startChild(command, args, { cwd: opts.cwd, env });

  const getOutputTail = attachOutputTail(child);
  const stop = makeStop(child);

  try {
    await waitForHealthy(
      opts.healthUrl,
      opts.timeoutMs,
      child,
      commandLabel,
      getOutputTail,
      opts.signal,
    );
  } catch (e) {
    await stop();
    throw e;
  }

  return { stop };
}

/**
 * One shared teardown per `startApp` call, no matter how many times or how
 * concurrently `stop()` is invoked. The obvious shape — `if (stopped)
 * return; stopped = true; await killTree(...)` (this module's own first
 * version) — sets a boolean BEFORE the `await`, so a second call that
 * overlaps the first sees the flag already true and resolves immediately
 * while the tree is still alive (coordinator review, reproduced: "after the
 * 2nd stop() resolved, app alive = true") — a real break of both this
 * function's own doc comment and `RunningApp.stop`'s. Sharing the IN-FLIGHT
 * PROMISE instead means every caller, sequential or concurrent, awaits the
 * SAME teardown and only settles once it has actually finished.
 */
function makeStop(child: Child): () => Promise<void> {
  let stopPromise: Promise<void> | null = null;
  return () => {
    stopPromise ??= killTree(child);
    return stopPromise;
  };
}

/**
 * Resolves once `healthUrl` answers (any HTTP response), or throws once
 * `timeoutMs` elapses, or throws immediately if the process exits first —
 * turning a crash-on-boot into a specific, immediate failure instead of a
 * hang that only reveals itself once the whole timeout budget is spent — or
 * once `signal` aborts, for a caller (the CLI, on SIGINT/SIGTERM) that wants
 * to give up on a still-starting app without waiting for either.
 */
async function waitForHealthy(
  healthUrl: string,
  timeoutMs: number,
  child: Child,
  commandLabel: string,
  getOutputTail: () => string,
  signal: AbortSignal | undefined,
): Promise<void> {
  const exitState: { info: ChildExit | null } = { info: null };
  // `done` always RESOLVES — for a crash, a nonzero exit, a spawn failure.
  void child.done.then((exit) => {
    exitState.info = exit;
  });

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (signal?.aborted === true) {
      throw new Error(
        `startApp: cancelled while waiting for ${healthUrl} to respond (started: ${commandLabel})`,
      );
    }

    if (exitState.info !== null) {
      const { exitCode, signal: exitSignal, spawnError } = exitState.info;
      throw new Error(
        `${commandLabel} exited before ${healthUrl} ever responded ` +
          `(exit code ${exitCode === null ? 'null' : String(exitCode)}` +
          `${exitSignal !== null ? `, signal ${exitSignal}` : ''}` +
          `${spawnError !== undefined ? `, ${spawnError.message}` : ''})` +
          formatTail(getOutputTail()),
      );
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(
        `timed out after ${timeoutMs}ms waiting for ${healthUrl} to respond (started: ${commandLabel})` +
          formatTail(getOutputTail()),
      );
    }

    if (await answers(healthUrl, Math.min(REQUEST_TIMEOUT_MS, remaining), signal)) {
      return;
    }

    await sleep(Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
  }
}

function formatTail(tail: string): string {
  return tail === '' ? '' : `\n--- output tail (last ${OUTPUT_TAIL_BYTES / 1024}KB) ---\n${tail}`;
}

/**
 * A single health-check attempt. Any HTTP response — including a 404 or a
 * 500 — counts as "answered": this is a liveness probe (is the port open
 * and serving HTTP), not a correctness check. Treating a non-2xx response
 * as "not ready" would make a perfectly running API-only backend with no
 * root route time out for a reason that has nothing to do with whether it
 * started — and `scan_dast` itself does not require 2xx either, see
 * `dast/probe.ts`.
 *
 * `timeoutMs` here is `REQUEST_TIMEOUT_MS` (capped by whatever remains of
 * the overall budget) — a genuinely separate quantity from the GAP between
 * attempts; see that constant's own comment for the defect this fixes.
 *
 * This timer is deliberately NOT `unref()`'d, unlike `dast/deadline.ts`'s
 * — that one guards a background CEILING that should never keep the process
 * alive if the real work already finished; this one IS the real work the
 * caller is awaiting. Confirmed the hard way: `unref()`-ing it here let a
 * bare CLI invocation (nothing else scheduled — no other timer, socket, or
 * handle keeping the event loop open) exit the moment the loop next saw
 * "nothing ref'd", abandoning `waitForHealthy` mid-poll with no error and no
 * warning — Node's documented `unref()` behaviour, but the single worst
 * possible outcome for this module: not a hang, but a SILENT, INSTANT exit
 * 0, indistinguishable from a genuine pass. Invisible in the unit suite,
 * where vitest's own machinery keeps the process alive regardless; only a
 * real subprocess CLI invocation with nothing else in flight exposed it —
 * see the task report.
 */
async function answers(
  url: string,
  timeoutMs: number,
  outerSignal: AbortSignal | undefined,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onOuterAbort = (): void => controller.abort();
  if (outerSignal?.aborted === true) {
    // Same trap `dast/probe.ts` documents: adding an 'abort' listener to a
    // signal that has already aborted never fires it (the event already
    // happened), so react to the stale signal directly instead of silently
    // running this one attempt to completion.
    controller.abort();
  } else {
    outerSignal?.addEventListener('abort', onOuterAbort);
  }
  try {
    await fetch(url, { signal: controller.signal, redirect: 'manual' });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener('abort', onOuterAbort);
  }
}

/**
 * Kills the whole process tree rooted at `child` (`runners/childProcess.ts`),
 * then waits for the direct child to actually be reaped before returning — so
 * a caller awaiting this knows "stopped" means "gone", not merely "signal
 * sent".
 */
async function killTree(child: Child): Promise<void> {
  await stopTree(child, { graceMs: KILL_GRACE_MS, abandonMs: PIPE_ABANDON_MS });
  await child.done;
}

/**
 * Attaches once, for the process's whole lifetime, and keeps only the last
 * `OUTPUT_TAIL_BYTES` of combined stdout+stderr — draining continuously (a
 * `'data'` listener puts a stream in flowing mode) so the child can never
 * block on a full pipe no matter how long it stays alive after `startApp`
 * resolves. Returns a getter rather than the buffer itself so a caller
 * always reads the CURRENT tail, not a snapshot taken at attach time.
 */
function attachOutputTail(child: Child): () => string {
  let tail = '';
  const onText = (text: string): void => {
    tail += text;
    if (tail.length > OUTPUT_TAIL_BYTES) {
      tail = tail.slice(tail.length - OUTPUT_TAIL_BYTES);
    }
  };
  readText(child.process?.stdout, onText);
  readText(child.process?.stderr, onText);
  return () => tail;
}

/**
 * NOT `unref()`'d — see `answers`'s comment. The poll loop is its only
 * caller, and waiting IS the operation `startApp` promised the caller: an
 * unref'd timer would let a bare CLI process exit mid-wait instead of
 * completing it. (`killTree`'s waits are the child's own: its `done` keeps
 * the loop alive until it settles.)
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
