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
 * module never touches the scan pipeline. See design doc §7 for why
 * `--start-command` lives here and not as an MCP tool parameter: a human
 * types a CLI flag; an MCP tool's parameters can be filled by a model
 * reading the very repository under scan.
 *
 * No shell, ever (`shell: false`, argv as an array end to end, never
 * joined into a string). A metacharacter in an argument must reach the
 * child as inert data, not as a command separator — the whole safety
 * argument for letting a CLI flag start a process collapses the moment a
 * shell is in the path.
 */

import { execa, type ResultPromise } from 'execa';

export interface StartAppOptions {
  /** argv array — never a shell string. `command[0]` is the executable. */
  command: readonly string[];
  cwd: string;
  /** Polled with a plain request until it answers (any HTTP response, any
   *  status — see `answers` below) or `timeoutMs` expires. */
  healthUrl: string;
  timeoutMs: number;
}

export interface RunningApp {
  /** Kills the process tree. Idempotent — safe to call more than once,
   *  including after `startApp` itself already called it on a failed
   *  health check, and the CLI calls it again in a `finally`. */
  stop: () => Promise<void>;
}

/** Gap between failed health-check attempts. Short enough that a
 *  fast-booting app is detected almost immediately; long enough that
 *  polling a refused connection — which fails near-instantly, not on its
 *  own timeout — does not spin the event loop. */
const POLL_INTERVAL_MS = 100;

/** How long a POSIX process group gets to exit cleanly after SIGTERM before
 *  this module escalates to SIGKILL. Windows has no equivalent grace phase
 *  — `taskkill /F` is unconditionally forceful — so this constant is read
 *  only on POSIX. Matches `runners/processRunner.ts`'s own KILL_GRACE_MS,
 *  reused here as a value, not imported, since that module's constant is
 *  private. */
const KILL_GRACE_MS = 5_000;

export async function startApp(opts: StartAppOptions): Promise<RunningApp> {
  const [file, ...args] = opts.command;
  if (file === undefined) {
    throw new Error('startApp: command must not be empty');
  }
  const commandLabel = opts.command.join(' ');

  const child = execa(file, args, {
    cwd: opts.cwd,
    shell: false,
    // The started app's own console output is not this module's concern —
    // `RunningApp` exposes no log surface (deliberately: the brief's
    // interface is `{ stop }` only), and forwarding it to this process's
    // own stdout/stderr would interleave with the scan report a `--format
    // json`/`--sarif` consumer expects to parse cleanly. `ignore` also
    // means the child can never block on a full, undrained pipe buffer.
    stdio: 'ignore',
    // Never throw for a nonzero exit or a spawn failure (e.g. the binary
    // does not exist) — `waitForHealthy` below reads the settled result
    // itself, turning either case into a specific "exited before healthy"
    // error instead of an uncaught rejection.
    reject: false,
    // execa's default: kill the DIRECT child if this process exits first.
    // Left explicit (rather than merely relying on the default) because it
    // stops applying the moment `detached` is true (execa's own
    // `cleanupOnExit` short-circuits on `detached` — confirmed by reading
    // its source, see the task report) — stated here so that fact is not
    // silently lost if the POSIX branch below ever changes.
    cleanup: true,
    // POSIX only: makes `child` the leader of a new process group so
    // `killTree` can signal the WHOLE group (direct child + any grandchild
    // that did not itself detach) with one call to `process.kill(-pid, …)`.
    // Windows has no equivalent concept; `killTree`'s Windows branch walks
    // the OS parent/child table via `taskkill /T` instead, which needs no
    // spawn-time flag — setting `detached` there would only change how the
    // child's own console is handled, which is not what this module wants.
    detached: process.platform !== 'win32',
  });

  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    await killTree(child);
  };

  try {
    await waitForHealthy(opts.healthUrl, opts.timeoutMs, child, commandLabel);
  } catch (e) {
    await stop();
    throw e;
  }

  return { stop };
}

/**
 * Resolves once `healthUrl` answers (any HTTP response), or throws once
 * `timeoutMs` elapses, or throws immediately if the process exits first —
 * turning a crash-on-boot into a specific, immediate failure instead of a
 * hang that only reveals itself once the whole timeout budget is spent.
 */
async function waitForHealthy(
  healthUrl: string,
  timeoutMs: number,
  child: ResultPromise,
  commandLabel: string,
): Promise<void> {
  const exitState: { info: { exitCode: number | null; signal: string | null } | null } = {
    info: null,
  };
  // `reject: false` (set at spawn) means this promise always RESOLVES, even
  // for a crash or a nonzero exit, never rejects — so there is nothing for
  // a `.catch` to do here in practice. It is attached anyway: a future
  // change to that option turning this into a genuine rejection would
  // otherwise surface as an unhandled rejection, which this project's own
  // "pristine output" test discipline exists to catch.
  child
    .then((result) => {
      exitState.info = { exitCode: result.exitCode ?? null, signal: result.signal ?? null };
    })
    .catch(() => {
      /* unreachable while reject:false holds; see comment above */
    });

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (exitState.info !== null) {
      const { exitCode, signal } = exitState.info;
      throw new Error(
        `${commandLabel} exited before ${healthUrl} ever responded ` +
          `(exit code ${exitCode === null ? 'null' : String(exitCode)}` +
          `${signal !== null ? `, signal ${signal}` : ''})`,
      );
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(
        `timed out after ${timeoutMs}ms waiting for ${healthUrl} to respond (started: ${commandLabel})`,
      );
    }

    if (await answers(healthUrl, Math.min(POLL_INTERVAL_MS, remaining))) {
      return;
    }

    await sleep(Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
  }
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
async function answers(url: string, timeoutMs: number): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetch(url, { signal: controller.signal, redirect: 'manual' });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Kills the whole process tree rooted at `child`, then waits for the direct
 * child to actually be reaped before returning — so a caller awaiting this
 * knows "stopped" means "gone", not merely "signal sent".
 */
async function killTree(child: ResultPromise): Promise<void> {
  const pid = child.pid;
  if (pid !== undefined) {
    if (process.platform === 'win32') {
      // `/T` walks the OS parent/child table and kills the whole tree;
      // `/F` is unconditionally forceful — matches processRunner.ts's own
      // Windows handling, deliberately mirrored rather than reinvented.
      try {
        await execa('taskkill', ['/PID', String(pid), '/T', '/F'], {
          reject: false,
          timeout: KILL_GRACE_MS,
        });
      } catch {
        /* best-effort: taskkill missing, or the tree was already gone */
      }
    } else {
      // `detached: true` at spawn made `pid` the leader of its own process
      // group, so signalling the NEGATIVE pid reaches every member of that
      // group at once — the direct child AND any grandchild that did not
      // itself detach (e.g. the `node` process `npm start` launches).
      // Signalling the bare (positive) pid would reach only the direct
      // child and orphan exactly the process this module exists to catch.
      trySignal(-pid, 'SIGTERM');
      await Promise.race([child.catch(() => undefined), sleep(KILL_GRACE_MS)]);
      trySignal(-pid, 'SIGKILL');
    }
  }
  // Wait for the direct child to actually be reaped, on every platform —
  // this is the fact `stop()`'s callers rely on.
  await child.catch(() => undefined);
}

function trySignal(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(pid, signal);
  } catch {
    /* ESRCH: already dead. Nothing left to signal. */
  }
}

/**
 * NOT `unref()`'d — see `answers`'s comment. Every caller of `sleep` is
 * either the poll loop (waiting IS the operation `startApp` promised the
 * caller) or `killTree`'s SIGTERM grace period (waiting IS the operation
 * `stop()` promised the caller); in both cases an unref'd timer would let a
 * bare CLI process exit mid-wait instead of completing it.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
