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
 *
 * ---- The POSIX group kill's one honest limit -------------------------------
 *
 * `killTree`'s POSIX branch signals the NEGATIVE pid of the process group
 * `detached: true` put the direct child in — this reaches every descendant
 * that stayed in that group, which is what an ordinary `npm start` grandchild
 * does (confirmed against a real Linux container: a plain, non-detached
 * grandchild shares the parent's pgid and dies with it). A grandchild that
 * ITSELF calls `setsid()` (or spawns with its own `detached: true`) leaves
 * that group and forms its own — `-pid` cannot reach it, by construction, on
 * any platform; this is inherent to signal-based POSIX process-group kills,
 * not a gap specific to this implementation. `mcp/test/unit/ci/appRunner.ts`
 * mirrors this: its POSIX fixtures spawn a plain (non-detached) grandchild,
 * which is both the realistic case and the one this module can actually
 * reach.
 */
import { execa } from 'execa';
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
/** How long a POSIX process group gets to exit cleanly after SIGTERM before
 *  this module escalates to SIGKILL. Windows has no equivalent grace phase
 *  — `taskkill /F` is unconditionally forceful — so this constant is read
 *  only on POSIX. Matches `runners/processRunner.ts`'s own KILL_GRACE_MS,
 *  reused here as a value, not imported, since that module's constant is
 *  private. */
const KILL_GRACE_MS = 5_000;
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
export async function startApp(opts) {
    if (opts.signal?.aborted === true) {
        throw new Error('startApp: aborted before the application was started');
    }
    const [file, ...args] = opts.command;
    if (file === undefined) {
        throw new Error('startApp: command must not be empty');
    }
    const commandLabel = opts.command.join(' ');
    const child = execa(file, args, {
        cwd: opts.cwd,
        shell: false,
        // Piped, not ignored — `attachOutputTail` below drains both streams
        // continuously for the process's whole lifetime (the listener is
        // attached once, immediately, and never removed) and keeps only a
        // small rolling tail, so this can never grow without bound or block the
        // child on a full pipe. The app's full output is still never forwarded
        // to THIS process's own stdout/stderr — only the bounded tail is ever
        // surfaced, and only inside a thrown error — so a `--format json`/
        // `--sarif` consumer parsing this CLI's own stdout is unaffected.
        stdio: ['ignore', 'pipe', 'pipe'],
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
        // silently lost if the POSIX branch below ever changes. This is NOT a
        // substitute for the CLI's own SIGINT/SIGTERM handling: `cleanup` only
        // fires on THIS process's own natural exit paths, never on a delivered
        // signal, and is inert under `detached` regardless (POSIX) — the CLI
        // owns interrupt-driven teardown itself.
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
    const getOutputTail = attachOutputTail(child);
    const stop = makeStop(child);
    try {
        await waitForHealthy(opts.healthUrl, opts.timeoutMs, child, commandLabel, getOutputTail, opts.signal);
    }
    catch (e) {
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
function makeStop(child) {
    let stopPromise = null;
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
async function waitForHealthy(healthUrl, timeoutMs, child, commandLabel, getOutputTail, signal) {
    const exitState = {
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
        if (signal?.aborted === true) {
            throw new Error(`startApp: cancelled while waiting for ${healthUrl} to respond (started: ${commandLabel})`);
        }
        if (exitState.info !== null) {
            const { exitCode, signal: exitSignal } = exitState.info;
            throw new Error(`${commandLabel} exited before ${healthUrl} ever responded ` +
                `(exit code ${exitCode === null ? 'null' : String(exitCode)}` +
                `${exitSignal !== null ? `, signal ${exitSignal}` : ''})` +
                formatTail(getOutputTail()));
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
            throw new Error(`timed out after ${timeoutMs}ms waiting for ${healthUrl} to respond (started: ${commandLabel})` +
                formatTail(getOutputTail()));
        }
        if (await answers(healthUrl, Math.min(REQUEST_TIMEOUT_MS, remaining), signal)) {
            return;
        }
        await sleep(Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
    }
}
function formatTail(tail) {
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
async function answers(url, timeoutMs, outerSignal) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onOuterAbort = () => controller.abort();
    if (outerSignal?.aborted === true) {
        // Same trap `dast/probe.ts` documents: adding an 'abort' listener to a
        // signal that has already aborted never fires it (the event already
        // happened), so react to the stale signal directly instead of silently
        // running this one attempt to completion.
        controller.abort();
    }
    else {
        outerSignal?.addEventListener('abort', onOuterAbort);
    }
    try {
        await fetch(url, { signal: controller.signal, redirect: 'manual' });
        return true;
    }
    catch {
        return false;
    }
    finally {
        clearTimeout(timer);
        outerSignal?.removeEventListener('abort', onOuterAbort);
    }
}
/**
 * Kills the whole process tree rooted at `child`, then waits for the direct
 * child to actually be reaped before returning — so a caller awaiting this
 * knows "stopped" means "gone", not merely "signal sent".
 */
async function killTree(child) {
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
            }
            catch {
                /* best-effort: taskkill missing, or the tree was already gone */
            }
        }
        else {
            // `detached: true` at spawn made `pid` the leader of its own process
            // group, so signalling the NEGATIVE pid reaches every member of that
            // group at once — the direct child AND any grandchild that did not
            // itself detach (e.g. the `node` process `npm start` launches).
            // Signalling the bare (positive) pid would reach only the direct
            // child and orphan exactly the process this module exists to catch.
            // A grandchild that itself detaches (its own `setsid`/`detached`)
            // leaves this group and forms its own — `-pid` cannot reach it, by
            // construction; see the module doc comment's "one honest limit".
            trySignal(-pid, 'SIGTERM');
            await Promise.race([child.catch(() => undefined), sleep(KILL_GRACE_MS)]);
            trySignal(-pid, 'SIGKILL');
        }
    }
    // Wait for the direct child to actually be reaped, on every platform —
    // this is the fact `stop()`'s callers rely on.
    await child.catch(() => undefined);
}
function trySignal(pid, signal) {
    try {
        process.kill(pid, signal);
    }
    catch {
        /* ESRCH: already dead. Nothing left to signal. */
    }
}
/**
 * Attaches once, for the process's whole lifetime, and keeps only the last
 * `OUTPUT_TAIL_BYTES` of combined stdout+stderr — draining continuously (a
 * `'data'` listener puts a stream in flowing mode) so the child can never
 * block on a full pipe no matter how long it stays alive after `startApp`
 * resolves. Returns a getter rather than the buffer itself so a caller
 * always reads the CURRENT tail, not a snapshot taken at attach time.
 */
function attachOutputTail(child) {
    let tail = '';
    const onData = (chunk) => {
        tail += chunk.toString('utf8');
        if (tail.length > OUTPUT_TAIL_BYTES) {
            tail = tail.slice(tail.length - OUTPUT_TAIL_BYTES);
        }
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
    return () => tail;
}
/**
 * NOT `unref()`'d — see `answers`'s comment. Every caller of `sleep` is
 * either the poll loop (waiting IS the operation `startApp` promised the
 * caller) or `killTree`'s SIGTERM grace period (waiting IS the operation
 * `stop()` promised the caller); in both cases an unref'd timer would let a
 * bare CLI process exit mid-wait instead of completing it.
 */
function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}
//# sourceMappingURL=appRunner.js.map