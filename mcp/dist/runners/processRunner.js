/**
 * Generic child-process runner with the same safety net as `runShellScript`:
 *   - 5 MB rolling cap on stdout (kills the child if exceeded)
 *   - 10-minute default timeout (override via `GUARDIAN_SCAN_TIMEOUT_MS`)
 *   - AbortSignal → SIGTERM, then SIGKILL after 5 s
 *   - stderr line streaming via `onLog`
 *
 * `runShellScript` builds on this — direct scanner invocations (Semgrep,
 * Trivy CLI, gitleaks) call `runProcess` straight.
 *
 * ---- Every kill is a TREE kill ----------------------------------------------
 *
 * Timeout, cancellation and the stdout cap all stop the child's whole process
 * tree, not just the direct child. Scanners fork (bash → semgrep →
 * semgrep-core), and a grandchild that survives keeps the stdout pipe open, so
 * `await child` waits for IT: measured before this was fixed, execa's own
 * `timeout: 2000` returned after 25 151 ms — the full lifetime of a
 * `sleep 25` grandchild. So the timeout is implemented here rather than
 * handed to execa, and it goes through the same `killTree` as the rest:
 *
 *   - Windows: `taskkill /PID <pid> /T /F` walks the OS parent/child table,
 *     and — because that table loses every process Git Bash `exec`s — the
 *     MSYS descendants are found by a per-child environment token and
 *     killed too. See `windowsTreeKill.ts`.
 *   - POSIX: the child is spawned `detached`, which makes it the leader of
 *     its own process group, and the NEGATIVE pid signals the whole group.
 *     Same mechanism as `ci/appRunner.ts`, with the same honest limit: a
 *     grandchild that calls `setsid()` itself leaves the group and cannot be
 *     reached this way.
 *
 * `detached` opts the child out of execa's kill-on-parent-exit cleanup (execa
 * skips it for detached children), so the runner supplies that cleanup
 * itself through the same `signal-exit` hook execa uses: when this process
 * exits — `process.exit()` in the MCP server's shutdown, or an unhandled
 * SIGINT/SIGTERM in the CLI — each live group gets a SIGTERM.
 *
 * If a pipe is still held open after the SIGKILL grace (a `setsid`
 * grandchild), the runner stops reading it rather than wait on it for ever.
 */
import { randomUUID } from 'node:crypto';
import { basename } from 'node:path';
import { execa } from 'execa';
import { onExit } from 'signal-exit';
import { killWindowsTree, PROC_TREE_ENV } from './windowsTreeKill.js';
const FIVE_MB = 5 * 1024 * 1024;
const KILL_GRACE_MS = 5_000;
/** After SIGKILL, how long to keep waiting for the pipes before abandoning
 *  them. Only reached when something outside the tree still holds them. */
const PIPE_ABANDON_MS = 1_000;
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
/** `setTimeout`'s ceiling; a larger delay fires after 1 ms instead. */
const MAX_TIMER_MS = 2_147_483_647;
export async function runProcess(options) {
    const timeoutMs = options.timeoutMs ??
        (Number(process.env['GUARDIAN_SCAN_TIMEOUT_MS']) || DEFAULT_TIMEOUT_MS);
    const cap = options.stdoutCapBytes ?? FIVE_MB;
    const posixGroup = process.platform !== 'win32';
    // Windows only: what lets `killWindowsTree` find the MSYS descendants.
    const treeToken = posixGroup ? null : randomUUID();
    let stdoutBuf = '';
    let stderrBuf = '';
    let truncated = false;
    let outcome = 'completed';
    const child = execa(options.command, options.args ?? [], {
        cwd: options.cwd,
        env: envFor(options.command, options.env, treeToken),
        // `?? true` restates execa's own default explicitly rather than relying
        // on `undefined` meaning it, so the merge behaviour is visible here
        // instead of only in execa's docs.
        extendEnv: options.extendEnv ?? true,
        shell: false,
        encoding: 'utf8',
        // Own process group on POSIX, so `killTree` can signal the whole group.
        // Never on Windows: there `detached` means a new console, not a group.
        detached: posixGroup,
        stdio: ['ignore', 'pipe', 'pipe'],
        reject: false,
    });
    let settled = false;
    let stopping = false;
    // Timeout, abort and the stdout cap can all fire; the tree is killed once.
    const stopTree = () => {
        if (stopping)
            return;
        stopping = true;
        killTree(child, options.command, treeToken, () => settled);
    };
    // execa skips its own exit cleanup for a detached child; supply it.
    const removeExitHook = posixGroup ? onExit(() => signalGroup(child.pid, 'SIGTERM')) : null;
    attachStdoutCap(child, cap, (chunk) => {
        stdoutBuf += chunk;
    }, () => {
        if (outcome === 'completed')
            outcome = 'output_too_large';
        truncated = true;
        stopTree();
    });
    // Cap stderr at 1/10 of the stdout cap (default 512 KB). Long-running
    // tools with `--verbose` flags can spew MBs of stderr; without a cap the
    // server would grow unbounded.
    const stderrCap = Math.max(64 * 1024, Math.floor(cap / 10));
    let stderrBytes = 0;
    attachStderr(child, (chunk) => {
        stderrBytes += chunk.length;
        if (stderrBytes <= stderrCap) {
            stderrBuf += chunk;
        }
        else if (!stderrBuf.endsWith('…(truncated)\n')) {
            stderrBuf += '…(truncated)\n';
        }
        if (options.onLog) {
            for (const line of chunk.split(/\r?\n/)) {
                if (line.length > 0)
                    options.onLog(line);
            }
        }
    });
    let timer = null;
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        timer = setTimeout(() => {
            if (outcome === 'completed')
                outcome = 'timed_out';
            stopTree();
        }, Math.min(timeoutMs, MAX_TIMER_MS));
    }
    let abortListener = null;
    if (options.signal) {
        if (options.signal.aborted) {
            outcome = 'cancelled';
            stopTree();
        }
        else {
            abortListener = () => {
                if (outcome === 'completed')
                    outcome = 'cancelled';
                stopTree();
            };
            options.signal.addEventListener('abort', abortListener, { once: true });
        }
    }
    const result = await child;
    settled = true;
    if (timer)
        clearTimeout(timer);
    removeExitHook?.();
    if (abortListener && options.signal) {
        options.signal.removeEventListener('abort', abortListener);
    }
    if (outcome === 'completed' && result.exitCode !== 0)
        outcome = 'failed';
    return {
        outcome,
        exitCode: result.exitCode ?? null,
        stdout: stdoutBuf,
        stderr: stderrBuf,
        truncated,
    };
}
/**
 * Environment for the child: the caller's `env`, plus
 *
 *   - on Windows, the tree token `killWindowsTree` finds descendants by;
 *   - for `docker` only, the two variables that stop Git Bash's MSYS layer
 *     rewriting POSIX-looking arguments. An MSYS parent turns `-w /src` into
 *     `-w C:/Program Files/Git/src` (measured). A Node parent does not
 *     rewrite anything itself, so from here this is defence for any MSYS
 *     process that ends up between us and docker — never for other commands,
 *     where scripts running under Git Bash rely on the conversion to hand
 *     Windows paths to native tools.
 */
function envFor(command, env, treeToken) {
    const name = basename(command.replace(/\\/g, '/')).replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
    const isDocker = name === 'docker';
    if (!isDocker && treeToken === null)
        return env;
    return {
        ...env,
        ...(treeToken !== null ? { [PROC_TREE_ENV]: treeToken } : {}),
        ...(isDocker ? { MSYS_NO_PATHCONV: '1', MSYS2_ARG_CONV_EXCL: '*' } : {}),
    };
}
function attachStdoutCap(child, cap, onChunk, onOversize) {
    let total = 0;
    child.stdout?.on('data', (chunk) => {
        total += chunk.length;
        if (total > cap) {
            onOversize();
            return;
        }
        onChunk(chunk.toString('utf8'));
    });
}
function attachStderr(child, onChunk) {
    child.stderr?.on('data', (chunk) => {
        onChunk(chunk.toString('utf8'));
    });
}
/**
 * Stop the child's whole tree: a graceful signal now, SIGKILL after
 * `KILL_GRACE_MS`, and — if the pipes are STILL open after that, which means
 * something outside the tree holds them — stop reading them so the caller is
 * released. Called once per child — see `stopTree`.
 */
function killTree(child, command, treeToken, isSettled) {
    const pid = child.pid;
    if (pid === undefined)
        return;
    let treeKill = Promise.resolve();
    if (treeToken !== null) {
        // `taskkill /T /F` plus the MSYS orphans it cannot see — see
        // `windowsTreeKill.ts`. The direct kill is only a FALLBACK, after
        // taskkill failed: killing the root first would make taskkill's tree walk
        // start from a pid that no longer exists ("process not found") and orphan
        // every grandchild, which is what the old order did.
        const direct = () => {
            try {
                child.kill('SIGTERM');
            }
            catch {
                /* already dead */
            }
        };
        treeKill = killWindowsTree(pid, command, treeToken, direct).catch(direct);
    }
    else {
        signalGroup(pid, 'SIGTERM');
    }
    setTimeout(() => {
        if (isSettled())
            return;
        // On Windows, never escalate while taskkill is still walking the tree
        // (measured at up to ~5 s on a loaded host): SIGKILLing the root under
        // it would orphan the grandchildren it has not reached yet.
        void treeKill.then(() => {
            if (isSettled())
                return;
            if (treeToken !== null) {
                try {
                    child.kill('SIGKILL');
                }
                catch {
                    /* already dead */
                }
            }
            else {
                signalGroup(pid, 'SIGKILL');
            }
            setTimeout(() => {
                if (isSettled())
                    return;
                child.stdout?.destroy();
                child.stderr?.destroy();
            }, PIPE_ABANDON_MS).unref();
        });
    }, KILL_GRACE_MS).unref();
}
/** Signal a POSIX process group (negative pid). ESRCH = already gone. */
function signalGroup(pid, signal) {
    if (pid === undefined)
        return;
    try {
        process.kill(-pid, signal);
    }
    catch {
        /* ESRCH: the group is already gone. */
    }
}
//# sourceMappingURL=processRunner.js.map