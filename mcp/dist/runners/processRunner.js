/**
 * Generic child-process runner with the same safety net as `runShellScript`:
 *   - 5 MB rolling cap on stdout (kills the child if exceeded)
 *   - 10-minute default timeout (override via `GUARDIAN_SCAN_TIMEOUT_MS`)
 *   - AbortSignal → SIGTERM, then SIGKILL after 5 s
 *   - stderr line streaming via `onLog`
 *
 * `runShellScript` builds on this — direct scanner invocations (Semgrep,
 * Trivy CLI, gitleaks) call `runProcess` straight.
 */
import { execa } from 'execa';
const FIVE_MB = 5 * 1024 * 1024;
const KILL_GRACE_MS = 5_000;
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
export async function runProcess(options) {
    const timeoutMs = options.timeoutMs ??
        (Number(process.env['GUARDIAN_SCAN_TIMEOUT_MS']) || DEFAULT_TIMEOUT_MS);
    const cap = options.stdoutCapBytes ?? FIVE_MB;
    let stdoutBuf = '';
    let stderrBuf = '';
    let truncated = false;
    let outcome = 'completed';
    const child = execa(options.command, options.args ?? [], {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        encoding: 'utf8',
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
        reject: false,
    });
    attachStdoutCap(child, cap, (chunk) => {
        stdoutBuf += chunk;
    }, () => {
        truncated = true;
        outcome = 'output_too_large';
        safeKill(child);
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
    let abortListener = null;
    if (options.signal) {
        if (options.signal.aborted) {
            safeKill(child);
            outcome = 'cancelled';
        }
        else {
            abortListener = () => {
                outcome = 'cancelled';
                safeKill(child);
            };
            options.signal.addEventListener('abort', abortListener, { once: true });
        }
    }
    const result = await child;
    if (abortListener && options.signal) {
        options.signal.removeEventListener('abort', abortListener);
    }
    if (outcome === 'completed') {
        if (result.timedOut)
            outcome = 'timed_out';
        else if (result.exitCode !== 0)
            outcome = 'failed';
    }
    return {
        outcome,
        exitCode: result.exitCode ?? null,
        stdout: stdoutBuf,
        stderr: stderrBuf,
        truncated,
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
function safeKill(child) {
    if (!child.pid)
        return;
    // On Windows, child.kill('SIGTERM') only signals the immediate child.
    // Scanners typically spawn grandchildren (e.g. node → bash → semgrep)
    // which would survive and continue running. `taskkill /T /F /PID` kills
    // the whole tree synchronously. We fire-and-forget — if taskkill itself
    // is missing or fails, we fall through to the regular kill.
    if (process.platform === 'win32') {
        try {
            // Spawn `taskkill` detached so we don't wait on it.
            // We deliberately don't `await` — the parent `child` promise will
            // resolve once the tree is dead.
            void execa('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
                reject: false,
                timeout: 5_000,
            }).catch(() => {
                /* nothing more to do */
            });
        }
        catch {
            /* fall through */
        }
    }
    try {
        child.kill('SIGTERM');
    }
    catch {
        /* already dead */
    }
    setTimeout(() => {
        try {
            child.kill('SIGKILL');
        }
        catch {
            /* already dead */
        }
    }, KILL_GRACE_MS).unref();
}
//# sourceMappingURL=processRunner.js.map