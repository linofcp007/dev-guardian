/**
 * The stdio transport `audit_mcp_tools` starts a server with.
 *
 * The SDK's own `StdioClientTransport` spawns the same way — `cross-spawn`
 * (here through execa, which uses it), `shell: false`, the SDK's
 * `getDefaultEnvironment()` allowlist plus the entry's own `env` — but its
 * `close()` signals only the direct child. A server started as `npx -y pkg`,
 * `uvx pkg` or `cmd /c …` is a launcher with the real server as a GRANDCHILD,
 * and that grandchild would outlive the audit. So this transport owns the
 * process the way `runners/processRunner.ts` does, with the same tree kill:
 *
 *   - POSIX: spawned `detached`, the leader of its own process group, and
 *     the NEGATIVE pid signals the whole group (SIGTERM, then SIGKILL). A
 *     descendant that calls `setsid()` itself leaves the group and is out of
 *     reach — the same honest limit `processRunner.ts` documents.
 *   - Windows: `taskkill /T /F` plus the MSYS descendants found by the
 *     per-child `GUARDIAN_PROC_TREE_ID` token (`runners/windowsTreeKill.ts`).
 *
 * `close()` ALWAYS kills the tree — after a successful listing too: a server
 * that answered is still running, and nothing here needs it afterwards.
 * `detached` opts the child out of execa's kill-on-parent-exit, so a
 * `signal-exit` hook signals the group if this process exits mid-probe.
 *
 * The environment is exactly `getDefaultEnvironment()` + the entry's `env`
 * (+ the Windows tree token): `extendEnv: false`, so nothing else of this
 * server's environment — tokens, keys — reaches the third-party process.
 */
import { randomUUID } from 'node:crypto';
import { getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ReadBuffer, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';
import { execa } from 'execa';
import { onExit } from 'signal-exit';
import { killWindowsTree, PROC_TREE_ENV } from '../runners/windowsTreeKill.js';
/** A listing bigger than this is not a tool list; the read is abandoned. */
const MAX_READ_BUFFER_BYTES = 8 * 1024 * 1024;
/** How much of the server's stderr is kept, from the end. */
const STDERR_TAIL_CHARS = 2048;
const TERM_GRACE_MS = 2_000;
const KILL_GRACE_MS = 2_000;
/** The environment a probed server is started with. Exported for the tests. */
export function probeEnvironment(entryEnv, treeToken) {
    const base = {};
    for (const [k, v] of Object.entries(getDefaultEnvironment()))
        if (typeof v === 'string')
            base[k] = v;
    return { ...base, ...entryEnv, ...(treeToken === null ? {} : { [PROC_TREE_ENV]: treeToken }) };
}
export class ProbeStdioTransport {
    launch;
    onclose;
    onerror;
    onmessage;
    child;
    done;
    readBuffer = new ReadBuffer({ maxBufferSize: MAX_READ_BUFFER_BYTES });
    posixGroup = process.platform !== 'win32';
    treeToken = process.platform === 'win32' ? randomUUID() : null;
    removeExitHook = null;
    stderr = '';
    exited = null;
    closing = null;
    closeNotified = false;
    constructor(launch) {
        this.launch = launch;
    }
    /** Last {@link STDERR_TAIL_CHARS} characters the server wrote to stderr. */
    get stderrTail() {
        return this.stderr;
    }
    /** How the process ended, once it has; null while it runs. */
    get exit() {
        return this.exited;
    }
    async start() {
        if (this.child !== undefined)
            throw new Error('ProbeStdioTransport already started');
        const child = execa(this.launch.command, this.launch.args, {
            cwd: this.launch.cwd,
            env: probeEnvironment(this.launch.env, this.treeToken),
            extendEnv: false,
            shell: false,
            stdin: 'pipe',
            stdout: 'pipe',
            stderr: 'pipe',
            buffer: false,
            reject: false,
            detached: this.posixGroup,
            windowsHide: true,
        });
        this.child = child;
        if (this.posixGroup)
            this.removeExitHook = onExit(() => signalGroup(child.pid, 'SIGKILL'));
        child.stdout?.on('data', (chunk) => {
            try {
                this.readBuffer.append(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
            }
            catch (e) {
                this.onerror?.(e);
                void this.close();
                return;
            }
            for (;;) {
                let message;
                try {
                    message = this.readBuffer.readMessage();
                }
                catch (e) {
                    // A line that is not JSON-RPC (a banner on stdout): reported, skipped.
                    this.onerror?.(e);
                    continue;
                }
                if (message === null)
                    break;
                this.onmessage?.(message);
            }
        });
        child.stderr?.on('data', (chunk) => {
            this.stderr = (this.stderr + chunk.toString()).slice(-STDERR_TAIL_CHARS);
        });
        child.stdin?.on('error', (e) => this.onerror?.(e));
        const spawned = new Promise((resolve) => child.once('spawn', () => resolve('spawned')));
        // Resolves after the process has exited AND its pipes have closed, so
        // stderr is complete by then.
        this.done = child.then((result) => {
            this.exited = {
                exitCode: result.exitCode ?? null,
                signal: result.signal ?? null,
                ...(result.exitCode === undefined && result.signal === undefined && result.failed
                    ? { spawnError: result.shortMessage }
                    : {}),
            };
            this.removeExitHook?.();
            this.notifyClosed();
        });
        const first = await Promise.race([spawned, this.done.then(() => 'ended')]);
        if (first === 'ended' && this.exited?.spawnError !== undefined) {
            throw new Error(`could not start '${this.launch.command}': ${this.exited.spawnError}`);
        }
    }
    send(message) {
        return new Promise((resolve, reject) => {
            const stdin = this.child?.stdin;
            if (stdin === undefined || stdin === null || this.exited !== null) {
                reject(new Error('Not connected'));
                return;
            }
            if (stdin.write(serializeMessage(message)))
                resolve();
            else
                stdin.once('drain', () => resolve());
        });
    }
    /** Kill the whole tree, wait for it (bounded), then report closed. Idempotent. */
    close() {
        this.closing ??= this.killAndWait();
        return this.closing;
    }
    async killAndWait() {
        const child = this.child;
        const done = this.done;
        if (child === undefined || done === undefined) {
            this.notifyClosed();
            return;
        }
        try {
            child.stdin?.end();
        }
        catch {
            /* already closed */
        }
        const pid = child.pid;
        if (pid !== undefined) {
            if (this.treeToken !== null) {
                const direct = () => {
                    try {
                        child.kill('SIGKILL');
                    }
                    catch {
                        /* already gone */
                    }
                };
                await killWindowsTree(pid, this.launch.command, this.treeToken, direct).catch(direct);
            }
            else {
                signalGroup(pid, 'SIGTERM');
            }
        }
        if (!(await settlesWithin(done, TERM_GRACE_MS))) {
            if (this.treeToken === null)
                signalGroup(pid, 'SIGKILL');
            else
                child.kill('SIGKILL');
            if (!(await settlesWithin(done, KILL_GRACE_MS))) {
                // Something outside the tree holds the pipes: stop reading them.
                child.stdout?.destroy();
                child.stderr?.destroy();
            }
        }
        else if (this.treeToken === null) {
            // The leader is gone; a group member that ignored SIGTERM is not.
            signalGroup(pid, 'SIGKILL');
        }
        this.removeExitHook?.();
        this.readBuffer.clear();
        this.notifyClosed();
    }
    notifyClosed() {
        if (this.closeNotified)
            return;
        this.closeNotified = true;
        this.onclose?.();
    }
}
/** Signal a POSIX process group (negative pid). ESRCH = already gone. */
function signalGroup(pid, signal) {
    if (pid === undefined)
        return;
    try {
        process.kill(-pid, signal);
    }
    catch {
        /* ESRCH: the group is already gone */
    }
}
async function settlesWithin(p, ms) {
    let timer;
    const timeout = new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), ms);
        timer.unref();
    });
    const settled = await Promise.race([p.then(() => true, () => true), timeout]);
    if (timer !== undefined)
        clearTimeout(timer);
    return settled;
}
//# sourceMappingURL=stdioTransport.js.map