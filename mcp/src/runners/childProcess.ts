/**
 * How dev-guardian starts a child that may own a process TREE, and stops that
 * whole tree (review 8, finding 4). `runProcess` (the scanners, the package
 * managers, the archive extraction), `ci/appRunner.ts` (the application a DAST
 * pass probes), `mcpaudit/stdioTransport.ts` (a third-party MCP server) and,
 * since 3.4.0, async git (`runners/gitExec.ts`) share these. Not every child:
 * the one-process probes (`spawn.ts#captureOutput`), the tree kill's own
 * `ps`/`grep`/`taskkill`, and the synchronous git of `platform/gitSafety.ts`
 * (`execGitSync`, which the hooks use) start the plain way —
 * `test/unit/platform/gitSpawnSites.test.ts` classifies each.
 *
 * Starting ({@link startChild}): `spawn.ts#spawnNoShell` — `cross-spawn`,
 * no shell, no console window — with the child's environment exactly as given
 * (the caller merges; nothing of this process's is added behind its back),
 * `detached` on POSIX, the leader of its own process group, and a unique
 * `GUARDIAN_PROC_TREE_ID` on Windows, so {@link stopTree} can find what it
 * started.
 *
 * Stopping ({@link stopTree}), once per child however often it is asked:
 *
 *   - POSIX: SIGTERM to the NEGATIVE pid — the whole group — then, after the
 *     grace, SIGKILL to the group, which also takes a member that ignored
 *     SIGTERM after its leader exited. A descendant that calls `setsid()`
 *     itself leaves the group and is out of reach: the honest limit of any
 *     group kill.
 *   - Windows: `taskkill /T /F` plus the MSYS descendants the table loses,
 *     found by the token (`windowsTreeKill.ts`); the direct child is killed
 *     only as a FALLBACK, and never escalated while taskkill is still walking
 *     (killing the root under it orphans what it has not reached).
 *   - Then, if the pipes are STILL open — something outside the tree holds
 *     them (a `setsid` grandchild) — they are no longer read, so the caller is
 *     released. Measured before the runner owned its timeout: execa's
 *     `timeout: 2000` returned after 25 151 ms, the lifetime of a `sleep 25`
 *     grandchild holding the pipe.
 *
 * And when THIS process exits first — the server's shutdown, a SIGINT the CLI
 * did not handle — every live child gets a signal through `signal-exit`: its
 * group on POSIX, the child itself on Windows.
 */

import { randomUUID } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
import { onExit } from 'signal-exit';
import { isSpawnFailure, settlesWithin, spawnNoShell } from './spawn.js';
import { killWindowsTree, PROC_TREE_ENV } from './windowsTreeKill.js';

export { readText } from './spawn.js';

/** How a child ended: its exit code or signal, or the error that kept it from starting. */
export interface ChildExit {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  /** Set when the process could not be started at all (`ENOENT`, `EACCES`, …). */
  spawnError?: NodeJS.ErrnoException;
}

interface StartChildOptions {
  cwd: string;
  /** The child's WHOLE environment. Merge with `process.env` before calling, when that is what you mean. */
  env: NodeJS.ProcessEnv;
  /** `pipe` for a child this process talks to (an MCP server); `ignore` otherwise. */
  stdin?: 'ignore' | 'pipe';
  /** The signal the child's tree gets when this process exits first. Default SIGTERM. */
  signalOnParentExit?: NodeJS.Signals;
}

export interface Child {
  readonly process: ChildProcess;
  /** The command as spawned — `windowsTreeKill` reads the Git Bash it may be. */
  readonly command: string;
  /** Settles once the process has exited and its pipes have closed (or were abandoned). Never rejects. */
  readonly done: Promise<ChildExit>;
  /** Whether {@link done} has settled. */
  settled(): boolean;
}

interface ChildState extends Child {
  readonly treeToken: string | null;
  stopping: Promise<void> | null;
}

const POSIX_GROUP = process.platform !== 'win32';

/**
 * Starts `command` with `args`: no shell, the environment as given, stdout and
 * stderr piped, and — for {@link stopTree} — its own process group on POSIX or
 * a tree token on Windows. A command that cannot be started is not a throw:
 * `done` settles with its `spawnError`.
 *
 * `command` is an absolute path: a caller resolves a bare name with
 * `findOnPath` first (`platform/binaryPath.ts`) — `cross-spawn`'s own lookup
 * on Windows tries the working directory, usually the project, first.
 */
export function startChild(command: string, args: readonly string[], options: StartChildOptions): Child {
  const treeToken = POSIX_GROUP ? null : randomUUID();
  const env = treeToken === null ? options.env : { ...options.env, [PROC_TREE_ENV]: treeToken };
  // `detached` never on Windows (spawnNoShell): there it means a new console, not a group.
  const proc = spawnNoShell(command, args, { cwd: options.cwd, env, detached: true, stdio: [options.stdin ?? 'ignore', 'pipe', 'pipe'] });

  let isSettled = false;
  let removeExitHook: (() => void) | null = null;
  const done = new Promise<ChildExit>((resolve) => {
    const settle = (exit: ChildExit): void => {
      if (isSettled) return;
      isSettled = true;
      removeExitHook?.();
      resolve(exit);
    };
    // 'close': the process has exited AND its pipes are closed — so every
    // byte it wrote has been read. A spawn error: it never started — Node's
    // own, or cross-spawn's ENOENT for a command `cmd.exe` could not find.
    // Any other 'error' (a failed kill) changes nothing; the listener stays,
    // so none is ever unhandled.
    proc.once('close', (code, signal) => settle({ exitCode: code, signal }));
    proc.on('error', (error: NodeJS.ErrnoException) => {
      if (isSpawnFailure(proc, error)) settle({ exitCode: null, signal: null, spawnError: error });
    });
  });
  if (proc.pid !== undefined) {
    const signal = options.signalOnParentExit ?? 'SIGTERM';
    const pid = proc.pid;
    removeExitHook = onExit(() => {
      if (POSIX_GROUP) signalGroup(pid, signal);
      else killDirect(proc, signal);
    });
  }

  const child: ChildState = { process: proc, command, done, settled: () => isSettled, treeToken, stopping: null };
  return child;
}

interface StopTreeOptions {
  /** How long the tree gets after the first signal before it is killed outright. */
  graceMs: number;
  /** After the kill, how long to wait for the pipes before they are no longer read. */
  abandonMs: number;
}

/**
 * Stops `child`'s whole tree — see the module comment for how — and resolves
 * once the child has settled or its pipes were abandoned. Idempotent: a second
 * call, concurrent or later, awaits the same stop.
 */
export function stopTree(child: Child, options: StopTreeOptions): Promise<void> {
  const state = child as ChildState;
  state.stopping ??= stopOnce(state, options);
  return state.stopping;
}

async function stopOnce(child: ChildState, { graceMs, abandonMs }: StopTreeOptions): Promise<void> {
  const proc = child.process;
  const pid = proc.pid;
  if (pid === undefined || child.settled()) {
    await child.done;
    return;
  }
  let treeKill: Promise<void> = Promise.resolve();
  if (child.treeToken !== null) {
    const direct = (): void => killDirect(proc, 'SIGTERM');
    treeKill = killWindowsTree(pid, child.command, child.treeToken, direct).catch(direct);
  } else {
    signalGroup(pid, 'SIGTERM');
  }
  if (!(await settlesWithin(child.done, graceMs))) {
    // Never escalate on Windows while taskkill is still walking the tree.
    await treeKill;
    if (child.treeToken === null) signalGroup(pid, 'SIGKILL');
    else killDirect(proc, 'SIGKILL');
    if (!(await settlesWithin(child.done, abandonMs))) {
      // Something outside the tree holds the pipes: stop reading them.
      proc.stdout?.destroy();
      proc.stderr?.destroy();
      proc.stdin?.destroy();
    }
  } else if (child.treeToken === null) {
    // The leader is gone; a group member that ignored SIGTERM may not be.
    signalGroup(pid, 'SIGKILL');
  }
  await treeKill;
  await settlesWithin(child.done, abandonMs);
}

/** Signal a POSIX process group (negative pid). ESRCH = already gone. */
function signalGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-pid, signal);
  } catch {
    /* ESRCH: the group is already gone */
  }
}

function killDirect(proc: ChildProcess, signal: NodeJS.Signals): void {
  try {
    proc.kill(signal);
  } catch {
    /* already gone */
  }
}
