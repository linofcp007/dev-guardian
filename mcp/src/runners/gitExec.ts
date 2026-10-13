/**
 * Async git on the shared tree kill (review 10, finding 12).
 *
 * `platform/gitSafety.ts` spawned git with Node's `spawn` and, on a timeout,
 * killed git alone. A `git clone` over HTTPS is git plus `git remote-https`
 * (and a credential helper, `ssh`, …): on Windows the helper survived, held
 * the pipes, and `scan_skill` on a URL that stalled answered after more than
 * 330 s against its 120 s timeout. {@link spawnGitTree} starts git through
 * `childProcess.ts#startChild` and stops its whole tree with `stopTree` —
 * the process group on POSIX, `taskkill /T` plus the MSYS descendants on
 * Windows — as every scanner is stopped.
 *
 * It is installed into `gitSafety.ts` (`useGitSpawner`) when this module
 * loads, rather than imported there, because the hook bundle loads
 * `gitSafety.ts` and may hold no npm package — the tree kill brings two.
 * `runners/git.ts`, through which the engine runs git, imports this module;
 * so do the other modules that call `execGit` themselves.
 */

import { tmpdir } from 'node:os';
import { useGitSpawner, type Collected, type GitSpawner } from '../platform/gitSafety.js';
import { startChild, stopTree } from './childProcess.js';

/** After the stop signal, how long git's tree gets before it is killed outright. */
const GRACE_MS = 1_000;
/** After the kill, how long to wait for the pipes before they are no longer read. */
const ABANDON_MS = 2_000;
/** stderr kept, as before: a git that writes more is cut, never failed for it. */
const MAX_STDERR = 1024 * 1024;

/** {@link GitSpawner} on the shared tree kill — see the module comment. Never rejects. */
export const spawnGitTree: GitSpawner = (command, args, opts) =>
  new Promise<Collected>((resolveRun) => {
    // `command` is absolute (`gitSafety.ts#gitExecutable`) and git runs with
    // `-C <dir>`: the working directory decides nothing, so it is one that
    // always exists.
    const child = startChild(command, args, { cwd: tmpdir(), env: opts.env });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outBytes = 0;
    let errBytes = 0;
    let error: NodeJS.ErrnoException | undefined;
    let stopping: Promise<void> | null = null;
    let settled = false;
    const finish = (status: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveRun({ status, stdout: Buffer.concat(out), stderr: Buffer.concat(err), ...(error !== undefined ? { error } : {}) });
    };
    const stop = (code: string, message: string): void => {
      error ??= Object.assign(new Error(message), { code });
      // Settled once the tree is stopped, even if a pipe was abandoned and
      // the child never reports its close.
      stopping ??= stopTree(child, { graceMs: GRACE_MS, abandonMs: ABANDON_MS }).then(() => finish(null));
    };
    const timer = setTimeout(() => stop('ETIMEDOUT', `timed out after ${opts.timeoutMs} ms`), opts.timeoutMs);
    child.process.stdout?.on('data', (chunk: Buffer) => {
      outBytes += chunk.length;
      if (outBytes > opts.maxBuffer) stop('ENOBUFS', 'stdout maxBuffer exceeded');
      else out.push(chunk);
    });
    child.process.stderr?.on('data', (chunk: Buffer) => {
      errBytes += chunk.length;
      if (errBytes <= MAX_STDERR) err.push(chunk);
    });
    void child.done.then(async (exit) => {
      clearTimeout(timer);
      if (exit.spawnError !== undefined) error ??= exit.spawnError;
      // A stop under way finishes first: the tree is gone when the caller hears back.
      if (stopping !== null) await stopping;
      finish(error !== undefined ? null : exit.exitCode);
    });
  });

useGitSpawner(spawnGitTree);
