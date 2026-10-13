/**
 * The spawn primitive every child dev-guardian starts goes through (review 8,
 * finding 4): `cross-spawn` — Node's `spawn` with Windows' command resolution
 * done right, a `.cmd` / `.bat` shim such as `npm.cmd` run through `cmd.exe`
 * with every argument escaped, a shebang read; the spawn the MCP SDK's own
 * stdio client uses — with `shell: false` always and `windowsHide`.
 *
 * A child that owns a tree — a scanner, a package manager, an application, an
 * MCP server — is started through `childProcess.ts#startChild`, which stops
 * its whole tree. {@link captureOutput} is for the one-process probes the tree
 * kill itself needs (`ps`, `grep`, `taskkill`) and `--version` queries.
 */

import type { ChildProcess, StdioOptions } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import crossSpawn from 'cross-spawn';
import { findOnPath, isBareName } from '../platform/binaryPath.js';

export interface SpawnNoShellOptions {
  cwd?: string;
  /** The child's WHOLE environment. */
  env: NodeJS.ProcessEnv;
  stdio: StdioOptions;
  /** POSIX only: the leader of its own process group. */
  detached?: boolean;
}

/** `command` with `args`, no shell, no console window. */
export function spawnNoShell(command: string, args: readonly string[], options: SpawnNoShellOptions): ChildProcess {
  return crossSpawn(command, args, {
    ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    env: options.env,
    shell: false,
    windowsHide: true,
    detached: options.detached === true && process.platform !== 'win32',
    stdio: options.stdio,
  });
}

/**
 * Whether an `'error'` a child emitted means it never started: Node's own
 * spawn failure, or cross-spawn's `ENOENT` for a command `cmd.exe` could not
 * find (it emits that after the shell ran, with a pid).
 */
export function isSpawnFailure(proc: ChildProcess, error: NodeJS.ErrnoException): boolean {
  return proc.pid === undefined || String(error.syscall ?? '').startsWith('spawn');
}

/**
 * Reads a child's stream as UTF-8 text, a character split across two chunks
 * decoded whole. `onText` gets each decoded piece and the stream's byte total
 * so far.
 */
export function readText(stream: NodeJS.ReadableStream | null | undefined, onText: (text: string, totalBytes: number) => void): void {
  if (stream === null || stream === undefined) return;
  const decoder = new StringDecoder('utf8');
  let total = 0;
  stream.on('data', (chunk: Buffer | string) => {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
    total += buf.length;
    const text = decoder.write(buf);
    if (text !== '') onText(text, total);
  });
  stream.on('end', () => {
    const rest = decoder.end();
    if (rest !== '') onText(rest, total);
  });
}

/** Whether `p` settles within `ms` — the timer never keeps this process alive. */
export async function settlesWithin(p: Promise<unknown>, ms: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), ms);
    timer.unref();
  });
  const settled = await Promise.race([p.then(() => true as const, () => true as const), timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return settled;
}

export interface Captured {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Set when the command never started — not on PATH, or a spawn error. */
  spawnError?: string;
}

export interface CaptureOptions {
  cwd?: string;
  /** The child's whole environment; this process's by default. */
  env?: NodeJS.ProcessEnv;
  timeoutMs: number;
  /** The most of each stream kept; the rest is read and dropped. Default 16 MiB. */
  maxBytes?: number;
}

/** After a timeout's kill, how long the pipes get before they are no longer read. */
const CAPTURE_ABANDON_MS = 500;

/**
 * Runs a short, ONE-process command — `ps`, `grep`, `taskkill`, a
 * `--version` probe — and collects what it prints. A bare name is resolved on
 * the child's PATH first (`platform/binaryPath.ts`), never in `cwd`. At the
 * timeout the process is killed outright and, {@link CAPTURE_ABANDON_MS} later,
 * its pipes are no longer read: the answer comes at the deadline whatever
 * holds them. Never rejects. No tree kill — a command that starts others
 * belongs in `runProcess`.
 */
export function captureOutput(command: string, args: readonly string[], options: CaptureOptions): Promise<Captured> {
  const env = options.env ?? process.env;
  const file = isBareName(command) ? findOnPath(command, env) : command;
  if (file === null) {
    return Promise.resolve({ exitCode: null, stdout: '', stderr: '', timedOut: false, spawnError: `${command}: not found on PATH` });
  }
  return new Promise((resolve) => {
    const proc = spawnNoShell(file, args, { ...(options.cwd !== undefined ? { cwd: options.cwd } : {}), env, stdio: ['ignore', 'pipe', 'pipe'] });
    const max = options.maxBytes ?? 16 * 1024 * 1024;
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    readText(proc.stdout, (text, total) => {
      if (total <= max) stdout += text;
    });
    readText(proc.stderr, (text, total) => {
      if (total <= max) stderr += text;
    });
    const finish = (exitCode: number | null, spawnError?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode, stdout, stderr, timedOut, ...(spawnError !== undefined ? { spawnError } : {}) });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        proc.kill('SIGKILL');
      } catch {
        /* already gone */
      }
      setTimeout(() => {
        proc.stdout?.destroy();
        proc.stderr?.destroy();
        finish(null);
      }, CAPTURE_ABANDON_MS);
    }, options.timeoutMs);
    proc.once('close', (code) => finish(timedOut ? null : code));
    proc.on('error', (error: NodeJS.ErrnoException) => {
      if (isSpawnFailure(proc, error)) finish(null, error.message);
    });
  });
}
