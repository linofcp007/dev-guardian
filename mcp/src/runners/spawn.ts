/**
 * The spawn primitive under dev-guardian's runners (review 8, finding 4):
 * every child `runProcess`, `startChild` (async git too, `runners/gitExec.ts`)
 * and `captureOutput` start goes through it — not the synchronous git of
 * `platform/gitSafety.ts` nor the one `node -e` of `mcpaudit/launch.ts`. It is `cross-spawn` — Node's `spawn`
 * with Windows' command resolution done right, a `.cmd` / `.bat` file such as
 * `npm.cmd` run through `cmd.exe` with its arguments escaped, a shebang read;
 * the spawn the MCP SDK's own stdio client uses — with `shell: false` always
 * and `windowsHide`.
 *
 * ## A batch file is handed only arguments `cmd.exe` cannot misread
 *
 * A `.cmd` / `.bat` file runs through `cmd.exe`, which parses its command line
 * TWICE: once for `cmd /d /s /c "…"`, and again when the batch file expands
 * `%*` / `%1` into its own lines. cross-spawn escapes for the first parse only
 * (the second, a `^` per metacharacter, only for npm's own shims under
 * `node_modules\.bin`), so an argument with a `"` before an `&` closed its
 * quotes in the second parse and ran the rest as a command — "BatBadBut"
 * (review 10, finding 3): `wp_report { kind: "plugin", slug: 'x"&echo
 * PWNED>f&"' }` wrote `f` through a `wp.bat`, `wp_vuln_check` through
 * `wpscan.bat`, `perf_check` through `lighthouse.cmd`.
 *
 * No escaping is right for every batch file: what is safe depends on how the
 * file itself uses its arguments (`%*`, `"%~1"`, a `call`), which dev-guardian
 * does not know. So such an argument is REFUSED rather than escaped: when
 * cross-spawn's parse says the command runs through `cmd.exe`, an argument
 * (or the command's own path) holding a double quote, a percent sign, a
 * carriage return, a line feed or a NUL is not started at all —
 * {@link BatchArgumentRefused}, which every caller reports as the spawn
 * failure it is (`notRun.code: 'batch_argument_refused'`). With none of them,
 * every argument stays inside the double quotes cross-spawn wraps it in
 * through both parses — a `"` is what closes them, `%` expands a variable
 * before quoting is read (`%CMDCMDLINE:~-1%` IS a quote), and a line break
 * ends the command — so `&`, `|`, `<`, `>`, `^`, `(`, `)` and `!` arrive as
 * data. A `.exe` is never judged: its arguments reach it through
 * `CreateProcess` alone. The tools validate what they pass as well (a slug
 * as a slug, a URL parsed and re-serialised); this is the layer that holds
 * for every caller.
 *
 * A child that owns a tree — a scanner, a package manager, an application, an
 * MCP server — is started through `childProcess.ts#startChild`, which stops
 * its whole tree. {@link captureOutput} is for the one-process probes the tree
 * kill itself needs (`ps`, `grep`, `taskkill`) and `--version` queries.
 */

import { spawn, type ChildProcess, type SpawnOptions, type StdioOptions } from 'node:child_process';
import { basename } from 'node:path';
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

/** What `cmd.exe` cannot be handed inside an argument (see the module comment). */
const CMD_UNSAFE: ReadonlyArray<readonly [string, string]> = [
  ['"', 'a double quote'],
  ['%', 'a percent sign'],
  ['\r', 'a carriage return'],
  ['\n', 'a line feed'],
  ['\0', 'a NUL character'],
];

/**
 * A command not started because `cmd.exe` would have run it with an argument
 * it cannot be handed safely (see the module comment). Thrown by
 * {@link spawnNoShell}; `startChild` and {@link captureOutput} turn it into
 * the spawn failure every caller already handles.
 */
export class BatchArgumentRefused extends Error implements NodeJS.ErrnoException {
  readonly code = 'batch_argument_refused';
  readonly syscall = 'spawn';
  constructor(command: string, what: string) {
    super(
      `on Windows ${basename(command)} runs through cmd.exe, which cannot be handed ${what} without ` +
        'risking a second command, so dev-guardian refused to start it',
    );
    this.name = 'BatchArgumentRefused';
  }
}

/** Which of `command` and `args` `cmd.exe` cannot be handed, described; null when none. */
function cmdUnsafePart(command: string, args: readonly string[]): string | null {
  const parts = [command, ...args];
  for (const [index, part] of parts.entries()) {
    const hit = CMD_UNSAFE.find(([char]) => part.includes(char));
    if (hit !== undefined) return `${index === 0 ? 'a command path' : `an argument (#${index})`} holding ${hit[1]}`;
  }
  return null;
}

/**
 * `command` with `args`, no shell, no console window. Throws
 * {@link BatchArgumentRefused} — and starts nothing — when Windows would run
 * it through `cmd.exe` with an argument `cmd.exe` cannot be handed safely.
 */
export function spawnNoShell(command: string, args: readonly string[], options: SpawnNoShellOptions): ChildProcess {
  const spawnOptions: SpawnOptions = {
    ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    env: options.env,
    shell: false,
    windowsHide: true,
    detached: options.detached === true && process.platform !== 'win32',
    stdio: options.stdio,
  };
  // cross-spawn's own `spawn`, in its three steps, so that what it would hand
  // `cmd.exe` is judged before anything starts. It sets
  // `windowsVerbatimArguments` exactly when it built a `cmd.exe` line.
  const parsed = crossSpawn._parse(command, args, spawnOptions);
  if (parsed.options.windowsVerbatimArguments === true) {
    const unsafe = cmdUnsafePart(command, args);
    if (unsafe !== null) throw new BatchArgumentRefused(command, unsafe);
  }
  const child = spawn(parsed.command, parsed.args, parsed.options);
  crossSpawn._enoent.hookChildProcess(child, parsed);
  return child;
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
  let proc: ChildProcess;
  try {
    proc = spawnNoShell(file, args, { ...(options.cwd !== undefined ? { cwd: options.cwd } : {}), env, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    if (!(e instanceof BatchArgumentRefused)) throw e;
    return Promise.resolve({ exitCode: null, stdout: '', stderr: '', timedOut: false, spawnError: e.message });
  }
  return new Promise((resolve) => {
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
