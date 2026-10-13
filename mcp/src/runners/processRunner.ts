/**
 * Generic child-process runner with the same safety net as `runShellScript`:
 *   - 5 MB rolling cap on stdout (kills the child if exceeded)
 *   - 10-minute default timeout (override via `GUARDIAN_SCAN_TIMEOUT_MS`)
 *   - AbortSignal → SIGTERM, then SIGKILL after 5 s
 *   - stderr line streaming via `onLog`
 *   - git hardening in the child's environment (`platform/gitSafety.ts`):
 *     no git the child starts — a scanner's `git ls-files`, gitleaks'
 *     `git log -p`, a package manager's clone — runs a command the scanned
 *     repository's own git configuration or hooks name. A repository whose
 *     configuration cannot be read safely is not run at all: outcome
 *     `failed`, the reason in stderr.
 *
 * `runShellScript` builds on this — direct scanner invocations (Semgrep,
 * Trivy CLI, gitleaks), the package managers `deps_update_plan` runs and the
 * archive extraction `scan_skill` does call `runProcess` straight.
 *
 * A bare command name is resolved in-process on the child's PATH and the
 * absolute path is spawned: never a binary the scanned project planted in
 * `cwd` (`platform/binaryPath.ts`).
 *
 * ---- Every kill is a TREE kill ----------------------------------------------
 *
 * Timeout, cancellation and the stdout cap all stop the child's whole process
 * tree, not just the direct child (`childProcess.ts#stopTree`). Scanners fork
 * (bash → semgrep → semgrep-core), and a grandchild that survives keeps the
 * stdout pipe open, so waiting for the child waits for IT: measured before
 * this was fixed, execa's own `timeout: 2000` returned after 25 151 ms — the
 * full lifetime of a `sleep 25` grandchild. So the timeout is implemented
 * here, and it goes through the same tree kill as the rest: a process group
 * on POSIX, `taskkill /T` plus the MSYS descendants on Windows — and, if a
 * pipe is still held open after the SIGKILL grace (a `setsid` grandchild),
 * the runner stops reading it rather than wait on it for ever. When this
 * process exits first, every live child's tree gets a SIGTERM.
 */

import { basename } from 'node:path';
import { findOnPath, isBareName } from '../platform/binaryPath.js';
import { applyGitSafety, gitSafetyFor, withoutHooksPath } from '../platform/gitSafety.js';
import { readText, startChild, stopTree } from './childProcess.js';

const FIVE_MB = 5 * 1024 * 1024;
const KILL_GRACE_MS = 5_000;
/** After SIGKILL, how long to keep waiting for the pipes before abandoning
 *  them. Only reached when something outside the tree still holds them. */
const PIPE_ABANDON_MS = 1_000;
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
/** `setTimeout`'s ceiling; a larger delay fires after 1 ms instead. */
const MAX_TIMER_MS = 2_147_483_647;

export type ProcessOutcome =
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'output_too_large'
  | 'timed_out';

export interface ProcessRunOptions {
  command: string;
  args?: string[];
  cwd: string;
  env?: NodeJS.ProcessEnv;
  /**
   * False replaces the child's environment with `env` instead of merging
   * `env` over the parent's. Defaults to true.
   *
   * This is the difference between an allowlist and a decoration: `env` is
   * merged over `process.env` by default, so passing a scrubbed `env`
   * WITHOUT this set to false hands the child every parent variable anyway
   * and scrubs nothing. Any caller passing `env` in order to withhold
   * something must pass `extendEnv: false` too.
   */
  extendEnv?: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
  onLog?: (line: string) => void;
  /**
   * Override the stdout buffer cap. Defaults to 5 MB. Set lower for
   * untrusted output or higher when a scanner is known to print
   * legitimately large reports (Trivy fs on a monorepo, for instance).
   */
  stdoutCapBytes?: number;
  /**
   * Git hardening for this child and everything it starts
   * (`platform/gitSafety.ts`): git's configuration overrides in its
   * environment, so no git it runs — directly, or inside a scanner or a
   * package manager — executes a command the scanned repository's own git
   * configuration or hooks name. On by default, for every child. `false`
   * only for a child that runs the project's own code BY DESIGN (the test
   * command create_fix_pr verifies with): that code can do anything git
   * could, and the overrides would change how its own tests use git.
   * `'except-hooks-path'` keeps all of it but the `core.hooksPath` redirect,
   * for the child whose job is installing hooks (`gitSafety.ts#withoutHooksPath`).
   */
  gitHardening?: boolean | 'except-hooks-path';
  /**
   * Further directories whose repository configuration this child's git
   * reaches, beyond `cwd` — a push to a local-path remote, a scanner handed a
   * repository elsewhere.
   */
  gitRepos?: readonly string[];
}

/** Why a child never ran: not on PATH, a repository whose git configuration was refused, or a spawn error. */
interface ProcessNotRun {
  /** `not_found`, `git_config_refused`, or the spawn error's code (`ENOENT`, `EACCES`, …). */
  code: string;
  message: string;
}

export interface ProcessRunResult {
  outcome: ProcessOutcome;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  /**
   * Keys of the repository's own git configuration the hardening overrode
   * for this child (`filter.lfs.smudge`, `diff.x.textconv`, …). Present only
   * when there were some — a caller whose result depends on them names them.
   */
  gitNotApplied?: readonly string[];
  /** Set when the child was never started; `outcome` is then `failed` and `exitCode` null. */
  notRun?: ProcessNotRun;
}

export async function runProcess(options: ProcessRunOptions): Promise<ProcessRunResult> {
  // The timeout covers the whole call — the git configuration read below
  // included — so a caller's budget is the time it waits.
  const started = Date.now();
  const timeoutMs =
    options.timeoutMs ??
    (Number(process.env['GUARDIAN_SCAN_TIMEOUT_MS']) || DEFAULT_TIMEOUT_MS);
  const cap = options.stdoutCapBytes ?? FIVE_MB;

  let stdoutBuf = '';
  let stderrBuf = '';
  let truncated = false;
  let outcome: ProcessOutcome = 'completed';

  // The environment the child would have had: `env` over this process's, or
  // `env` alone.
  const extendEnv = options.extendEnv ?? true;
  let childEnv: NodeJS.ProcessEnv = extendEnv ? { ...process.env, ...(options.env ?? {}) } : { ...(options.env ?? {}) };
  let gitNotApplied: readonly string[] = [];
  if (options.gitHardening !== false) {
    // Hardened — the user's own GIT_CONFIG_COUNT entries are counted before
    // ours are appended.
    const full = await gitSafetyFor([options.cwd, ...(options.gitRepos ?? [])], { env: childEnv });
    const safety = options.gitHardening === 'except-hooks-path' ? withoutHooksPath(full) : full;
    if (safety.refused !== null) {
      const message = `dev-guardian did not run ${basename(options.command)}: ${safety.refused}`;
      return notRun({ code: 'git_config_refused', message }, message);
    }
    childEnv = applyGitSafety(safety, childEnv);
    gitNotApplied = safety.notApplied;
  }

  // A bare name is spawned by the absolute path it resolves to on the CHILD's PATH, looked up here —
  // never in `cwd`, which is usually the project being scanned (platform/binaryPath.ts). Found on no
  // PATH entry, the one place left for a spawn to find it is `cwd`: it is not spawned at all.
  const command = isBareName(options.command) ? findOnPath(options.command, childEnv) : options.command;
  if (command === null) {
    return notRun({ code: 'not_found', message: `${options.command}: not found on PATH` }, `${options.command}: not found on PATH\n`);
  }

  const child = startChild(command, options.args ?? [], { cwd: options.cwd, env: envFor(command, childEnv) });
  // Timeout, abort and the stdout cap can all fire; the tree is stopped once.
  const stop = (): void => {
    void stopTree(child, { graceMs: KILL_GRACE_MS, abandonMs: PIPE_ABANDON_MS });
  };

  readText(child.process?.stdout, (text, totalBytes) => {
    if (totalBytes > cap) {
      if (outcome === 'completed') outcome = 'output_too_large';
      truncated = true;
      stop();
      return;
    }
    stdoutBuf += text;
  });

  // Cap stderr at 1/10 of the stdout cap (default 512 KB). Long-running
  // tools with `--verbose` flags can spew MBs of stderr; without a cap the
  // server would grow unbounded.
  const stderrCap = Math.max(64 * 1024, Math.floor(cap / 10));
  readText(child.process?.stderr, (text, totalBytes) => {
    if (totalBytes <= stderrCap) {
      stderrBuf += text;
    } else if (!stderrBuf.endsWith('…(truncated)\n')) {
      stderrBuf += '…(truncated)\n';
    }
    if (options.onLog) {
      for (const line of text.split(/\r?\n/)) {
        if (line.length > 0) options.onLog(line);
      }
    }
  });

  let timer: NodeJS.Timeout | null = null;
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    timer = setTimeout(
      () => {
        if (outcome === 'completed') outcome = 'timed_out';
        stop();
      },
      // What is left of the budget after the configuration read (at least 1 ms).
      Math.min(Math.max(1, timeoutMs - (Date.now() - started)), MAX_TIMER_MS),
    );
  }

  let abortListener: (() => void) | null = null;
  if (options.signal) {
    if (options.signal.aborted) {
      outcome = 'cancelled';
      stop();
    } else {
      abortListener = () => {
        if (outcome === 'completed') outcome = 'cancelled';
        stop();
      };
      options.signal.addEventListener('abort', abortListener, { once: true });
    }
  }

  const exit = await child.done;
  if (timer) clearTimeout(timer);
  if (abortListener && options.signal) {
    options.signal.removeEventListener('abort', abortListener);
  }

  if (exit.spawnError !== undefined) {
    const message = `${basename(command)}: ${exit.spawnError.message}`;
    return { ...notRun({ code: exit.spawnError.code ?? 'spawn_failed', message }, `${stderrBuf}${message}\n`), ...gitNotAppliedField(gitNotApplied) };
  }
  if (outcome === 'completed' && exit.exitCode !== 0) outcome = 'failed';

  return {
    outcome,
    exitCode: exit.exitCode,
    stdout: stdoutBuf,
    stderr: stderrBuf,
    truncated,
    ...gitNotAppliedField(gitNotApplied),
  };
}

function notRun(reason: ProcessNotRun, stderr: string): ProcessRunResult {
  return { outcome: 'failed', exitCode: null, stdout: '', stderr, truncated: false, notRun: reason };
}

function gitNotAppliedField(keys: readonly string[]): { gitNotApplied?: readonly string[] } {
  return keys.length > 0 ? { gitNotApplied: keys } : {};
}

/**
 * Environment for the child: the caller's, plus — for `docker` only — the
 * two variables that stop Git Bash's MSYS layer rewriting POSIX-looking
 * arguments. An MSYS parent turns `-w /src` into `-w C:/Program
 * Files/Git/src` (measured). A Node parent does not rewrite anything itself,
 * so from here this is defence for any MSYS process that ends up between us
 * and docker — never for other commands, where scripts running under Git
 * Bash rely on the conversion to hand Windows paths to native tools.
 */
function envFor(command: string, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const name = basename(command.replace(/\\/g, '/')).replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
  if (name !== 'docker') return env;
  return { ...env, MSYS_NO_PATHCONV: '1', MSYS2_ARG_CONV_EXCL: '*' };
}
