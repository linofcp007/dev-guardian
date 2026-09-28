/**
 * The one way a test spawns Semgrep synchronously.
 *
 * ---- The defect this fixes ------------------------------------------------
 *
 * The rule-pack tests (`bugfixRules*`, `baseRules`, `rgpdRules`,
 * `semgrepPacks`) called `execFileSync('semgrep', …)` / `spawnSync('semgrep',
 * …)` with no `timeout`. A synchronous spawn blocks the vitest WORKER THREAD,
 * and vitest's own `testTimeout` is a timer on that same thread — it cannot
 * fire while the thread is blocked. So a Semgrep that stops making progress
 * (one was seen at 0 % CPU for 4.7 h under load) held its worker forever and
 * `npm test` never ended, with nothing on screen saying why.
 *
 * Every spawn here carries `timeout` + `killSignal: 'SIGKILL'`, and a timeout
 * THROWS {@link SemgrepTimeoutError} — the test fails at the bound with a
 * message naming the command, never hangs and never passes.
 *
 * ---- Why stdout goes to a file, not a pipe ---------------------------------
 *
 * `spawnSync` returns only once the child has exited AND its stdio pipes have
 * closed. `semgrep` is a Python launcher over `semgrep-core`; the kill reaches
 * the launcher only, and a grandchild still holding the pipe would keep
 * `spawnSync` waiting after the timeout had fired — the same hang, one level
 * down. With stdout and stderr written to files there is no pipe to wait on:
 * the call returns when the direct child is dead. An orphaned grandchild may
 * keep writing to a file nobody reads, which is harmless.
 *
 * ---- Knobs (test-only) -----------------------------------------------------
 *
 * - `GUARDIAN_TEST_SEMGREP_TIMEOUT_MS` — per-spawn bound (default 120 s), for a
 *   machine slow enough that a real run needs longer.
 * - `GUARDIAN_TEST_SEMGREP_CMD` — a JSON array naming the command to run
 *   instead of `semgrep` (e.g. `["node", "fake-semgrep.mjs"]`). It exists so the
 *   timeout itself can be demonstrated against a command that never finishes.
 */

import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmDir } from './tempDir.js';

/** Default bound on one Semgrep run. Below every rule-pack file's 180 s `testTimeout`. */
export const SEMGREP_TIMEOUT_MS = 120_000;

/** Bound on the `--version` probe that decides whether the Semgrep tests run at all. */
export const SEMGREP_VERSION_TIMEOUT_MS = 60_000;

/** A Semgrep run that did not finish within its bound and was killed. */
export class SemgrepTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SemgrepTimeoutError';
  }
}

export interface SemgrepRun {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SemgrepOptions {
  /** Overrides the bound for this call (and `GUARDIAN_TEST_SEMGREP_TIMEOUT_MS`). */
  readonly timeoutMs?: number;
  /** The working directory (Semgrep names a local rule relative to it when it can). */
  readonly cwd?: string;
}

function semgrepCommand(): { file: string; prefix: string[] } {
  const raw = process.env['GUARDIAN_TEST_SEMGREP_CMD'];
  if (raw === undefined || raw.trim() === '') return { file: 'semgrep', prefix: [] };
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed) || !parsed.every((x): x is string => typeof x === 'string')) {
    throw new Error('GUARDIAN_TEST_SEMGREP_CMD must be a JSON array of strings');
  }
  const [file, ...prefix] = parsed;
  if (file === undefined) throw new Error('GUARDIAN_TEST_SEMGREP_CMD must name a command');
  return { file, prefix };
}

function defaultTimeoutMs(): number {
  const raw = process.env['GUARDIAN_TEST_SEMGREP_TIMEOUT_MS'];
  const n = raw === undefined ? Number.NaN : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : SEMGREP_TIMEOUT_MS;
}

/**
 * Runs Semgrep with `args` and returns its exit status and output. Throws
 * {@link SemgrepTimeoutError} when it outlives its bound, and the spawn error
 * itself when it could not start (e.g. `ENOENT`). A non-zero exit is returned,
 * not thrown — see {@link semgrepStdout} for the throwing form.
 */
export function runSemgrep(args: readonly string[], options: SemgrepOptions = {}): SemgrepRun {
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs();
  const { file, prefix } = semgrepCommand();
  const io = mkdtempSync(join(tmpdir(), 'guardian-semgrep-io-'));
  const outPath = join(io, 'stdout');
  const errPath = join(io, 'stderr');
  const out = openSync(outPath, 'w');
  const err = openSync(errPath, 'w');
  let result: ReturnType<typeof spawnSync>;
  try {
    result = spawnSync(file, [...prefix, ...args], {
      stdio: ['ignore', out, err],
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      windowsHide: true,
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    });
  } finally {
    closeSync(out);
    closeSync(err);
  }
  const stdout = readFileSync(outPath, 'utf8');
  const stderr = readFileSync(errPath, 'utf8');
  try {
    rmDir(io);
  } catch {
    // An orphaned semgrep-core may still hold the file open on Windows.
  }

  const spawnError = result.error as NodeJS.ErrnoException | undefined;
  if (spawnError !== undefined) {
    if (spawnError.code === 'ETIMEDOUT') {
      throw new SemgrepTimeoutError(
        `semgrep did not finish within ${String(timeoutMs / 1000)} s and was killed (SIGKILL): ` +
          `${[file, ...prefix, ...args].join(' ')}. Raise GUARDIAN_TEST_SEMGREP_TIMEOUT_MS only if a ` +
          'healthy run on this machine really takes longer; a hung Semgrep used to block the vitest ' +
          'worker for hours.',
      );
    }
    throw spawnError;
  }
  return { status: result.status, stdout, stderr };
}

/**
 * `execFileSync` semantics: the stdout of a run that exited 0, or an error
 * naming the exit status and the tail of stderr. A timeout throws
 * {@link SemgrepTimeoutError} as in {@link runSemgrep}.
 */
export function semgrepStdout(args: readonly string[], options: SemgrepOptions = {}): string {
  const run = runSemgrep(args, options);
  if (run.status !== 0) {
    throw new Error(
      `semgrep exited ${String(run.status)}: semgrep ${args.join(' ')}\n${run.stderr.slice(-4000)}`,
    );
  }
  return run.stdout;
}

/**
 * Whether Semgrep answers `--version` — the gate every rule-pack test file
 * skips on. Absent (`ENOENT`) or failing is `false`; a probe that HANGS is not
 * "absent", so its {@link SemgrepTimeoutError} is rethrown and the file fails
 * loudly instead of skipping quietly.
 */
export function semgrepAvailable(): boolean {
  try {
    return runSemgrep(['--version'], { timeoutMs: SEMGREP_VERSION_TIMEOUT_MS }).status === 0;
  } catch (e) {
    if (e instanceof SemgrepTimeoutError) throw e;
    return false;
  }
}
