/**
 * Run a `.sh` script under the probed shell.
 *
 * Thin wrapper over `runProcess` that translates a `ShellChoice` into
 * `(command, argsPrefix)`. Under WSL the script path AND every argument that
 * is an absolute Windows path are converted (`C:\proj` → `/mnt/c/proj`):
 * bash there runs in the Linux filesystem view, where a `C:\…` project path
 * names nothing and the script scans nothing. Converting only the script path
 * — as this once did — broke every script tool under WSL.
 *
 * All the safety machinery (5 MB cap, SIGTERM/SIGKILL, timeout, stderr
 * streaming) lives in `runProcess` — this file only wires the shell.
 */

import { toShellPath, type ShellChoiceLike } from '../platform/pathTranslate.js';
import type { ShellChoice } from '../platform/shellProbe.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';

export type ShellRunOutcome = ProcessRunResult['outcome'];
export type ShellRunResult = ProcessRunResult;

export interface ShellRunOptions {
  shell: ShellChoice;
  scriptPath: string;
  args?: string[];
  cwd: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  timeoutMs?: number;
  onLog?: (line: string) => void;
}

export async function runShellScript(options: ShellRunOptions): Promise<ShellRunResult> {
  const shell: ShellChoiceLike = options.shell;
  const scriptArg = toShellPath(options.scriptPath, shell);
  const userArgs = (options.args ?? []).map((a) =>
    isWindowsAbsolutePath(a) ? toShellPath(a, shell) : a,
  );
  const args = [...options.shell.args_prefix, scriptArg, ...userArgs];

  const runOpts: Parameters<typeof runProcess>[0] = {
    command: options.shell.command,
    args,
    cwd: options.cwd,
  };
  if (options.env !== undefined) runOpts.env = options.env;
  if (options.signal !== undefined) runOpts.signal = options.signal;
  if (options.timeoutMs !== undefined) runOpts.timeoutMs = options.timeoutMs;
  if (options.onLog !== undefined) runOpts.onLog = options.onLog;

  return runProcess(runOpts);
}

/** `C:\x`, `c:/x` — a drive-letter absolute path. Flags and relative paths are not. */
function isWindowsAbsolutePath(arg: string): boolean {
  return /^[a-zA-Z]:[\\/]/.test(arg);
}
