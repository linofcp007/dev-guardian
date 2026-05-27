/**
 * Run a `.sh` script under the probed shell.
 *
 * Thin wrapper over `runProcess` that translates a `ShellChoice` into
 * `(command, argsPrefix)`. WSL paths are converted before being passed to
 * the script via `toShellPath`.
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
  const scriptArg = toShellPath(options.scriptPath, options.shell as ShellChoiceLike);
  const args = [...options.shell.args_prefix, scriptArg, ...(options.args ?? [])];

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
