/**
 * shellcheck over a project's shell scripts — `quality_check` (whole project
 * or a scope). Measured on shellcheck 0.11.0 (Windows and Linux, 2026-10-24),
 * and deciding every argument below:
 *
 *   - It writes its report to stdout only (`-f json1`: `{ comments: [...] }`),
 *     so each command-line batch is one run whose stdout is the report.
 *   - Exit 0 is clean, 1 is comments, 2 is "some file could not be read" —
 *     the others' report is still written, and stderr names the file
 *     (`x.sh: x.sh: openBinaryFile: does not exist …`). 3 and 4 are bad
 *     options: a failure.
 *   - A script it could not parse is reported as comments, not as an error:
 *     SC1072 / SC1073 ("Fix to allow more checks") mean the rest of the file
 *     was NOT checked, so the file is named `Syntax error` (partial). SC1071
 *     is a shell it does not support (zsh): those scripts are never listed
 *     ({@link shellScripts}), and one reaching it anyway is named.
 *   - Configuration: shellcheck looks for `.shellcheckrc` in each script's
 *     directory and upwards, then in the user's home — a file there could
 *     switch checks off for every project. Only the project's ROOT
 *     `.shellcheckrc` is honoured, through `--rcfile` (which wins over the
 *     search, nested ones included, measured); without one, `--norc`. A
 *     `# shellcheck disable=` directive in a script is the script's own call.
 *   - SC1091 ("Not following: … was not specified as input") is about the
 *     analysis, not the code, and is excluded; `-x` is never passed, so a
 *     sourced file outside the project is never read.
 */

import type { PartialParse, ToolRun } from '../types.js';
import { readProjectHead, presentInProject } from '../platform/projectFs.js';
import { join } from 'node:path';
import { batchArgs } from './argBatches.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { nameRepoConfig } from './repoConfig.js';
import { asArray, getNumber, getProp, getString, parseInputAsJson, toPosixPath } from './scannerParsers/index.js';

/** The `tools_run` name of the shellcheck pass. */
export const SHELLCHECK = 'shellcheck';

/** Extensions shellcheck reads as sh, bash, dash or ksh. */
const SHELL_EXTENSIONS = /\.(sh|bash|dash|ksh)$/i;

/** `#!/bin/sh`, `#!/usr/bin/env bash`, `#!/bin/busybox sh`, … — never zsh or fish. */
const SHELL_SHEBANG = /^#![ \t]*\/\S*\/(?:env[ \t]+(?:-\S+[ \t]+)*)?(?:busybox[ \t]+)?(?:sh|bash|dash|ksh|mksh)\b/;

/** How much of an extensionless file is read to find its shebang. */
const SHEBANG_BYTES = 128;

/** A file of a script shellcheck could not parse past its error. */
export const SHELLCHECK_SYNTAX_ERROR = 'Syntax error';

/** Codes whose comment means the rest of the file was not checked. */
const PARSE_STOPPED = new Set([1072, 1073]);

/** SC1071: a shell shellcheck does not support. */
const UNSUPPORTED_SHELL = 1071;

/**
 * The shell scripts among `files` (project-relative, `/`-separated): a
 * `.sh` / `.bash` / `.dash` / `.ksh` file, or a file with no extension whose
 * first line is a shebang for one of those shells — read through the
 * bounded project reader, never a link out of the project.
 */
export function shellScripts(projectPath: string, files: readonly string[]): string[] {
  const out: string[] = [];
  for (const raw of files) {
    const file = toPosixPath(raw);
    const name = file.slice(file.lastIndexOf('/') + 1);
    if (SHELL_EXTENSIONS.test(name)) {
      out.push(file);
      continue;
    }
    if (name.includes('.')) continue;
    const head = readProjectHead(projectPath, file, SHEBANG_BYTES);
    if (head.status === 'ok' && SHELL_SHEBANG.test(head.text)) out.push(file);
  }
  return out.sort();
}

interface ShellcheckBatch {
  ok: boolean;
  reason?: string;
  /** The report (stdout), when it parsed. */
  report?: string;
  partial: PartialParse[];
}

/** `x.sh: x.sh: openBinaryFile: …` → `x.sh`, the message after it. */
const UNREAD_LINE = /^(.+?): \1: (.+)$/;

/** One batch's run, judged (see the module comment). */
export function judgeShellcheck(run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>): ShellcheckBatch {
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return { ok: false, reason: `did not finish (${run.outcome})`, partial: [] };
  }
  if (run.exitCode !== 0 && run.exitCode !== 1 && run.exitCode !== 2) {
    const line = run.stderr.split(/\r?\n/).find((l) => l.trim() !== '')?.trim();
    return { ok: false, reason: `exit ${String(run.exitCode)}${line ? `: ${line}` : ''}`, partial: [] };
  }
  const root = parseInputAsJson(run.stdout);
  const comments = getProp(root, 'comments');
  if (!Array.isArray(comments)) return { ok: false, reason: 'no readable report was written', partial: [] };
  const partial: PartialParse[] = [];
  const add = (file: string, type: string, message: string): void => {
    if (!partial.some((p) => p.file === file && p.type === type)) partial.push({ file, type, message });
  };
  for (const c of asArray(comments)) {
    const code = getNumber(c, 'code');
    const file = getString(c, 'file');
    if (file === undefined || code === undefined) continue;
    if (PARSE_STOPPED.has(code)) add(file, SHELLCHECK_SYNTAX_ERROR, getString(c, 'message') ?? 'could not parse');
    else if (code === UNSUPPORTED_SHELL) add(file, 'Unsupported shell', getString(c, 'message') ?? 'unsupported shell');
  }
  if (run.exitCode === 2) {
    const unread = run.stderr
      .split(/\r?\n/)
      .map((l) => UNREAD_LINE.exec(l.trim()))
      .filter((m): m is RegExpExecArray => m !== null);
    if (unread.length === 0) return { ok: false, reason: 'exit 2: a file could not be read, and shellcheck named none', partial };
    for (const m of unread) add(m[1] ?? '', 'Not read', m[2] ?? 'could not be read');
  }
  return { ok: true, report: run.stdout, partial };
}

interface ShellcheckPass {
  toolRun: ToolRun;
  /** Whether the run is a gap too (`missing_tools`): files it read only in part, or not at all. */
  missing: boolean;
  reports: string[];
  cancelled: boolean;
}

/**
 * shellcheck over `scripts` (project-relative), one run per command-line
 * batch. `ok` with the scripts it could not check named (`partially_parsed`,
 * and `missing`), or `failed` with the batch's reason; the reports any batch
 * wrote are kept either way.
 */
export async function shellcheckScripts(args: {
  projectPath: string;
  scripts: readonly string[];
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<ShellcheckPass> {
  const rootRc = presentInProject(args.projectPath, '.shellcheckrc');
  const fixed = ['-f', 'json1', ...(rootRc ? ['--rcfile', join(args.projectPath, '.shellcheckrc')] : ['--norc']), '--exclude=SC1091', '--'];
  const batches = batchArgs(args.scripts, { command: 'shellcheck', fixedArgs: fixed });
  const reports: string[] = [];
  const failures: string[] = [];
  const partial: PartialParse[] = [];
  let cancelled = false;
  for (const [i, batch] of batches.entries()) {
    if (args.signal.aborted) {
      cancelled = true;
      break;
    }
    const run = await runProcess({
      command: 'shellcheck',
      args: [...fixed, ...batch],
      cwd: args.projectPath,
      env: args.env,
      signal: args.signal,
      ...(args.onLog ? { onLog: args.onLog } : {}),
      stdoutCapBytes: 50 * 1024 * 1024,
    });
    if (run.outcome === 'cancelled') cancelled = true;
    const judged = judgeShellcheck(run);
    if (judged.report !== undefined) reports.push(judged.report);
    for (const p of judged.partial) {
      const file = toPosixPath(p.file);
      if (!partial.some((q) => q.file === file && q.type === p.type)) partial.push({ ...p, file });
    }
    if (!judged.ok) failures.push(`${batches.length > 1 ? `batch ${i + 1}/${batches.length}: ` : ''}${judged.reason ?? 'failed'}`);
    if (cancelled) break;
  }
  const described = `${args.scripts.length} script(s)${batches.length > 1 ? ` in ${batches.length} batches` : ''}`;
  if (failures.length > 0 || cancelled) {
    return {
      toolRun: { name: SHELLCHECK, status: 'failed', reason: cancelled && failures.length === 0 ? 'cancelled' : `${described}: ${failures.join('; ')}` },
      missing: false,
      reports,
      cancelled,
    };
  }
  const toolRun: ToolRun = { name: SHELLCHECK, status: 'ok', reason: `${described} checked` };
  if (partial.length > 0) {
    const shown = partial.slice(0, 5).map((p) => `${p.type}: ${p.file}`).join('; ');
    toolRun.reason += `; partial: ${partial.length} script(s) not fully checked (${shown}${partial.length > 5 ? '; …' : ''})`;
    toolRun.partially_parsed = partial;
  }
  // The root .shellcheckrc it was handed, named (`runners/repoConfig.ts`).
  return { toolRun: await nameRepoConfig(toolRun, args.projectPath, 'shellcheck'), missing: partial.length > 0, reports, cancelled };
}
