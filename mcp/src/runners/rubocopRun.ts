/**
 * RuboCop over a project's Ruby — `quality_check` (whole project or a
 * scope). Measured on RuboCop 1.92.1 with RubyInstaller 4.0.9 (Windows),
 * 2026-10-24, over seeded files, Sinatra (147 files) and Jekyll (162), and
 * deciding every argument below:
 *
 *   - Never the project's configuration: a `.rubocop.yml` holding
 *     `require: ./evil.rb` RAN that file (it wrote a marker) when RuboCop read
 *     the project's own configuration — and so does `plugins:` — at the root
 *     or in any directory below. With `--config <dev-guardian's file>` no
 *     `.rubocop.yml` anywhere is read (the marker stayed absent, a nested one
 *     included). The project's `# rubocop:disable` comments are honoured:
 *     they are comments.
 *   - Never from the project: RuboCop reads a `.rubocop` file in its working
 *     directory as more arguments, `--config` or not — one holding
 *     `--require ./evil.rb` RAN it (the marker was written). It runs from the
 *     report directory, which holds dev-guardian's files only, and is handed
 *     each file by its absolute path.
 *   - A `*` in a path makes RuboCop read it as a pattern (`Dir[path]`, after
 *     `--` too): such a file is never handed over — a name built of `{..,x}`
 *     and `**` would reach files outside the project — and is named.
 *   - Its departments that judge the code, not its layout: `--only
 *     Lint,Security,Metrics,Naming`. {@link rubocopConfig} keeps the cops
 *     that are still pending off (`NewCops: disable`: the same cops from one
 *     RuboCop to the next) and lets the blocks of the usual DSLs — RSpec's
 *     `describe`, Rake's `task`, Rails' `draw` — be long: `Metrics/BlockLength`
 *     was 128 of Sinatra's 521 offenses and 105 of Jekyll's 351, and 0 and 10
 *     with them allowed.
 *   - Run as `ruby <the gem's rubocop script>` — never its Windows `.bat`
 *     wrapper, which `cmd.exe` would run with the project's file names on its
 *     command line. Ruby's variables that load code before RuboCop does —
 *     `RUBYOPT` (`-rbundler/setup` would evaluate the project's `Gemfile`),
 *     `RUBYGEMS_GEMDEPS`, `BUNDLE_GEMFILE` — are left out of its environment.
 *   - `--format json` to stdout, one run per command-line batch, the files
 *     after `--`. Exit 0 is clean, 1 offenses, 2 an error (a file that is not
 *     there, a target Ruby it does not know): a failure.
 *   - A file it cannot parse is an offense, `Lint/Syntax` (severity
 *     `fatal`): its file is named `Syntax error` (partial), as shellcheck's.
 *   - The Ruby it parses for is set ({@link targetRubyVersion}): with none
 *     declared it parsed as Ruby 2.7, and a valid endless method
 *     (`def double(x) = x * 2`) and `it` were each a `Lint/Syntax` — and the
 *     project's own `.ruby-version` is not found from dev-guardian's
 *     configuration file. The version the project declares (`.ruby-version`,
 *     `.tool-versions`, `Gemfile.lock`, a `ruby '…'` line of its `Gemfile`,
 *     each read as text, never run), else the Ruby that runs RuboCop.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { findFileOnPath } from '../platform/binaryPath.js';
import { readProjectTextOrUndefined } from '../platform/projectFs.js';
import { ensureUserBinOnPath } from '../platform/userBin.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { PartialParse, ToolRun } from '../types.js';
import { batchArgs } from './argBatches.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson, toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

/** The `tools_run` name of the RuboCop pass, and the missing-tools name of the Ruby runtime it runs on. */
const RUBOCOP = 'rubocop';
const RUBY_RUNTIME = 'ruby';

/** The departments run (see the module comment). */
const RUBOCOP_DEPARTMENTS = 'Lint,Security,Metrics,Naming';

/** dev-guardian's configuration, the only one RuboCop reads, parsing for `target` (`3.4`) when one is known. */
export function rubocopConfig(target: string | null): string {
  return [
    'AllCops:',
    '  NewCops: disable',
    '  SuggestExtensions: false',
    ...(target !== null ? [`  TargetRubyVersion: ${target}`] : []),
    'Metrics/BlockLength:',
    '  AllowedMethods:',
    ...[
      'describe', 'context', 'shared_examples', 'shared_examples_for', 'shared_context', 'feature', 'scenario', 'it',
      'specify', 'let', 'before', 'after', 'around', 'refine', 'namespace', 'task', 'configure', 'draw', 'included',
      'class_methods', 'factory', 'define',
    ].map((m) => `    - ${m}`),
    '',
  ].join('\n');
}

/** `3.4.1`, `ruby-3.3.0`, `ruby 3.2.2p53` → `3.4`, `3.3`, `3.2`; null for anything else (JRuby, a range). */
function majorMinor(text: string | undefined): string | null {
  const m = /^(?:ruby-?\s*)?(\d+)\.(\d+)/.exec((text ?? '').trim());
  return m === null || Number(m[1]) < 2 ? null : `${m[1] ?? ''}.${m[2] ?? ''}`;
}

/**
 * The Ruby version the project declares, read as text (see the module
 * comment), and which file said so; null when none does.
 */
export function declaredRubyVersion(projectPath: string): { version: string; from: string } | null {
  const read = (file: string): string | undefined => readProjectTextOrUndefined(projectPath, file, 64 * 1024);
  const own = majorMinor(read('.ruby-version')?.split(/\s/)[0]);
  if (own !== null) return { version: own, from: '.ruby-version' };
  const tools = /^ruby\s+(\S+)/m.exec(read('.tool-versions') ?? '');
  const fromTools = majorMinor(tools?.[1]);
  if (fromTools !== null) return { version: fromTools, from: '.tool-versions' };
  const lock = /^RUBY VERSION\s*\n\s+(ruby \S+)/m.exec(read('Gemfile.lock') ?? '');
  const fromLock = majorMinor(lock?.[1]);
  if (fromLock !== null) return { version: fromLock, from: 'Gemfile.lock' };
  const gemfile = /^\s*ruby\s+['"]([^'"]+)['"]/m.exec(read('Gemfile') ?? '');
  const fromGemfile = majorMinor(gemfile?.[1]);
  return fromGemfile !== null ? { version: fromGemfile, from: 'Gemfile' } : null;
}

/** Ruby's variables that load code before RuboCop does (see the module comment). */
const LOADS_CODE = ['RUBYOPT', 'RUBYGEMS_GEMDEPS', 'BUNDLE_GEMFILE'];

/** Files Ruby is written in, by name. */
const RUBY_FILE_NAMES = new Set(['Gemfile', 'Rakefile', 'Guardfile', 'Capfile', 'Vagrantfile']);

/** The project's Ruby among `files` (project-relative): `.rb`, `.rake`, `.gemspec`, `.ru`, and `Gemfile`, `Rakefile` and their kin. */
export function rubySources(files: readonly string[]): string[] {
  return files
    .map(toPosixPath)
    .filter((f) => /\.(rb|rake|gemspec|ru)$/i.test(f) || RUBY_FILE_NAMES.has(f.slice(f.lastIndexOf('/') + 1)))
    .sort();
}

/** The gem's `rubocop` script on the PATH, the per-user tools directory included; null when there is none. */
export function findRubocop(env: NodeJS.ProcessEnv = process.env): string | null {
  return findFileOnPath('rubocop', env);
}

/** `env` without {@link LOADS_CODE}, whatever their case. */
export function rubocopEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) if (!LOADS_CODE.includes(k.toUpperCase())) out[k] = v;
  return out;
}

/** A file of a script RuboCop could not parse. */
export const RUBOCOP_SYNTAX_ERROR = 'Syntax error';

interface RubocopBatch {
  ok: boolean;
  reason?: string;
  /** The report (stdout), when it parsed. */
  report?: string;
  partial: PartialParse[];
}

/** One batch's run, judged (see the module comment). */
export function judgeRubocop(run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>): RubocopBatch {
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return { ok: false, reason: `did not finish (${run.outcome})`, partial: [] };
  }
  if (run.exitCode !== 0 && run.exitCode !== 1) {
    const line = `${run.stderr}\n${run.stdout}`
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l !== '' && !l.startsWith('{'));
    return { ok: false, reason: `exit ${String(run.exitCode)}${line ? `: ${line.slice(0, 300)}` : ''}`, partial: [] };
  }
  const root = parseInputAsJson(run.stdout);
  if (getString(getProp(root, 'metadata'), 'rubocop_version') === undefined || !Array.isArray(getProp(root, 'files'))) {
    return { ok: false, reason: 'no readable report was written', partial: [] };
  }
  const partial: PartialParse[] = [];
  for (const file of asArray(getProp(root, 'files'))) {
    const path = getString(file, 'path');
    if (path === undefined) continue;
    for (const o of asArray(getProp(file, 'offenses'))) {
      if (getString(o, 'cop_name') !== 'Lint/Syntax') continue;
      if (!partial.some((p) => p.file === path)) {
        partial.push({ file: path, type: RUBOCOP_SYNTAX_ERROR, message: getString(o, 'message') ?? 'could not parse' });
      }
    }
  }
  return { ok: true, report: run.stdout, partial };
}

interface RubocopPass {
  toolRun: ToolRun | null;
  missing: string[];
  reports: string[];
  cancelled: boolean;
}

/**
 * RuboCop over the Ruby among `files` (project-relative), one run per
 * command-line batch. No entry when there is none; `skipped` when RuboCop or
 * Ruby is not there; `ok` with the files it could not parse named
 * (`partially_parsed`, and missing), or `failed` with the batch's reason.
 */
export async function rubocopFiles(args: {
  projectPath: string;
  files: readonly string[];
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<RubocopPass> {
  const sources = rubySources(args.files);
  if (sources.length === 0) return { toolRun: null, missing: [], reports: [], cancelled: false };
  ensureUserBinOnPath();
  const skipped = (reason: string, missing: string): RubocopPass => ({
    toolRun: { name: RUBOCOP, status: 'skipped', reason },
    missing: [missing],
    reports: [],
    cancelled: false,
  });
  if (!(await scannerAvailable(RUBY_RUNTIME))) return skipped('ruby is not installed: RuboCop runs on Ruby 2.7 or newer', RUBY_RUNTIME);
  const script = findRubocop();
  if (script === null) return skipped('not_installed', RUBOCOP);
  // The Ruby to parse for: the project's, else the one that runs RuboCop (see the module comment).
  const declared = declaredRubyVersion(args.projectPath);
  const running =
    declared === null
      ? majorMinor(
          (
            await runProcess({ command: 'ruby', args: ['-e', 'print RUBY_VERSION'], cwd: args.reportDir, env: rubocopEnv({ ...process.env, ...args.env }), extendEnv: false, signal: args.signal, timeoutMs: 60_000 })
          ).stdout,
        )
      : null;
  const target = declared?.version ?? running;
  // A `*` is a pattern to RuboCop, whatever `--` (see the module comment): never handed over.
  if (args.projectPath.includes('*')) {
    return {
      toolRun: { name: RUBOCOP, status: 'failed', reason: "the project's path holds a `*`, which RuboCop reads as a file pattern: move the project" },
      missing: [],
      reports: [],
      cancelled: false,
    };
  }
  const handed = sources.filter((f) => !f.includes('*'));
  const notRead: PartialParse[] = sources
    .filter((f) => f.includes('*'))
    .map((file) => ({ file, type: 'Not read', message: 'a `*` in its path: RuboCop would read it as a file pattern, outside the project too' }));
  const config = join(args.reportDir, 'rubocop.yml');
  writeFileSync(config, rubocopConfig(target), 'utf8');
  const fixed = [script, '--config', config, '--format', 'json', '--only', RUBOCOP_DEPARTMENTS, '--'];
  const batches =
    handed.length === 0 ? [] : batchArgs(handed.map((f) => join(args.projectPath, ...f.split('/'))), { command: RUBY_RUNTIME, fixedArgs: fixed });
  // The whole environment, those variables left out — merged over the server's, they would come back.
  const env = rubocopEnv({ ...process.env, ...args.env });
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
      command: 'ruby',
      args: [...fixed, ...batch],
      // Never the project: a `.rubocop` there would be read as arguments (see the module comment).
      cwd: args.reportDir,
      env,
      extendEnv: false,
      signal: args.signal,
      ...(args.onLog ? { onLog: args.onLog } : {}),
      stdoutCapBytes: 50 * 1024 * 1024,
    });
    if (run.outcome === 'cancelled') cancelled = true;
    const judged = judgeRubocop(run);
    if (judged.report !== undefined) reports.push(judged.report);
    for (const p of judged.partial) {
      const file = toPosixPath(toRelativeIfPossible(p.file, args.projectPath));
      if (!partial.some((q) => q.file === file)) partial.push({ ...p, file });
    }
    if (!judged.ok) failures.push(`${batches.length > 1 ? `batch ${i + 1}/${batches.length}: ` : ''}${judged.reason ?? 'failed'}`);
    if (cancelled) break;
  }
  partial.push(...notRead);
  const described = `${handed.length} Ruby file(s)${batches.length > 1 ? ` in ${batches.length} batches` : ''}`;
  if (failures.length > 0 || cancelled) {
    return {
      toolRun: { name: RUBOCOP, status: 'failed', reason: cancelled && failures.length === 0 ? 'cancelled' : `${described}: ${failures.join('; ')}` },
      missing: [],
      reports,
      cancelled,
    };
  }
  const toolRun: ToolRun = {
    name: RUBOCOP,
    status: 'ok',
    reason:
      `${described} checked (${RUBOCOP_DEPARTMENTS}; parsed as Ruby ${target ?? "RuboCop's default"}` +
      `${declared !== null ? `, as ${declared.from} says` : target !== null ? ', the Ruby that ran it' : ''}; ` +
      "the project's .rubocop.yml is never read: its require and plugins run code)",
  };
  if (partial.length > 0) {
    const shown = partial.slice(0, 5).map((p) => `${p.type}: ${p.file}`).join('; ');
    toolRun.reason += `; partial: ${partial.length} file(s) RuboCop did not check whole (${shown}${partial.length > 5 ? '; …' : ''})`;
    toolRun.partially_parsed = partial;
  }
  return { toolRun, missing: partial.length > 0 ? [RUBOCOP] : [], reports, cancelled };
}
