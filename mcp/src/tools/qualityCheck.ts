/**
 * `quality_check` — code-quality scan: duplication, complexity, smells, naming.
 *
 *   - jscpd (every language) — duplication;
 *   - ruff + radon (`cc`) when the project has any `.py` file;
 *   - ESLint when the project configures it AND has it installed in
 *     `node_modules` — run with this Node, never through `npx`, which
 *     downloads ESLint from the network into a project that has none;
 *   - staticcheck when there is a `go.mod`.
 *
 * It used to run `scripts/scan/quality-scan.sh`, which lost ruff and radon to
 * `find | head -1` under `pipefail` on large Python trees, captured ESLint /
 * radon / staticcheck output and never parsed it, never read `categories`,
 * and ran `npx eslint`. Every applicable analyser is now either `ok`,
 * `failed` with a reason, or `skipped` with a reason and listed in
 * `missing_tools` — a quality scan that did not run an analyser is never
 * reported as full coverage.
 *
 * `categories` filters the RESPONSE only, like `bug_hunt`'s: every finding is
 * recorded, so a baseline or diff against this scan is never missing the
 * categories one call happened not to ask for. Each finding's category comes
 * from its analyser (`subcategory` for jscpd / radon / ESLint / staticcheck,
 * the rule code for ruff: C90 complexity, N naming).
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { hasFileWithExtension } from '../runners/projectFiles.js';
import { eslintFatalErrors, eslintParser } from '../runners/scannerParsers/eslint.js';
import { parseInputAsJson, type ScannerParser } from '../runners/scannerParsers/index.js';
import { jscpdParser } from '../runners/scannerParsers/jscpd.js';
import { radonErrors, radonParser } from '../runners/scannerParsers/radon.js';
import { ruffParser } from '../runners/scannerParsers/ruff.js';
import { staticcheckErrors, staticcheckParser } from '../runners/scannerParsers/staticcheck.js';
import { Force, ProjectPath } from '../schemas.js';
import type { Finding, ToolRun } from '../types.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';
import {
  makeScanTool,
  type InvokeContext,
  type ResponseView,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

export const QUALITY_CATEGORIES = ['duplicate', 'complexity', 'smell', 'naming'] as const;
export type QualityCategory = (typeof QUALITY_CATEGORIES)[number];

type QualityInput = ScanToolBaseInput & { categories?: QualityCategory[] };

const ESLINT_CONFIGS = [
  'eslint.config.js',
  'eslint.config.mjs',
  'eslint.config.cjs',
  'eslint.config.ts',
  'eslint.config.mts',
  'eslint.config.cts',
  '.eslintrc',
  '.eslintrc.js',
  '.eslintrc.cjs',
  '.eslintrc.json',
  '.eslintrc.yaml',
  '.eslintrc.yml',
];

/** Kept out of jscpd and radon, as they are out of every other walk of the project. */
const IGNORED_DIRS = ['node_modules', '.git', '.guardian', 'vendor', 'dist', 'build', 'venv', '.venv', '__pycache__'];

interface Collected {
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: Array<{ parser: ScannerParser; input: unknown }>;
  cancelled: boolean;
}

registerToolModule(
  makeScanTool<QualityInput>({
    name: 'quality_check',
    title: 'Code quality scan',
    description:
      'Code-quality scan: jscpd (duplication, any language); ruff and radon cyclomatic complexity when ' +
      'the project has .py files; ESLint when it is configured and installed in node_modules (never via ' +
      'npx); staticcheck when there is a go.mod. Findings are classified duplicate / complexity / smell / ' +
      'naming; `categories` narrows the response to those classes while every finding is still recorded ' +
      '(`category_filter` counts what was withheld). An applicable analyser that is missing or fails is ' +
      'reported as such and coverage is partial, never full.',
    scan_type: 'quality',
    category: 'quality',
    supportsAutoFix: false,
    responseOnlyInputs: ['categories'],
    responseView: (input, findings, scanId) => qualityCategoriesView(input.categories, findings, scanId),
    inputSchema: {
      project_path: ProjectPath,
      categories: z
        .array(z.enum(QUALITY_CATEGORIES))
        .optional()
        .describe(
          'Show only these quality classes in the response. Every finding is still recorded; ' +
            '`category_filter` counts what was withheld.',
        ),
      force: Force,
    },
    invoke: async (_input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'quality');
      const out: Collected = { tools_run: [], missing_tools: [], parser_inputs: [], cancelled: false };

      await runJscpd(ctx, reportDir, out);
      if (!out.cancelled && hasFileWithExtension(ctx.projectPath, ['.py'])) {
        await runRuff(ctx, reportDir, out);
        if (!out.cancelled) await runRadon(ctx, reportDir, out);
      }
      if (!out.cancelled && hasEslintConfig(ctx.projectPath)) await runEslint(ctx, reportDir, out);
      if (!out.cancelled && existsSync(join(ctx.projectPath, 'go.mod'))) await runStaticcheck(ctx, out);

      return {
        outcome: out.cancelled ? 'cancelled' : 'completed',
        tools_run: out.tools_run,
        missing_tools: out.missing_tools,
        parser_inputs: out.parser_inputs,
        report_paths: [reportDir],
      };
    },
  }),
);

/** The analyser is not on PATH: a named gap, never silence. */
function notInstalled(out: Collected, name: string, reason = 'not_installed'): void {
  out.tools_run.push({ name, status: 'skipped', reason });
  out.missing_tools.push(name);
}

/** Record one analyser run: `ok` with its report parsed, or `failed` with why. */
function record(
  out: Collected,
  name: string,
  run: ProcessRunResult,
  okExitCodes: readonly number[],
  report: string | null,
  reportOk: (parsed: unknown) => boolean,
  parser: ScannerParser,
  /**
   * Files the analyser could not analyse. The run is `ok` but its name goes
   * in `missing_tools` — "ran with reduced coverage" (scanCoverage.ts) —
   * because those files were not checked.
   */
  gaps: readonly string[] = [],
): void {
  if (run.outcome === 'cancelled') out.cancelled = true;
  const problems: string[] = [];
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    problems.push(`did not finish (${run.outcome})`);
  } else if (run.exitCode === null || !okExitCodes.includes(run.exitCode)) {
    problems.push(`exit ${String(run.exitCode)}${firstLine(run.stderr) ? `: ${firstLine(run.stderr)}` : ''}`);
  }
  if (problems.length === 0 && (report === null || !reportOk(parseInputAsJson(report)))) {
    problems.push('no readable report was written');
  }
  if (problems.length > 0) {
    out.tools_run.push({ name, status: 'failed', reason: problems.join('; ') });
    return;
  }
  out.parser_inputs.push({ parser, input: report });
  const entry: ToolRun = { name, status: 'ok' };
  if (gaps.length > 0) {
    entry.reason = gaps.join('; ');
    out.missing_tools.push(name);
  }
  out.tools_run.push(entry);
}

async function runJscpd(ctx: InvokeContext, reportDir: string, out: Collected): Promise<void> {
  if (!(await scannerAvailable('jscpd'))) return notInstalled(out, 'jscpd');
  const dupDir = join(reportDir, 'dup');
  const run = await runProcess({
    command: 'jscpd',
    args: [
      '--reporters',
      'json',
      '--output',
      dupDir,
      '--silent',
      '--ignore',
      IGNORED_DIRS.map((d) => `**/${d}/**`).join(','),
      '.',
    ],
    cwd: ctx.projectPath,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  // 1 = the duplication threshold was exceeded, which is a result.
  record(out, 'jscpd', run, [0, 1], readJsonSafe(join(dupDir, 'jscpd-report.json')), isObject, jscpdParser);
}

async function runRuff(ctx: InvokeContext, reportDir: string, out: Collected): Promise<void> {
  if (!(await scannerAvailable('ruff'))) return notInstalled(out, 'ruff');
  const file = join(reportDir, 'ruff.json');
  const run = await runProcess({
    command: 'ruff',
    // --exit-zero: findings are exit 0, so any other exit is ruff failing.
    args: ['check', '--output-format', 'json', '--exit-zero', '--output-file', file, '.'],
    cwd: ctx.projectPath,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  record(out, 'ruff', run, [0], readJsonSafe(file), Array.isArray, ruffParser);
}

async function runRadon(ctx: InvokeContext, reportDir: string, out: Collected): Promise<void> {
  if (!(await scannerAvailable('radon'))) return notInstalled(out, 'radon');
  const file = join(reportDir, 'radon-cc.json');
  const run = await runProcess({
    command: 'radon',
    args: ['cc', '-j', '-O', file, '-i', ['.*', ...IGNORED_DIRS].join(','), '.'],
    cwd: ctx.projectPath,
    env: { ...ctx.scriptEnv, PYTHONUTF8: '1' },
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  const report = readJsonSafe(file);
  const errors = report === null ? [] : radonErrors(report);
  record(out, 'radon', run, [0], report, isObject, radonParser, couldNotAnalyse(errors));
}

async function runEslint(ctx: InvokeContext, reportDir: string, out: Collected): Promise<void> {
  const eslint = localEslint(ctx.projectPath);
  if (eslint === null) {
    return notInstalled(
      out,
      'eslint',
      'ESLint is configured but not installed in node_modules — run your package manager install first. ' +
        'npx is never used: it would download ESLint from the network.',
    );
  }
  const file = join(reportDir, 'eslint.json');
  const run = await runProcess({
    command: process.execPath,
    args: [eslint, '--format', 'json', '--output-file', file, '.'],
    cwd: ctx.projectPath,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  const report = readJsonSafe(file);
  const fatal = report === null ? [] : eslintFatalErrors(report);
  // 0 = clean, 1 = lint errors; 2 = ESLint itself failed (config, crash).
  record(out, 'eslint', run, [0, 1], report, Array.isArray, eslintParser, couldNotAnalyse(fatal));
}

async function runStaticcheck(ctx: InvokeContext, out: Collected): Promise<void> {
  if (!(await scannerAvailable('staticcheck'))) return notInstalled(out, 'staticcheck');
  const run = await runProcess({
    command: 'staticcheck',
    args: ['-f', 'json', './...'],
    cwd: ctx.projectPath,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
    stdoutCapBytes: 50 * 1024 * 1024,
  });
  // JSON lines on stdout; exit 1 = problems found — and ALSO every fatal
  // error (go not on PATH, a pattern that matches no package), which prints
  // no JSON at all. So exit 1 counts only with JSON behind it, and a run whose
  // only output is `compile` entries analysed nothing.
  const entries = run.stdout.split(/\r?\n/).filter((l) => l.trim().startsWith('{')).length;
  const errors = staticcheckErrors(run.stdout);
  const finished = run.outcome !== 'cancelled' && run.outcome !== 'timed_out' && run.outcome !== 'output_too_large';
  if (finished && run.exitCode !== 0 && entries === 0) {
    const detail = firstLine(run.stderr);
    out.tools_run.push({
      name: 'staticcheck',
      status: 'failed',
      reason: `exit ${String(run.exitCode)} with no results${detail ? `: ${detail}` : ''}`,
    });
    return;
  }
  if (finished && entries > 0 && errors.length === entries) {
    out.tools_run.push({
      name: 'staticcheck',
      status: 'failed',
      reason: `no package could be analysed: ${errors.slice(0, 5).join('; ')}${errors.length > 5 ? '; …' : ''}`,
    });
    return;
  }
  record(out, 'staticcheck', run, [0, 1], run.stdout, () => true, staticcheckParser, couldNotAnalyse(errors));
}

function couldNotAnalyse(errors: readonly string[]): string[] {
  if (errors.length === 0) return [];
  const shown = errors.slice(0, 5).join('; ');
  return [`${errors.length} file(s) could not be analysed: ${shown}${errors.length > 5 ? '; …' : ''}`];
}

function hasEslintConfig(projectPath: string): boolean {
  if (ESLINT_CONFIGS.some((name) => existsSync(join(projectPath, name)))) return true;
  try {
    const pkg = parseInputAsJson(readFileSync(join(projectPath, 'package.json'), 'utf8'));
    return typeof pkg === 'object' && pkg !== null && 'eslintConfig' in pkg;
  } catch {
    return false;
  }
}

/**
 * `node_modules/eslint/bin/eslint.js` in the project or an ancestor (a
 * workspace root), stopping at the repository root — the ESLint Node itself
 * would resolve. Null when there is none: then ESLint is not installed and is
 * not fetched.
 */
function localEslint(projectPath: string): string | null {
  for (let dir = projectPath; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', 'eslint', 'bin', 'eslint.js');
    if (existsSync(candidate)) return candidate;
    if (existsSync(join(dir, '.git')) || dirname(dir) === dir) return null;
  }
}

function isObject(value: unknown): boolean {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function firstLine(text: string): string {
  return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}

/** The `quality_check` class of a finding. */
export function qualityCategoryOf(f: Finding): QualityCategory {
  const sub = f.subcategory;
  if (sub === 'duplicate' || sub === 'complexity' || sub === 'smell' || sub === 'naming') return sub;
  if (f.tool === 'ruff') {
    const code = f.rule_id ?? '';
    if (/^C9\d/.test(code)) return 'complexity';
    if (/^N\d/.test(code)) return 'naming';
  }
  return 'smell';
}

/**
 * `categories` as a view over the stored findings — the ones outside the
 * requested classes are withheld from THIS response and counted, never
 * dropped from the scan. Null when no filter was asked for.
 */
export function qualityCategoriesView(
  categories: readonly QualityCategory[] | undefined,
  findings: readonly Finding[],
  scanId: string,
): ResponseView | null {
  if (categories === undefined || categories.length === 0) return null;
  const visible: Finding[] = [];
  const withheldByCategory: Record<string, number> = {};
  for (const f of findings) {
    const category = qualityCategoryOf(f);
    if (categories.includes(category)) visible.push(f);
    else withheldByCategory[category] = (withheldByCategory[category] ?? 0) + 1;
  }
  const withheld = findings.length - visible.length;
  return {
    visible,
    disclosure: {
      category_filter: { categories: [...categories], withheld, withheld_by_category: withheldByCategory },
    },
    warning:
      withheld === 0
        ? null
        : `categories ${JSON.stringify(categories)} withheld ${withheld} finding(s) from this response only; ` +
          `they are recorded in scan ${scanId}, and baselines and diffs against it include them.`,
  };
}
