/**
 * Psalm's taint analysis over a project's PHP — `scan_sast` and
 * `scan_wordpress`. Measured on Psalm 6.20.1 (its release PHAR) with PHP 8.2
 * to 8.5 on Linux and 8.4.4 on Windows, 2026-10-24; what decides every
 * argument below:
 *
 *   - The configuration is dev-guardian's, written for the run, never the
 *     project's `psalm.xml` (its issue handlers could switch a taint type
 *     off): the files to analyse listed one by one (`.guardianignore`
 *     applied, `.php`, `.phtml` and `.inc` — Psalm skips the last two
 *     otherwise), `vendor/` and `node_modules/` left out (named: a call into
 *     them ends a flow, as one into any code Psalm cannot see), `pdo` and
 *     `mysqli` enabled (without them `PDO::query` is no sink), and every
 *     function and constant global (`allFunctionsGlobal`: one defined behind
 *     an include Psalm cannot resolve is unknown otherwise, and ends a flow).
 *   - `--root` is an empty directory of dev-guardian's own: Psalm runs
 *     `<root>/vendor/autoload.php` and `dirname(<root>, 2)/autoload.php` —
 *     with the project as its root, the PROJECT's autoloader would run.
 *   - The exit code is not trusted (0 with findings when `GITHUB_WORKFLOW` is
 *     set, 0 for no file): the JSON report is read, and it must hold as many
 *     issues as the per-type counts stdout prints (`--output-format=count`).
 *     Any exit code but 0 and 2, a report missing or not a JSON array, or
 *     counts that disagree, is a failure — never a clean run.
 *   - A file Psalm cannot parse is NOT reported in taint mode: the flows after
 *     the error are lost without a word. scan_sast's Semgrep pass reads the
 *     same files and names each one it could not parse; that is the gap.
 *   - One file can hang Psalm (a 1.5 MB array literal took over five minutes
 *     and never finished): {@link PSALM_TIMEOUT_MS} ends the run, a failure.
 *   - WordPress: `configs/psalm/wordpress-taint.phpstub` makes `$wpdb`'s
 *     query methods SQL sinks and declares WordPress's escapes; without it
 *     `$wpdb` is no sink at all and WordPress functions end every flow.
 *   - The project's own `@psalm-taint-escape` annotations are honoured, as
 *     inline suppressions are; `@psalm-suppress` does not hide a taint issue.
 *   - Psalm needs PHP 8.2 or newer (its PHAR refuses 8.1): checked first, and
 *     a missing or older PHP is a named gap (`php`). It is never told
 *     `--shepherd` (that uploads statistics) and opens no socket (traced).
 *   - Windows, and a PHP without pcntl, run it on one thread: WooCommerce
 *     (3 144 files) took 19 minutes on one, 3 on eight.
 */

import { availableParallelism, tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { findFileOnPath } from '../platform/binaryPath.js';
import { presentInProject } from '../platform/projectFs.js';
import { resolveConfigsDir } from '../platform/configsDir.js';
import { ensureUserBinOnPath } from '../platform/userBin.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { ToolRun } from '../types.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { toPosixPath } from './scannerParsers/index.js';

/** The `tools_run` name of the Psalm pass, and the missing-tools name of the PHP runtime it needs. */
export const PSALM = 'psalm';
const PHP_RUNTIME = 'php';

/** The oldest Psalm and PHP this pass runs (see the module comment). */
const PSALM_MIN_MAJOR = 6;
export const PHP_MIN_VERSION: readonly [number, number] = [8, 2];

/** How long one run may take: WooCommerce on one thread took 19 minutes. */
const PSALM_TIMEOUT_MS = 40 * 60_000;

/** What Psalm analyses as PHP. */
const PHP_SOURCE = /\.(php|phtml|inc)$/i;
/** Dependencies, never analysed: a path with one of these directories. */
const DEPENDENCY_DIR = /(^|\/)(vendor|node_modules)\//;

/** The project's own PHP sources among `files` (project-relative): never a dependency's, whatever the listing holds. */
export function phpSources(files: readonly string[]): string[] {
  return files
    .map(toPosixPath)
    .filter((f) => PHP_SOURCE.test(f) && !DEPENDENCY_DIR.test(f))
    .sort();
}

/** Whether `files` hold a `.php` or `.phtml` file outside `vendor/` — what makes Psalm run (an `.inc` alone may be C's). */
export function hasPhpSource(files: readonly string[]): boolean {
  return phpSources(files).some((f) => /\.(php|phtml)$/i.test(f));
}

/** `configs/psalm/wordpress-taint.phpstub`, the plugin's own. */
function wordpressTaintStub(): string {
  return join(resolveConfigsDir(), 'psalm', 'wordpress-taint.phpstub');
}

function xmlAttr(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/** The configuration Psalm is run with: `files` absolute, the WordPress stub when given. */
export function psalmConfigXml(files: readonly string[], wordpressStub: string | null): string {
  return [
    '<?xml version="1.0"?>',
    '<psalm errorLevel="1" findUnusedCode="false" findUnusedBaselineEntry="false" allFunctionsGlobal="true" allConstantsGlobal="true"',
    '       xmlns="https://getpsalm.org/schema/config">',
    '    <projectFiles>',
    ...files.map((f) => `        <file name="${xmlAttr(f)}" />`),
    '    </projectFiles>',
    '    <fileExtensions><extension name=".php" /><extension name=".phtml" /><extension name=".inc" /></fileExtensions>',
    '    <enableExtensions><extension name="pdo" /><extension name="mysqli" /></enableExtensions>',
    ...(wordpressStub !== null
      ? [`    <stubs><file name="${xmlAttr(wordpressStub)}" /></stubs>`, '    <globals><var name="wpdb" type="\\wpdb" /></globals>']
      : []),
    '</psalm>',
    '',
  ].join('\n');
}

/** `PHP 8.4.4` / `8.4.4` → `[8, 4]`; `Psalm 6.20.1@…` → `[6, 20]`; null when no version is there. */
export function versionOf(output: string, prefix: 'php' | 'psalm'): [number, number] | null {
  const m = (prefix === 'psalm' ? /Psalm\s+v?(\d+)\.(\d+)/i : /^\s*(?:PHP\s+)?(\d+)\.(\d+)/im).exec(output);
  return m === null ? null : [Number(m[1]), Number(m[2])];
}

/** `Psalm 6.20.1@376425b8…` → `6.20.1`, the version `tools_run` records; null when none is there. */
export function psalmRelease(output: string): string | null {
  return /Psalm\s+v?(\d+\.\d+(?:\.\d+)?)/i.exec(output)?.[1] ?? null;
}

/** The total of `--output-format=count`'s `TaintedSql: 3` lines; null when a line is something else. */
export function countedIssues(stdout: string): number | null {
  let total = 0;
  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim() === '') continue;
    const m = /^\s*(\w+):\s*(\d+)\s*$/.exec(line);
    if (m === null) return null;
    total += Number(m[2]);
  }
  return total;
}

interface PsalmJudgement {
  ok: boolean;
  reason?: string;
  /** The issues, when the report is sound. */
  issues: unknown[];
}

/** One run, judged (see the module comment). */
export function judgePsalm(args: { run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>; report: string | null }): PsalmJudgement {
  const { run } = args;
  const fail = (reason: string): PsalmJudgement => ({ ok: false, reason, issues: [] });
  if (run.outcome === 'timed_out') return fail(`did not finish in ${PSALM_TIMEOUT_MS / 60_000} minutes (a file that makes Psalm hang: list it in .guardianignore after review)`);
  if (run.outcome === 'cancelled' || run.outcome === 'output_too_large') return fail(`did not finish (${run.outcome})`);
  // `failed` is also how runProcess says "exited non-zero": Psalm's 2 is "issues found".
  if (run.exitCode === null) return fail(`did not run${run.stderr.trim() !== '' ? `: ${run.stderr.trim().split(/\r?\n/)[0] ?? ''}` : ''}`);
  if (run.exitCode !== 0 && run.exitCode !== 2) {
    // A PHP fatal error (memory, a missing extension) and Psalm's own crash both print one line that says why.
    const said = `${run.stderr}\n${run.stdout}`.split(/\r?\n/).map((l) => l.trim()).find((l) => l !== '');
    return fail(`exit ${String(run.exitCode)}${said ? `: ${said.slice(0, 300)}` : ''}`);
  }
  if (args.report === null) return fail('Psalm wrote no report');
  let issues: unknown;
  try {
    issues = JSON.parse(args.report);
  } catch {
    return fail('the report is not JSON (the run was cut short)');
  }
  if (!Array.isArray(issues)) return fail('the report is not a list of issues');
  const counted = countedIssues(run.stdout);
  if (counted === null || counted !== issues.length) {
    return fail(`the report holds ${issues.length} issue(s) and Psalm counted ${counted === null ? 'something else' : String(counted)}`);
  }
  return { ok: true, issues };
}

interface PsalmPass {
  toolRun: ToolRun | null;
  missing: string[];
  /** The JSON report, when it holds an issue. */
  report: string | null;
  cancelled: boolean;
}

const atLeast = (v: [number, number], min: readonly [number, number]): boolean => v[0] > min[0] || (v[0] === min[0] && v[1] >= min[1]);

/** The Psalm to run: the release PHAR, else a `psalm` launcher (Composer's, a distribution's) — each run by `php`. */
export function findPsalm(env: NodeJS.ProcessEnv = process.env): string | null {
  return findFileOnPath('psalm.phar', env) ?? findFileOnPath('psalm', env);
}

/**
 * Psalm's taint analysis over the PHP among `files` (project-relative):
 * every one of them, whatever a scope holds — a flow crosses files, and the
 * caller keeps the findings inside its scope. No entry when there is no PHP
 * outside `vendor/`; `skipped` when Psalm, or PHP 8.2+, is not there; `ok`,
 * or `failed` with the reason.
 */
export async function psalmTaint(args: {
  projectPath: string;
  files: readonly string[];
  wordpress: boolean;
  scopeFiles?: number;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<PsalmPass> {
  const analysed = phpSources(args.files);
  if (!hasPhpSource(analysed)) return { toolRun: null, missing: [], report: null, cancelled: false };
  ensureUserBinOnPath();
  const skipped = (reason: string, missing: string): PsalmPass => ({
    toolRun: { name: PSALM, status: 'skipped', reason },
    missing: [missing],
    report: null,
    cancelled: false,
  });
  const psalm = findPsalm();
  if (psalm === null) return skipped('not_installed', PSALM);
  if (!(await scannerAvailable(PHP_RUNTIME))) {
    return skipped(`php is not installed: Psalm runs on PHP ${PHP_MIN_VERSION.join('.')} or newer`, PHP_RUNTIME);
  }
  const probe = (probeArgs: string[]) =>
    runProcess({ command: 'php', args: probeArgs, cwd: args.reportDir, env: args.env, signal: args.signal, timeoutMs: 60_000 });
  const php = versionOf((await probe(['-r', 'echo PHP_VERSION;'])).stdout, 'php');
  if (php === null || !atLeast(php, PHP_MIN_VERSION)) {
    const found = php === null ? 'its version could not be read' : `it is ${php.join('.')}`;
    return skipped(`Psalm needs PHP ${PHP_MIN_VERSION.join('.')} or newer and ${found}`, PHP_RUNTIME);
  }
  const versionRun = await probe([psalm, '--version']);
  const versionOutput = `${versionRun.stdout}\n${versionRun.stderr}`;
  const version = versionOf(versionOutput, 'psalm');
  if (version === null || version[0] < PSALM_MIN_MAJOR) {
    const found = version === null ? `its version could not be read (${psalm})` : `it is ${version.join('.')}`;
    return skipped(`Psalm ${PSALM_MIN_MAJOR} or newer is needed and ${found}`, PSALM);
  }

  // dev-guardian's own directory: the configuration, and the empty root Psalm loads autoloaders from.
  const work = mkdtempSync(join(tmpdir(), 'guardian-psalm-'));
  try {
    const root = join(work, 'a', 'root');
    mkdirSync(root, { recursive: true });
    const config = join(work, 'psalm.xml');
    const stub = args.wordpress ? wordpressTaintStub() : null;
    writeFileSync(config, psalmConfigXml(analysed.map((f) => join(args.projectPath, ...f.split('/'))), stub), 'utf8');
    const out = join(args.reportDir, 'psalm.json');
    rmSync(out, { force: true });
    const run = await runProcess({
      command: 'php',
      args: [
        psalm,
        `--config=${config}`,
        `--root=${root}`,
        '--no-cache',
        `--threads=${String(Math.max(1, Math.min(availableParallelism(), 8)))}`,
        '--taint-analysis',
        '--output-format=count',
        `--report=${out}`,
        '--no-progress',
      ],
      cwd: root,
      env: args.env,
      signal: args.signal,
      ...(args.onLog ? { onLog: args.onLog } : {}),
      timeoutMs: PSALM_TIMEOUT_MS,
    });
    let report: string | null = null;
    try {
      report = readFileSync(out, 'utf8');
    } catch {
      report = null;
    }
    const judged = judgePsalm({ run, report });
    const cancelled = run.outcome === 'cancelled';
    const versionText = psalmRelease(versionOutput) ?? version.join('.');
    if (!judged.ok) {
      return { toolRun: { name: PSALM, version: versionText, status: 'failed', reason: judged.reason ?? 'Psalm failed' }, missing: [], report: null, cancelled };
    }
    const reason = [
      `${analysed.length} PHP file(s) analysed for taint${
        args.scopeFiles !== undefined
          ? ` — the whole project's, for a scope of ${args.scopeFiles} file(s), since a flow crosses files; only the scope's findings are kept`
          : ''
      }`,
      ...(presentInProject(args.projectPath, 'vendor') ? ['vendor/ not analysed: a call into it ends a flow'] : []),
      ...(stub !== null ? ["WordPress's APIs modelled ($wpdb's queries as SQL sinks, its escapes)"] : []),
      `PHP ${php.join('.')}`,
    ].join('; ');
    return {
      toolRun: { name: PSALM, version: versionText, status: 'ok', reason },
      missing: [],
      report: judged.issues.length > 0 ? report : null,
      cancelled,
    };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
