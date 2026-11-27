/**
 * `perf_check` — performance probe via Lighthouse (URL) or k6 (script).
 *
 * Exactly one of `target_url` (Lighthouse) or `k6_script_path` (k6) must be
 * provided. The response carries a parsed summary plus the absolute path to
 * the raw JSON report.
 *
 * Lighthouse summary surfaces Core Web Vitals (LCP, CLS, INP/TBT, FCP, SI,
 * TTFB) plus the 5 high-level scores (performance, a11y, best-practices,
 * SEO, PWA). k6 summary surfaces request count, error rate, average and
 * p95 latency (p99 when the script's `summaryTrendStats` asks for it), plus
 * every threshold the script configures and the ones that failed.
 *
 * A Lighthouse run additionally reads `.guardian/budgets.yml` (when present)
 * and reports any Core Web Vital / bundle-size budget it exceeds as a
 * Finding in `findings` — see `budgets/budgets.ts`. Not run for k6: none of
 * LCP/INP/CLS/TBT/bundle-size describe a load test's own metrics.
 *
 * `budgets` on the response says what happened with the budgets file itself
 * — `'none'` (nothing configured), `'ok'` (evaluated; `violations` counts
 * this run's breaches, possibly 0), or `'invalid'` (broken YAML, an
 * unrecognised key, a non-numeric value — `reason` says which). This exists
 * so `findings: []` is never ambiguous between "within budget" and "the
 * budgets file is broken and nothing was actually checked" — an earlier
 * version of this tool collapsed both into an empty `findings` array, which
 * read a typo'd budget as "all clear".
 *
 * Lighthouse is handed `target_url` parsed and re-serialised (http or https
 * only), and k6 a script path with no `"` (`platform/toolArgs.ts`): on
 * Windows an npm-installed Lighthouse is `lighthouse.cmd`, and a `"` in the
 * URL closed the quotes `cmd.exe` wraps it in (review 10, finding 3).
 *
 * Every MEASURED run (3.17.0) is kept as a `perf` scan row — its numbers in
 * `meta`, no finding — and `history` on the response judges it against the
 * earlier runs of the same target (`metrics/perfSeries.ts`). A run that
 * measured nothing (a page Lighthouse could not load, a k6 script error)
 * writes no row; a history that cannot be read or written never fails the
 * measurement — `history.recorded` is false and says why.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { budgetViolationFindings, evaluatePerfBudgets, loadBudgets, type PerfBudgets } from '../budgets/budgets.js';
import { allowlistedEnv } from '../fixpr/testCommandEnv.js';
import {
  judgeSeries,
  k6Samples,
  k6Series,
  k6Settings,
  lighthouseSamples,
  lighthouseSeries,
  type PerfMetricHistory,
  type PerfSample,
  type PerfSeries,
  seriesHint,
  seriesRunOf,
} from '../metrics/perfSeries.js';
import { type K6InputReader, k6LocalInputs } from '../metrics/k6Inputs.js';
import { hashProjectFile, isWithinDir, PROJECT_FILE_MAX_BYTES, projectPathKind, readProjectBytes } from '../platform/projectFs.js';
import { DEFAULT_RETENTION_SCANS } from '../storage/maintenance.js';
import { runProcess } from '../runners/processRunner.js';
import { httpUrl, pathArgProblem } from '../platform/toolArgs.js';
import { httpUrlField, ProjectPath } from '../schemas.js';
import type { DomainError, Finding, ToolResult } from '../types.js';
import { ensureReportDir, scannerAvailable } from './scanHelpers.js';
import {
  getNumber,
  getProp,
  getString,
} from '../runners/scannerParsers/index.js';
import { defineTool, registerToolModule, type ToolInput } from './index.js';
import { toolProjectPath } from './projectArg.js';

const inputSchema = {
  project_path: ProjectPath,
  target_url: httpUrlField()
    .optional()
    .describe('URL to probe with Lighthouse. Mutually exclusive with k6_script_path.'),
  k6_script_path: z
    .string()
    .optional()
    .describe('Path to a k6 script to execute. Mutually exclusive with target_url.'),
  lighthouse_categories: z
    .array(z.enum(['performance', 'accessibility', 'best-practices', 'seo', 'pwa']))
    .optional()
    .describe('Categories to include. Default: all five.'),
};

const tool = defineTool({
  name: 'perf_check',
  title: 'Performance check (Lighthouse or k6)',
  description:
    'Run Lighthouse against target_url, or k6 against k6_script_path: Core Web Vitals, or request counts ' +
    "and p95/p99, and the raw report's path. Lighthouse runs are checked against .guardian/budgets.yml: " +
    'an exceeded budget is a finding, and `budgets.status` never reads an unmeasured metric as within ' +
    'budget. Sends real load to the URL.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
});

registerToolModule(tool);

async function handler(
  inp: ToolInput<typeof inputSchema>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {

  const projectPath = toolProjectPath(inp.project_path);
  if (typeof projectPath !== 'string') return projectPath;

  // Narrow the VALUES, not a boolean derived from them: `hasUrl` told the
  // reader the url was present but told the compiler nothing, which is why
  // both call sites below used to need a non-null assertion.
  const targetUrl =
    inp.target_url !== undefined && inp.target_url.length > 0 ? inp.target_url : undefined;
  const k6Script =
    inp.k6_script_path !== undefined && inp.k6_script_path.length > 0
      ? inp.k6_script_path
      : undefined;
  if ((targetUrl === undefined) === (k6Script === undefined)) {
    return failDomain(
      'scanner_failed',
      'Provide exactly one of target_url (Lighthouse) or k6_script_path (k6).',
    );
  }
  // What the program is handed, checked before anything runs (see the module comment).
  const lighthouseUrl = targetUrl === undefined ? undefined : httpUrl(targetUrl);
  if (lighthouseUrl === null) return failDomain('invalid_input', 'target_url must be an http:// or https:// URL.');
  const scriptProblem = k6Script === undefined ? null : pathArgProblem('k6_script_path', k6Script);
  if (scriptProblem !== null) return failDomain('invalid_input', `${scriptProblem}.`);

  const scanId = randomUUID();
  const reportDir = ensureReportDir(projectPath, scanId, 'perf');

  if (lighthouseUrl !== undefined) {
    return runLighthouse({
      url: lighthouseUrl,
      categories: inp.lighthouse_categories,
      reportDir,
      projectPath,
      scanId,
      ctx,
    });
  }
  if (k6Script === undefined) {
    return failDomain('scanner_failed', 'Provide exactly one of target_url or k6_script_path.');
  }
  return runK6({ scriptPath: k6Script, reportDir, projectPath, scanId, ctx });
}

/**
 * Chrome's flags for Lighthouse. `--no-sandbox` only where Chrome refuses to
 * start without it — as root, the usual case inside a container. It was on
 * every run since the first version (no reason recorded), and the page
 * Chrome renders is one the agent named: its sandbox is what contains a
 * renderer exploit there (review of 3.6, finding 15).
 */
function chromeFlags(): string {
  const root = typeof process.getuid === 'function' && process.getuid() === 0;
  return root ? '--headless=new --no-sandbox' : '--headless=new';
}

interface LighthouseOpts {
  url: string;
  categories?: string[];
  reportDir: string;
  projectPath: string;
  /** The run's id: its report directory's, and its history row's. */
  scanId: string;
  ctx: PluginContext;
}

async function runLighthouse(
  opts: LighthouseOpts,
): Promise<ToolResult<Record<string, unknown>>> {
  const bin = await scannerAvailable('lighthouse');
  if (!bin) {
    return failDomain(
      'missing_scanner',
      'Lighthouse CLI is not installed. Install with `npm i -g lighthouse`.',
    );
  }

  const outFile = join(opts.reportDir, 'lighthouse.json');
  const args: string[] = [
    opts.url,
    '--quiet',
    '--output=json',
    `--output-path=${outFile}`,
    `--chrome-flags=${chromeFlags()}`,
  ];
  if (opts.categories && opts.categories.length > 0) {
    args.push(`--only-categories=${opts.categories.join(',')}`);
  }

  const result = await runProcess({
    command: 'lighthouse',
    args,
    cwd: opts.projectPath,
    // Lighthouse fetches a real page; cap higher than the default 10 min.
    timeoutMs: 5 * 60_000,
  });
  if (!existsSync(outFile)) {
    return failDomain(
      'scanner_failed',
      `Lighthouse did not produce a report. stderr: ${result.stderr.split(/\r?\n/)[0] ?? ''}`,
    );
  }

  const raw = readFileSync(outFile, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return failDomain('scanner_failed', 'Lighthouse output was not valid JSON.');
  }

  // Review M5: a page Lighthouse could not load is reported in the report
  // itself (`runtimeError`), and the CLI exits 1 after saving it (cli/run.js:
  // "we'll still exit with an error code after we saved the results"); a
  // protocol timeout exits 67. Either way nothing was measured: its null
  // scores used to read as a run, and its budgets as "ok".
  const runtimeError = getProp(parsed, 'runtimeError');
  if (runtimeError !== undefined && runtimeError !== null) {
    const code = getString(runtimeError, 'code') ?? 'UNKNOWN';
    const message = getString(runtimeError, 'message') ?? '';
    return failDomain(
      'scanner_failed',
      `Lighthouse could not measure ${opts.url}: ${code}${message ? ` — ${message}` : ''} (report: ${outFile})`,
    );
  }
  if (result.exitCode !== 0) {
    const line = result.stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ?? result.outcome;
    return failDomain('scanner_failed', `Lighthouse exit ${String(result.exitCode)}: ${line} (report: ${outFile})`);
  }

  const summary = summariseLighthouse(parsed);
  const budgetResult = evaluateLighthouseBudgets(opts.projectPath, summary.core_web_vitals);
  const categories = getProp(parsed, 'categories');
  // The history samples CLS unrounded: its tolerance is 0.01, the summary's rounding step, so a
  // CLS of 0.1351 x3 then 0.1549 (+0.0198) read 0.14 -> 0.15, within.
  const cls = getNumber(getProp(getProp(parsed, 'audits'), 'cumulative-layout-shift'), 'numericValue');
  const sampled = { ...summary, core_web_vitals: { ...summary.core_web_vitals, 'cumulative-layout-shift': cls ?? null } };
  const history = recordPerfRun(opts.ctx, {
    projectPath: opts.projectPath,
    scanId: opts.scanId,
    reportDir: opts.reportDir,
    reportPath: outFile,
    tool: 'lighthouse',
    toolVersion: getString(parsed, 'lighthouseVersion'),
    series: lighthouseSeries(
      opts.url,
      getString(parsed, 'lighthouseVersion'),
      categories !== null && typeof categories === 'object' ? Object.keys(categories) : [],
    ),
    samples: lighthouseSamples(sampled),
  });
  return {
    ok: true,
    tool: 'lighthouse',
    url: opts.url,
    report_path: outFile,
    summary,
    findings: budgetResult.findings,
    budgets: budgetResult.budgets,
    ...(budgetResult.warnings.length > 0 ? { warnings: budgetResult.warnings } : {}),
    history,
  };
}

/** `history` on a measured run's response. */
interface PerfHistory {
  series: string;
  recorded: boolean;
  scan_id?: string;
  /** recorded false: why the run is not in the history. */
  reason?: string;
  metrics?: PerfMetricHistory[];
  regressed?: string[];
  improved?: string[];
  hint?: string;
}

/**
 * The series' runs a judgment reads, newest first, in one statement: retention's
 * default keep. Retention keeps N `perf` rows per project, shared by all its
 * targets (docs/env.md), so a series holds at most N. Not `GUARDIAN_RETENTION_SCANS`
 * itself: its `0` (keep everything) would make this an unbounded read, and a keep
 * below 3 would leave no series judgeable, not even within one server session
 * (retention prunes at the start). What that hides:
 * with N above 50, `since` is the oldest 3 of a series' 50 newest runs, not of
 * every run kept.
 */
const SERIES_READ = DEFAULT_RETENTION_SCANS;

interface PerfRunRecord {
  projectPath: string;
  scanId: string;
  reportDir: string;
  reportPath: string;
  tool: 'lighthouse' | 'k6';
  toolVersion: string | undefined;
  series: PerfSeries;
  samples: PerfSample[];
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Judges a measured run against its series and keeps it as a `perf` row.
 * Neither step may fail the measurement: a history that cannot be read is
 * said, and a run that cannot be written is said, with its judgment kept.
 */
function recordPerfRun(ctx: PluginContext, run: PerfRunRecord): PerfHistory {
  if (run.samples.length === 0) {
    return { series: run.series.label, recorded: false, reason: 'the run measured no metric, so it is not kept' };
  }
  let metrics: PerfMetricHistory[];
  try {
    const earlier = ctx.storage.scans
      .listCompletedPerfSeries(run.projectPath, run.series.key, SERIES_READ)
      .flatMap((row) => seriesRunOf(row) ?? []);
    metrics = judgeSeries(earlier, run.samples);
  } catch (e) {
    return { series: run.series.label, recorded: false, reason: `the history could not be read, so the run was neither judged nor kept: ${errorText(e)}` };
  }
  const judged = {
    metrics,
    regressed: metrics.filter((m) => m.verdict === 'regressed').map((m) => m.name),
    improved: metrics.filter((m) => m.verdict === 'improved').map((m) => m.name),
    hint: seriesHint(metrics),
  };
  try {
    ctx.storage.scans.insert({
      scan_id: run.scanId,
      scan_type: 'perf',
      project_path: run.projectPath,
      tree_hash: '',
      report_dir: run.reportDir,
    });
    ctx.storage.scans.finalize({
      scan_id: run.scanId,
      status: 'completed',
      // Literal names: runNames.ts places them (they report through meta, no finding).
      tools_run: [
        run.tool === 'k6'
          ? { name: 'k6', status: 'ok' }
          : { name: 'lighthouse', status: 'ok', ...(run.toolVersion !== undefined ? { version: run.toolVersion } : {}) },
      ],
      missing_tools: [],
      meta: {
        series: run.series.key,
        series_label: run.series.label,
        tool: run.tool,
        ...(run.toolVersion !== undefined ? { tool_version: run.toolVersion } : {}),
        report_path: run.reportPath,
        metrics: Object.fromEntries(run.samples.map((s) => [s.name, { value: s.value, unit: s.unit }])),
        verdicts: Object.fromEntries(metrics.map((m) => [m.name, m.verdict])),
      },
    });
  } catch (e) {
    return { series: run.series.label, recorded: false, reason: `the run was judged but could not be kept in the history: ${errorText(e)}`, ...judged };
  }
  return { series: run.series.label, recorded: true, scan_id: run.scanId, ...judged };
}

/**
 * `budgets.status` on the response — always present on a Lighthouse run, so
 * a caller never has to infer "was this even checked?" from an empty
 * `findings` array, which is indistinguishable between "no budgets file"
 * and "budgets file exists and everything is within budget" and — the bug
 * this shape fixes — "budgets file is broken and was never evaluated at
 * all". `quality_check` reports the equivalent via its own `tools_run`
 * ('budgets': ok/failed); `perf_check` has no `tools_run` of its own, so
 * this field is the equivalent signal for it.
 */
export interface PerfBudgetsStatus {
  /**
   * `not_measured`: a budget is configured whose metric this run has no
   * value for (Lighthouse returned null — INP in a navigation run, an audit
   * that did not run). It is never `ok`: an unmeasured budget is not a
   * budget kept (review M5). The measured ones are still evaluated.
   */
  status: 'none' | 'ok' | 'invalid' | 'not_measured';
  /** Present for 'ok', 'not_measured' and 'invalid' — the budgets file that was (or would have been) read. */
  path?: string;
  /** 'invalid' only: why it could not be evaluated. */
  reason?: string;
  /** 'ok' / 'not_measured': how many of THIS run's measurements broke their budget. */
  violations?: number;
  /** 'not_measured' only: the budgets with no measurement (`perf.inp_ms`). */
  not_measured?: string[];
}

interface LighthouseBudgetResult {
  findings: Finding[];
  budgets: PerfBudgetsStatus;
  warnings: string[];
}

/**
 * `.guardian/budgets.yml`'s `perf` section, evaluated against this run's
 * Core Web Vitals. Never fails the whole perf check over a typo'd YAML
 * file — but, unlike an early version of this function, never silently
 * treats an INVALID file the same as a MISSING one either: both used to
 * fall into "no findings", which made a broken budgets.yml read as "within
 * budget" instead of "not evaluated". `budgets.status` now tells the two
 * apart explicitly, and an invalid file also gets a `warnings` entry.
 */
function evaluateLighthouseBudgets(
  projectPath: string,
  cwv: Record<string, number | null>,
): LighthouseBudgetResult {
  const loaded = loadBudgets(projectPath);
  if (loaded.kind === 'none') {
    return { findings: [], budgets: { status: 'none' }, warnings: [] };
  }
  if (loaded.kind === 'invalid') {
    return {
      findings: [],
      budgets: { status: 'invalid', path: loaded.path, reason: loaded.error },
      warnings: [
        `.guardian/budgets.yml is invalid and was NOT evaluated (perf budgets, if any were set, ` +
          `were not checked): ${loaded.error}`,
      ],
    };
  }
  const relPath = relative(projectPath, loaded.path);
  if (!loaded.budgets.perf) {
    return { findings: [], budgets: { status: 'ok', path: relPath, violations: 0 }, warnings: [] };
  }

  const totalByteWeight = cwv['total-byte-weight'];
  const measured: PerfBudgets = {
    lcp_ms: cwv['largest-contentful-paint'] ?? undefined,
    inp_ms: cwv['interaction-to-next-paint'] ?? undefined,
    cls: cwv['cumulative-layout-shift'] ?? undefined,
    tbt_ms: cwv['total-blocking-time'] ?? undefined,
    bundle_size_kb: totalByteWeight !== null && totalByteWeight !== undefined ? totalByteWeight / 1024 : undefined,
  };
  const violations = evaluatePerfBudgets(measured, loaded.budgets.perf);
  const findings = budgetViolationFindings(violations, relPath);
  // A configured budget with no measurement was not kept, nor broken: said so.
  const perf = loaded.budgets.perf;
  const unmeasured = (Object.keys(perf) as Array<keyof PerfBudgets>)
    .filter((key) => perf[key] !== undefined && (measured[key] === undefined || measured[key] === null))
    .map((key) => `perf.${key}`);
  if (unmeasured.length > 0) {
    return {
      findings,
      budgets: { status: 'not_measured', path: relPath, violations: findings.length, not_measured: unmeasured },
      warnings: [
        `${unmeasured.join(', ')} not measured: Lighthouse reported no value for ${
          unmeasured.length === 1 ? 'that metric' : 'those metrics'
        }, so ${unmeasured.length === 1 ? 'that budget was' : 'those budgets were'} not checked — never read that as within budget.`,
      ],
    };
  }
  return { findings, budgets: { status: 'ok', path: relPath, violations: findings.length }, warnings: [] };
}

interface LighthouseSummary {
  scores: Record<string, number | null>;
  core_web_vitals: Record<string, number | null>;
}

function summariseLighthouse(root: unknown): LighthouseSummary {
  const categories = getProp(root, 'categories');
  const scores: Record<string, number | null> = {};
  if (categories && typeof categories === 'object') {
    for (const key of ['performance', 'accessibility', 'best-practices', 'seo', 'pwa']) {
      const cat = getProp(categories, key);
      const score = getNumber(cat, 'score');
      scores[key] = score === undefined ? null : Math.round(score * 100);
    }
  }
  const audits = getProp(root, 'audits');
  const cwv: Record<string, number | null> = {};
  for (const key of [
    'largest-contentful-paint',
    'cumulative-layout-shift',
    'interaction-to-next-paint',
    'total-blocking-time',
    'first-contentful-paint',
    'speed-index',
    'server-response-time',
    // Total page weight in bytes — the closest thing Lighthouse measures to
    // "bundle size" without a bundler-stats integration; see
    // evaluateLighthouseBudgets, which converts it to bundle_size_kb.
    'total-byte-weight',
  ]) {
    const audit = getProp(audits, key);
    const numeric = getNumber(audit, 'numericValue');
    cwv[key] = numeric === undefined ? null : Math.round(numeric * 100) / 100;
  }
  return { scores, core_web_vitals: cwv };
}

interface K6Opts {
  scriptPath: string;
  reportDir: string;
  projectPath: string;
  scanId: string;
  ctx: PluginContext;
}

async function runK6(opts: K6Opts): Promise<ToolResult<Record<string, unknown>>> {
  const bin = await scannerAvailable('k6');
  if (!bin) {
    return failDomain(
      'missing_scanner',
      'k6 CLI is not installed. Install from https://k6.io/docs/getting-started/installation/.',
    );
  }
  // Resolved against the project — k6 runs there, and `existsSync` of the
  // bare argument used to answer about the server's own working directory —
  // and held inside it: a link or `..` out of the project is refused.
  const script = resolve(opts.projectPath, opts.scriptPath);
  const kind = projectPathKind(opts.projectPath, script);
  if (kind === 'outside') {
    return failDomain('invalid_input', `k6_script_path must be a file inside the project: ${opts.scriptPath}`);
  }
  if (kind !== 'file') {
    return failDomain('scanner_failed', `k6 script not found in the project: ${opts.scriptPath}`);
  }

  const summaryFile = join(opts.reportDir, 'k6-summary.json');
  // The script is code, and k6 hands it the environment as `__ENV`: only
  // what k6 needs, its own `K6_*` options and the proxy — never a token the
  // server was started with (review of 3.6, finding 14). Its `K6_*` settings
  // key the series, read from this object: what k6 is handed.
  const env = allowlistedEnv((name) => K6_ENV.test(name));
  // The series' inputs as k6 reads them at its start, so read before it runs: the script's content and the
  // local modules it imports (`metrics/k6Inputs.ts`, which never throws).
  const scriptRel = relative(opts.projectPath, script).split(sep).join('/');
  const contentSha256 = await hashProjectFile(opts.projectPath, script);
  const inputs = k6LocalInputs(scriptRel, k6ModuleReader(opts.projectPath));
  const result = await runProcess({
    command: 'k6',
    // `--no-usage-report`: k6 otherwise sends Grafana a usage report on every run (and keeps an installation id in
    // the user's config folder). A flag, never the `K6_NO_USAGE_REPORT` variable: a `K6_*` setting keys the series.
    args: ['run', '--no-usage-report', `--summary-export=${summaryFile}`, script],
    cwd: opts.projectPath,
    env,
    extendEnv: false,
    timeoutMs: 30 * 60_000,
  });
  // k6's own exit codes: 0, and 99 when the run completed but a threshold
  // failed — a result, not a failure of the tool. Anything else (a script
  // error, a bad option, an abort, the timeout) measured nothing to trust.
  const thresholdsFailed = result.exitCode === K6_THRESHOLDS_FAILED;
  if (result.outcome === 'timed_out' || (result.exitCode !== 0 && !thresholdsFailed)) {
    const line = result.stderr.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0) ?? result.outcome;
    return failDomain('scanner_failed', `k6 exit ${String(result.exitCode)}: ${line}`);
  }
  if (!existsSync(summaryFile)) {
    // Some k6 versions only write summary on success; capture stdout as a fallback.
    writeFileSync(summaryFile, result.stdout || '{}', 'utf8');
  }
  const raw = readFileSync(summaryFile, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return failDomain('scanner_failed', 'k6 summary was not valid JSON.');
  }

  const summary = summariseK6(parsed);
  // The series is the run's inputs only: the script as the project names it, its content (its
  // `options` are in it), the local modules it imports and the `K6_*` settings it was handed. Never a VU
  // count k6 measured: an arrival-rate executor adds VUs as the target slows down (keyed by the max, a
  // slower run left its series), and k6 samples them from the start of the VUs' init, so a minimum
  // jitters when the init outlasts the first sample (keyed by it, every run was new).
  const history = recordPerfRun(opts.ctx, {
    projectPath: opts.projectPath,
    scanId: opts.scanId,
    reportDir: opts.reportDir,
    reportPath: summaryFile,
    tool: 'k6',
    toolVersion: undefined,
    series: k6Series(scriptRel, contentSha256, k6Settings(env), inputs),
    samples: k6Samples(summary),
  });
  return {
    ok: true,
    tool: 'k6',
    script: opts.scriptPath,
    report_path: summaryFile,
    passed: !thresholdsFailed,
    exit_code: result.exitCode,
    ...(thresholdsFailed ? { note: 'k6 exited 99: the run completed, and at least one threshold failed' } : {}),
    summary,
    history,
  };
}

/** k6's exit code for a run that completed with a failed threshold. */
const K6_THRESHOLDS_FAILED = 99;

/**
 * What `k6LocalInputs` reads the script's modules with: contained project reads (a link out of the project, a
 * FIFO or a directory refused, never waited on), each under the project file cap, which a larger module is keyed
 * past (`too-large`).
 */
function k6ModuleReader(projectPath: string): K6InputReader {
  return {
    read(rel) {
      const r = readProjectBytes(projectPath, rel, PROJECT_FILE_MAX_BYTES);
      if (r.status === 'ok') return { kind: 'ok', bytes: r.bytes };
      if (r.status === 'absent') return { kind: 'absent' };
      return r.reason === 'too-large' ? { kind: 'too-large' } : { kind: 'refused' };
    },
    resolve(fromDir, spec) {
      let abs: string;
      try {
        abs = spec.startsWith('file://') ? fileURLToPath(spec) : resolve(projectPath, fromDir, spec);
      } catch {
        return null;
      }
      return isWithinDir(projectPath, abs) ? relative(projectPath, abs).split(sep).join('/') : null;
    },
  };
}

/** What k6 is given besides the test command's allowlist: its own options and the proxy. */
const K6_ENV = /^(?:K6_.+|HTTPS?_PROXY|NO_PROXY|ALL_PROXY|SSL_CERT_FILE|SSL_CERT_DIR)$/;

/**
 * The script's thresholds, as `--summary-export` writes them: under each metric (a submetric keeps k6's spelling,
 * `http_reqs{status:200}`), `thresholds: { "<expression>": <crossed> }` — `true` when it failed (k6 writes
 * `!threshold.ok`). Each one is `"<metric>: <expression>"`, sorted. A check is no threshold: `root_group.checks`
 * is never read here.
 */
function k6Thresholds(metrics: unknown): { configured: string[]; failed: string[] } {
  const configured: string[] = [];
  const failed: string[] = [];
  if (metrics !== null && typeof metrics === 'object') {
    for (const [name, metric] of Object.entries(metrics)) {
      const thresholds = getProp(metric, 'thresholds');
      if (thresholds === null || typeof thresholds !== 'object' || Array.isArray(thresholds)) continue;
      for (const [expression, crossed] of Object.entries(thresholds)) {
        const id = `${name}: ${expression}`;
        configured.push(id);
        if (crossed === true) failed.push(id);
      }
    }
  }
  return { configured: configured.sort(), failed: failed.sort() };
}

function summariseK6(root: unknown): Record<string, unknown> {
  const metrics = getProp(root, 'metrics');
  const requests = getProp(metrics, 'http_reqs');
  const duration = getProp(metrics, 'http_req_duration');
  const failed = getProp(metrics, 'http_req_failed');
  const thresholds = k6Thresholds(metrics);

  return {
    requests_total: getNumber(requests, 'count') ?? null,
    // `--summary-export` writes the legacy summary, where a Rate metric is `{ passes, fails, value }`.
    error_rate: getNumber(failed, 'rate') ?? getNumber(failed, 'value') ?? null,
    latency_avg_ms: getNumber(duration, 'avg') ?? null,
    latency_p95_ms: getNumber(duration, 'p(95)') ?? null,
    // k6 writes p(99) only when the script's `summaryTrendStats` asks for it: null otherwise.
    latency_p99_ms: getNumber(duration, 'p(99)') ?? null,
    thresholds_configured: thresholds.configured,
    thresholds_failed: thresholds.failed,
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
