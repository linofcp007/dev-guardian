/**
 * `perf_check` — performance probe via Lighthouse (URL) or k6 (script).
 *
 * Exactly one of `target_url` (Lighthouse) or `k6_script_path` (k6) must be
 * provided. The response carries a parsed summary plus the absolute path to
 * the raw JSON report.
 *
 * Lighthouse summary surfaces Core Web Vitals (LCP, CLS, INP/TBT, FCP, SI,
 * TTFB) plus the 5 high-level scores (performance, a11y, best-practices,
 * SEO, PWA). k6 summary surfaces request count, error rate, p95/p99
 * latency, plus the names of every configured threshold.
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
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { budgetViolationFindings, evaluatePerfBudgets, loadBudgets, type PerfBudgets } from '../budgets/budgets.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, Finding, ToolResult } from '../types.js';
import { ensureReportDir, scannerAvailable } from './scanHelpers.js';
import {
  asArray,
  getNumber,
  getProp,
  getString,
} from '../runners/scannerParsers/index.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  target_url: z
    .string()
    .url()
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

const tool: ToolModule = {
  name: 'perf_check',
  title: 'Performance probe (Lighthouse or k6)',
  description:
    'Run Lighthouse against target_url, or k6 against k6_script_path. Returns parsed metrics ' +
    '(Core Web Vitals for Lighthouse; request count + p95/p99 + thresholds for k6) and the ' +
    'absolute path to the raw JSON report. A Lighthouse run also reads .guardian/budgets.yml, when ' +
    'present, and reports any exceeded perf budget (LCP/INP/CLS/TBT/bundle size) as a Finding in ' +
    '`findings`. `budgets.status` says none/ok/invalid — an invalid file is never reported the same ' +
    'as "no budgets" or "within budget".',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    target_url?: string;
    k6_script_path?: string;
    lighthouse_categories?: string[];
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

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

  const scanId = randomUUID();
  const reportDir = ensureReportDir(projectPath, scanId, 'perf');

  if (targetUrl !== undefined) {
    return runLighthouse({
      url: targetUrl,
      categories: inp.lighthouse_categories,
      reportDir,
      projectPath,
      ctx,
    });
  }
  if (k6Script === undefined) {
    return failDomain('scanner_failed', 'Provide exactly one of target_url or k6_script_path.');
  }
  return runK6({ scriptPath: k6Script, reportDir, projectPath, ctx });
}

interface LighthouseOpts {
  url: string;
  categories?: string[];
  reportDir: string;
  projectPath: string;
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
    '--chrome-flags=--headless=new --no-sandbox',
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

  const summary = summariseLighthouse(parsed);
  const budgetResult = evaluateLighthouseBudgets(opts.projectPath, summary.core_web_vitals);
  return {
    ok: true,
    tool: 'lighthouse',
    url: opts.url,
    report_path: outFile,
    summary,
    findings: budgetResult.findings,
    budgets: budgetResult.budgets,
    ...(budgetResult.warnings.length > 0 ? { warnings: budgetResult.warnings } : {}),
  };
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
  status: 'none' | 'ok' | 'invalid';
  /** Present for 'ok' and 'invalid' — the budgets file that was (or would have been) read. */
  path?: string;
  /** 'invalid' only: why it could not be evaluated. */
  reason?: string;
  /** 'ok' only: how many of THIS run's measurements broke their budget. */
  violations?: number;
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
  if (!existsSync(opts.scriptPath)) {
    return failDomain('scanner_failed', `k6 script not found: ${opts.scriptPath}`);
  }

  const summaryFile = join(opts.reportDir, 'k6-summary.json');
  const result = await runProcess({
    command: 'k6',
    args: ['run', `--summary-export=${summaryFile}`, opts.scriptPath],
    cwd: opts.projectPath,
    timeoutMs: 30 * 60_000,
  });
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
  return {
    ok: true,
    tool: 'k6',
    script: opts.scriptPath,
    report_path: summaryFile,
    summary,
  };
}

function summariseK6(root: unknown): Record<string, unknown> {
  const metrics = getProp(root, 'metrics');
  const requests = getProp(metrics, 'http_reqs');
  const duration = getProp(metrics, 'http_req_duration');
  const failed = getProp(metrics, 'http_req_failed');
  const thresholds = getProp(root, 'root_group')
    ? asArray(getProp(getProp(root, 'root_group'), 'checks')).map((c) => getString(c, 'name'))
    : [];

  return {
    requests_total: getNumber(requests, 'count') ?? null,
    error_rate: getNumber(failed, 'rate') ?? null,
    latency_avg_ms: getNumber(duration, 'avg') ?? null,
    latency_p95_ms: getNumber(duration, 'p(95)') ?? null,
    latency_p99_ms: getNumber(duration, 'p(99)') ?? null,
    thresholds_configured: thresholds.filter((t) => t !== undefined),
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
