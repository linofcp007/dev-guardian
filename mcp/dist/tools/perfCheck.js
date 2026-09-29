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
import { budgetViolationFindings, evaluatePerfBudgets, loadBudgets } from '../budgets/budgets.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { ensureReportDir, scannerAvailable } from './scanHelpers.js';
import { asArray, getNumber, getProp, getString, } from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
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
const tool = {
    name: 'perf_check',
    title: 'Performance probe (Lighthouse or k6)',
    description: 'Run Lighthouse against target_url, or k6 against k6_script_path. Returns parsed metrics ' +
        '(Core Web Vitals for Lighthouse; request count + p95/p99 + thresholds for k6) and the ' +
        'absolute path to the raw JSON report. A Lighthouse run also reads .guardian/budgets.yml, when ' +
        'present, and reports any exceeded perf budget (LCP/INP/CLS/TBT/bundle size) as a Finding in ' +
        '`findings`. `budgets.status` says none/ok/not_measured/invalid — an invalid file, or a budget whose ' +
        'metric Lighthouse did not measure, is never reported as "within budget". A page Lighthouse could not ' +
        'load (runtimeError, non-zero exit) is a failed check.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    // Narrow the VALUES, not a boolean derived from them: `hasUrl` told the
    // reader the url was present but told the compiler nothing, which is why
    // both call sites below used to need a non-null assertion.
    const targetUrl = inp.target_url !== undefined && inp.target_url.length > 0 ? inp.target_url : undefined;
    const k6Script = inp.k6_script_path !== undefined && inp.k6_script_path.length > 0
        ? inp.k6_script_path
        : undefined;
    if ((targetUrl === undefined) === (k6Script === undefined)) {
        return failDomain('scanner_failed', 'Provide exactly one of target_url (Lighthouse) or k6_script_path (k6).');
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
async function runLighthouse(opts) {
    const bin = await scannerAvailable('lighthouse');
    if (!bin) {
        return failDomain('missing_scanner', 'Lighthouse CLI is not installed. Install with `npm i -g lighthouse`.');
    }
    const outFile = join(opts.reportDir, 'lighthouse.json');
    const args = [
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
        return failDomain('scanner_failed', `Lighthouse did not produce a report. stderr: ${result.stderr.split(/\r?\n/)[0] ?? ''}`);
    }
    const raw = readFileSync(outFile, 'utf8');
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
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
        return failDomain('scanner_failed', `Lighthouse could not measure ${opts.url}: ${code}${message ? ` — ${message}` : ''} (report: ${outFile})`);
    }
    if (result.exitCode !== 0) {
        const line = result.stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ?? result.outcome;
        return failDomain('scanner_failed', `Lighthouse exit ${String(result.exitCode)}: ${line} (report: ${outFile})`);
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
 * `.guardian/budgets.yml`'s `perf` section, evaluated against this run's
 * Core Web Vitals. Never fails the whole perf check over a typo'd YAML
 * file — but, unlike an early version of this function, never silently
 * treats an INVALID file the same as a MISSING one either: both used to
 * fall into "no findings", which made a broken budgets.yml read as "within
 * budget" instead of "not evaluated". `budgets.status` now tells the two
 * apart explicitly, and an invalid file also gets a `warnings` entry.
 */
function evaluateLighthouseBudgets(projectPath, cwv) {
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
    const measured = {
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
    const unmeasured = Object.keys(perf)
        .filter((key) => perf[key] !== undefined && (measured[key] === undefined || measured[key] === null))
        .map((key) => `perf.${key}`);
    if (unmeasured.length > 0) {
        return {
            findings,
            budgets: { status: 'not_measured', path: relPath, violations: findings.length, not_measured: unmeasured },
            warnings: [
                `${unmeasured.join(', ')} not measured: Lighthouse reported no value for ${unmeasured.length === 1 ? 'that metric' : 'those metrics'}, so ${unmeasured.length === 1 ? 'that budget was' : 'those budgets were'} not checked — never read that as within budget.`,
            ],
        };
    }
    return { findings, budgets: { status: 'ok', path: relPath, violations: findings.length }, warnings: [] };
}
function summariseLighthouse(root) {
    const categories = getProp(root, 'categories');
    const scores = {};
    if (categories && typeof categories === 'object') {
        for (const key of ['performance', 'accessibility', 'best-practices', 'seo', 'pwa']) {
            const cat = getProp(categories, key);
            const score = getNumber(cat, 'score');
            scores[key] = score === undefined ? null : Math.round(score * 100);
        }
    }
    const audits = getProp(root, 'audits');
    const cwv = {};
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
async function runK6(opts) {
    const bin = await scannerAvailable('k6');
    if (!bin) {
        return failDomain('missing_scanner', 'k6 CLI is not installed. Install from https://k6.io/docs/getting-started/installation/.');
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
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
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
function summariseK6(root) {
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
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=perfCheck.js.map