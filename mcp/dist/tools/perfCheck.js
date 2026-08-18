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
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
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
        'absolute path to the raw JSON report.',
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
    const summary = summariseLighthouse(parsed);
    return {
        ok: true,
        tool: 'lighthouse',
        url: opts.url,
        report_path: outFile,
        summary,
    };
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