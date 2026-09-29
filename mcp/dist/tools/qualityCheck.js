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
 *
 * `scope` (`platform/scope.ts`) hands every analyser the scoped files instead
 * of the project: jscpd all of them (so duplication is measured AMONG the
 * scoped files — a copy of code outside the scope is not seen, and the reason
 * says so), ruff and radon the `.py` ones, ESLint the JS/TS ones, staticcheck
 * the packages holding the `.go` ones (it analyses packages, not files; the
 * factory keeps only findings in scoped files). The budgets in
 * `.guardian/budgets.yml` are project-level — a duplication percentage of the
 * whole project — so a scoped run skips them and says why.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { z } from 'zod';
import { budgetViolationFindings, evaluateQualityBudgets, loadBudgets } from '../budgets/budgets.js';
import { ScanScopeInput } from '../platform/scope.js';
import { batchArgs } from '../runners/argBatches.js';
import { scanFileBatches } from '../runners/fileBatchScan.js';
import { runProcess } from '../runners/processRunner.js';
import { nameRepoConfig } from '../runners/repoConfig.js';
import { hasFileWithExtension } from '../runners/projectFiles.js';
import { eslintFatalErrors, eslintParser } from '../runners/scannerParsers/eslint.js';
import { asArray, getNumber, getProp, parseInputAsJson } from '../runners/scannerParsers/index.js';
import { jscpdParser } from '../runners/scannerParsers/jscpd.js';
import { radonErrors, radonParser } from '../runners/scannerParsers/radon.js';
import { ruffParser } from '../runners/scannerParsers/ruff.js';
import { staticcheckErrors, staticcheckParser } from '../runners/scannerParsers/staticcheck.js';
import { Force, ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
export const QUALITY_CATEGORIES = ['duplicate', 'complexity', 'smell', 'naming'];
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
/**
 * The analysers here that read the project's own configuration — ruff
 * `ruff.toml` / `[tool.ruff]` from each file upwards, jscpd `.jscpd.json`,
 * radon `radon.cfg` / `[radon]`, staticcheck `staticcheck.conf`, ESLint its
 * config — in whole-project and scoped runs alike. Each run that ran names
 * them (`runners/repoConfig.ts`; round 5, item 2).
 */
const QUALITY_RUNNERS = ['ruff', 'jscpd', 'radon', 'staticcheck', 'eslint'];
async function nameQualityConfig(projectPath, out) {
    const named = [];
    for (const run of out.tools_run) {
        const runner = QUALITY_RUNNERS.find((r) => r === run.name);
        const ran = !(run.status === 'skipped');
        named.push(runner !== undefined && ran ? await nameRepoConfig(run, projectPath, runner) : run);
    }
    out.tools_run = named;
}
/** Kept out of jscpd and radon, as they are out of every other walk of the project. */
const IGNORED_DIRS = ['node_modules', '.git', '.guardian', 'vendor', 'dist', 'build', 'venv', '.venv', '__pycache__'];
registerToolModule(makeScanTool({
    name: 'quality_check',
    title: 'Code quality scan',
    description: 'Code-quality scan: jscpd (duplication, any language); ruff and radon cyclomatic complexity when ' +
        'the project has .py files; ESLint when it is configured and installed in node_modules (never via ' +
        'npx); staticcheck when there is a go.mod. Findings are classified duplicate / complexity / smell / ' +
        'naming; `categories` narrows the response to those classes while every finding is still recorded ' +
        '(`category_filter` counts what was withheld). An applicable analyser that is missing or fails is ' +
        'reported as such and coverage is partial, never full. Also reads .guardian/budgets.yml, when ' +
        'present, and reports an exceeded duplication % or complexity budget as a finding. Pass scope to ' +
        'analyse only some files (duplication is then measured among them; budgets, being project-level, ' +
        'are skipped). .guardianignore paths are filtered out.',
    scan_type: 'quality',
    category: 'quality',
    supportsAutoFix: false,
    supportsScope: true,
    responseOnlyInputs: ['categories'],
    responseView: (input, findings, scanId) => qualityCategoriesView(input.categories, findings, scanId),
    inputSchema: {
        project_path: ProjectPath,
        categories: z
            .array(z.enum(QUALITY_CATEGORIES))
            .optional()
            .describe('Show only these quality classes in the response. Every finding is still recorded; ' +
            '`category_filter` counts what was withheld.'),
        force: Force,
        scope: ScanScopeInput,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'quality');
        const out = { tools_run: [], missing_tools: [], parser_inputs: [], cancelled: false };
        if (ctx.scope !== null) {
            await runOnScope(ctx, reportDir, out, ctx.scope.files);
            await nameQualityConfig(ctx.projectPath, out);
            return {
                outcome: out.cancelled ? 'cancelled' : 'completed',
                tools_run: out.tools_run,
                missing_tools: out.missing_tools,
                parser_inputs: out.parser_inputs,
                report_paths: [reportDir],
            };
        }
        await runJscpd(ctx, reportDir, out);
        if (!out.cancelled && hasFileWithExtension(ctx.projectPath, ['.py'])) {
            await runRuff(ctx, reportDir, out);
            if (!out.cancelled)
                await runRadon(ctx, reportDir, out);
        }
        if (!out.cancelled && hasEslintConfig(ctx.projectPath))
            await runEslint(ctx, reportDir, out);
        if (!out.cancelled && existsSync(join(ctx.projectPath, 'go.mod')))
            await runStaticcheck(ctx, out);
        // Separated step, deliberately: reads the jscpd/radon reports jscpd and
        // radon already wrote above (never re-runs a scanner), and is the only
        // part of this file that knows about .guardian/budgets.yml at all.
        if (!out.cancelled)
            runBudgets(ctx.projectPath, reportDir, out);
        await nameQualityConfig(ctx.projectPath, out);
        return {
            outcome: out.cancelled ? 'cancelled' : 'completed',
            tools_run: out.tools_run,
            missing_tools: out.missing_tools,
            parser_inputs: out.parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
/** Wraps a precomputed `Finding[]` as a `ScannerParser` — no parsing left to do, but this is what lets it flow through the same `parser_inputs` pipeline as every other analyser's output. */
const budgetsPassthroughParser = {
    name: 'budgets',
    parse(input) {
        return { findings: input, cves: [] };
    },
};
/**
 * `.guardian/budgets.yml`'s `quality` section (duplication %, complexity),
 * evaluated against THIS scan's own jscpd/radon reports — re-read from the
 * files `runJscpd`/`runRadon` already wrote above, never a second scanner
 * run. A clearly separate step on purpose (task 15 brief): everything else
 * in this file is "run an analyser, parse its report"; this is "read two of
 * those reports again and compare them to a budget".
 *
 * No `.guardian/budgets.yml` at all is not a gap — nothing was asked for, so
 * nothing is reported (no `tools_run` entry). A budgets file that fails to
 * parse IS reported, `failed`, with why: a typo'd budget must not silently
 * stop firing.
 */
function runBudgets(projectPath, reportDir, out) {
    const loaded = loadBudgets(projectPath);
    if (loaded.kind === 'none')
        return;
    if (loaded.kind === 'invalid') {
        out.tools_run.push({ name: 'budgets', status: 'failed', reason: `${loaded.path}: ${loaded.error}` });
        return;
    }
    const budgets = loaded.budgets.quality;
    if (!budgets)
        return;
    const measured = measureQuality(reportDir);
    const violations = evaluateQualityBudgets(measured, budgets);
    const findings = budgetViolationFindings(violations, relative(projectPath, loaded.path));
    if (findings.length > 0)
        out.parser_inputs.push({ parser: budgetsPassthroughParser, input: findings });
    out.tools_run.push({
        name: 'budgets',
        status: 'ok',
        ...(findings.length > 0 ? { reason: `${findings.length} violation(s) — ${loaded.path}` } : {}),
    });
}
/** jscpd's project-wide duplication %, and radon's highest function/method complexity — read straight back out of the JSON reports both scanners already wrote for this scan. Either is absent when its scanner did not run (radon: no `.py` files) — `evaluateQualityBudgets` skips a metric it has no measurement for. */
function measureQuality(reportDir) {
    const measured = {};
    const dup = parseInputAsJson(readJsonSafe(join(reportDir, 'dup', 'jscpd-report.json')));
    const total = getProp(dup, 'statistics') ? getProp(getProp(dup, 'statistics'), 'total') : undefined;
    const reportedPct = getNumber(total, 'percentage');
    if (reportedPct !== undefined) {
        measured.duplication_pct = reportedPct;
    }
    else {
        // The fixture-shaped jscpd report this ships with carries no
        // `percentage` field (only the counts it is computed from); real jscpd
        // output normally has one, but fall back to computing it rather than
        // silently never measuring duplication at all.
        const lines = getNumber(total, 'lines');
        const duplicatedLines = getNumber(total, 'duplicatedLines');
        if (lines !== undefined && lines > 0 && duplicatedLines !== undefined) {
            measured.duplication_pct = (duplicatedLines / lines) * 100;
        }
    }
    const radon = parseInputAsJson(readJsonSafe(join(reportDir, 'radon-cc.json')));
    const maxComplexity = highestComplexity(radon);
    if (maxComplexity !== null)
        measured.complexity = maxComplexity;
    return measured;
}
/** The highest `complexity` among radon's function/method blocks (mirrors radonParser's own filter, minus the per-block Finding shaping). */
function highestComplexity(root) {
    if (root === null || typeof root !== 'object' || Array.isArray(root))
        return null;
    let max = null;
    for (const blocks of Object.values(root)) {
        for (const block of asArray(blocks)) {
            const type = getProp(block, 'type');
            if (type !== 'function' && type !== 'method')
                continue;
            const complexity = getNumber(block, 'complexity');
            if (complexity !== undefined && (max === null || complexity > max))
                max = complexity;
        }
    }
    return max;
}
/** The analyser is not on PATH: a named gap, never silence. */
function notInstalled(out, name, reason = 'not_installed') {
    out.tools_run.push({ name, status: 'skipped', reason });
    out.missing_tools.push(name);
}
/** Record one analyser run: `ok` with its report parsed, or `failed` with why. */
function record(out, name, run, okExitCodes, report, reportOk, parser, 
/**
 * Files the analyser could not analyse. The run is `ok` but its name goes
 * in `missing_tools` — "ran with reduced coverage" (scanCoverage.ts) —
 * because those files were not checked.
 */
gaps = []) {
    if (run.outcome === 'cancelled')
        out.cancelled = true;
    const problems = [];
    if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
        problems.push(`did not finish (${run.outcome})`);
    }
    else if (run.exitCode === null || !okExitCodes.includes(run.exitCode)) {
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
    const entry = { name, status: 'ok' };
    if (gaps.length > 0) {
        entry.reason = gaps.join('; ');
        out.missing_tools.push(name);
    }
    out.tools_run.push(entry);
}
async function runJscpd(ctx, reportDir, out) {
    if (!(await scannerAvailable('jscpd')))
        return notInstalled(out, 'jscpd');
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
async function runRuff(ctx, reportDir, out) {
    if (!(await scannerAvailable('ruff')))
        return notInstalled(out, 'ruff');
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
async function runRadon(ctx, reportDir, out) {
    if (!(await scannerAvailable('radon')))
        return notInstalled(out, 'radon');
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
async function runEslint(ctx, reportDir, out) {
    const eslint = localEslint(ctx.projectPath);
    if (eslint === null) {
        return notInstalled(out, 'eslint', 'ESLint is configured but not installed in node_modules — run your package manager install first. ' +
            'npx is never used: it would download ESLint from the network.');
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
async function runStaticcheck(ctx, out, packages = ['./...']) {
    if (!(await scannerAvailable('staticcheck')))
        return notInstalled(out, 'staticcheck');
    const run = await runProcess({
        command: 'staticcheck',
        args: ['-f', 'json', ...packages],
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
// ---- scoped runs ------------------------------------------------------
const JS_TS = /\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i;
/** Every applicable analyser over the scope's files — see the module comment. */
async function runOnScope(ctx, reportDir, out, files) {
    if (files.length === 0) {
        out.tools_run.push({ name: 'jscpd', status: 'skipped', reason: 'the scope holds no file — nothing to analyse' });
        return;
    }
    await runJscpdOnFiles(ctx, reportDir, out, files);
    const python = files.filter((f) => f.toLowerCase().endsWith('.py'));
    if (!out.cancelled && python.length > 0) {
        await runOnFileBatches(ctx, out, {
            name: 'ruff',
            // --exit-zero: findings are exit 0, so any other exit is ruff failing.
            args: ['check', '--output-format', 'json', '--exit-zero'],
            reportArgs: (f) => ['--output-file', f],
            files: python,
            reportDir,
            okExitCodes: [0],
            reportOk: Array.isArray,
            parser: ruffParser,
        });
        if (!out.cancelled) {
            await runOnFileBatches(ctx, out, {
                name: 'radon',
                args: ['cc', '-j'],
                reportArgs: (f) => ['-O', f],
                files: python,
                reportDir,
                okExitCodes: [0],
                reportOk: isObject,
                parser: radonParser,
                errors: radonErrors,
                env: { PYTHONUTF8: '1' },
            });
        }
    }
    const scripts = files.filter((f) => JS_TS.test(f));
    if (!out.cancelled && scripts.length > 0 && hasEslintConfig(ctx.projectPath)) {
        const eslint = localEslint(ctx.projectPath);
        if (eslint === null) {
            notInstalled(out, 'eslint', 'ESLint is configured but not installed in node_modules — npx is never used.');
        }
        else {
            await runOnFileBatches(ctx, out, {
                name: 'eslint',
                command: process.execPath,
                args: [eslint, '--format', 'json'],
                reportArgs: (f) => ['--output-file', f],
                files: scripts,
                reportDir,
                okExitCodes: [0, 1],
                reportOk: Array.isArray,
                parser: eslintParser,
                errors: eslintFatalErrors,
            });
        }
    }
    const goFiles = files.filter((f) => f.endsWith('.go'));
    if (!out.cancelled && goFiles.length > 0 && existsSync(join(ctx.projectPath, 'go.mod'))) {
        // staticcheck analyses packages: the directories holding the scoped files.
        const packages = [...new Set(goFiles.map((f) => (f.includes('/') ? `./${f.slice(0, f.lastIndexOf('/'))}` : '.')))].sort();
        await runStaticcheck(ctx, out, packages);
    }
    if (!out.cancelled && loadBudgets(ctx.projectPath).kind !== 'none') {
        out.tools_run.push({
            name: 'budgets',
            status: 'skipped',
            reason: 'project-level: .guardian/budgets.yml budgets the duplication % and complexity of the whole ' +
                'project, which a scoped scan does not measure — run quality_check without scope to check them',
        });
    }
}
/**
 * jscpd over the scoped files, one run per command-line batch, each with its
 * own report directory. Duplication is measured among the files of one run:
 * the reason says so, and says when a scope was too long for one run.
 */
async function runJscpdOnFiles(ctx, reportDir, out, files) {
    if (!(await scannerAvailable('jscpd')))
        return notInstalled(out, 'jscpd');
    const fixed = ['--reporters', 'json', '--output', join(reportDir, 'dup-000'), '--silent', '--'];
    const batches = batchArgs(files, { command: 'jscpd', fixedArgs: fixed });
    const problems = [];
    for (const [i, batch] of batches.entries()) {
        const dupDir = join(reportDir, `dup-${String(i + 1).padStart(3, '0')}`);
        const run = await runProcess({
            command: 'jscpd',
            args: ['--reporters', 'json', '--output', dupDir, '--silent', '--', ...batch],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        if (run.outcome === 'cancelled')
            out.cancelled = true;
        const report = readJsonSafe(join(dupDir, 'jscpd-report.json'));
        const label = batches.length > 1 ? `batch ${i + 1}/${batches.length}: ` : '';
        if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
            problems.push(`${label}did not finish (${run.outcome})`);
        }
        else if (run.exitCode !== 0 && run.exitCode !== 1) {
            problems.push(`${label}exit ${String(run.exitCode)}${firstLine(run.stderr) ? `: ${firstLine(run.stderr)}` : ''}`);
        }
        else if (report === null || !isObject(parseInputAsJson(report))) {
            problems.push(`${label}no readable report was written`);
        }
        else {
            out.parser_inputs.push({ parser: jscpdParser, input: report });
        }
        if (out.cancelled)
            break;
    }
    const scope = `duplication measured among the ${files.length} scoped file(s) only — a copy of code outside the scope is not seen` +
        (batches.length > 1 ? `, nor one across the ${batches.length} batches the scope needed` : '');
    out.tools_run.push(problems.length === 0
        ? { name: 'jscpd', status: 'ok', reason: scope }
        : { name: 'jscpd', status: 'failed', reason: problems.join('; ') });
}
/**
 * One analyser over the scoped files, batched (`scanFileBatches`), recorded
 * like a whole-project run: `ok`, `failed` with why, and files it could not
 * analyse as reduced coverage.
 */
async function runOnFileBatches(ctx, out, opts) {
    if (opts.command === undefined && !(await scannerAvailable(opts.name)))
        return notInstalled(out, opts.name);
    const run = await scanFileBatches({
        name: opts.name,
        command: opts.command ?? opts.name,
        args: opts.args,
        reportArgs: opts.reportArgs,
        files: opts.files,
        cwd: ctx.projectPath,
        reportDir: opts.reportDir,
        reportPrefix: opts.name,
        env: { ...ctx.scriptEnv, ...(opts.env ?? {}) },
        signal: ctx.signal,
        ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
        check: ({ raw, exitCode, outcome }) => {
            if (outcome === 'cancelled' || outcome === 'timed_out' || outcome === 'output_too_large') {
                return { ok: false, reason: `did not finish (${outcome})` };
            }
            if (exitCode === null || !opts.okExitCodes.includes(exitCode))
                return { ok: false, reason: `exit ${String(exitCode)}` };
            if (raw === null || !opts.reportOk(parseInputAsJson(raw)))
                return { ok: false, reason: 'no readable report was written' };
            return { ok: true };
        },
    });
    if (run.cancelled)
        out.cancelled = true;
    for (const raw of run.reports)
        out.parser_inputs.push({ parser: opts.parser, input: raw });
    const entry = { ...run.toolRun };
    const errors = opts.errors === undefined ? [] : run.reports.flatMap((r) => opts.errors?.(r) ?? []);
    const gaps = couldNotAnalyse(errors);
    if (entry.status === 'ok' && gaps.length > 0) {
        entry.reason = [entry.reason, ...gaps].filter((s) => s !== undefined).join('; ');
        out.missing_tools.push(opts.name);
    }
    out.tools_run.push(entry);
}
function couldNotAnalyse(errors) {
    if (errors.length === 0)
        return [];
    const shown = errors.slice(0, 5).join('; ');
    return [`${errors.length} file(s) could not be analysed: ${shown}${errors.length > 5 ? '; …' : ''}`];
}
function hasEslintConfig(projectPath) {
    if (ESLINT_CONFIGS.some((name) => existsSync(join(projectPath, name))))
        return true;
    try {
        const pkg = parseInputAsJson(readFileSync(join(projectPath, 'package.json'), 'utf8'));
        return typeof pkg === 'object' && pkg !== null && 'eslintConfig' in pkg;
    }
    catch {
        return false;
    }
}
/**
 * `node_modules/eslint/bin/eslint.js` in the project or an ancestor (a
 * workspace root), stopping at the repository root — the ESLint Node itself
 * would resolve. Null when there is none: then ESLint is not installed and is
 * not fetched.
 */
function localEslint(projectPath) {
    for (let dir = projectPath;; dir = dirname(dir)) {
        const candidate = join(dir, 'node_modules', 'eslint', 'bin', 'eslint.js');
        if (existsSync(candidate))
            return candidate;
        if (existsSync(join(dir, '.git')) || dirname(dir) === dir)
            return null;
    }
}
function isObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function firstLine(text) {
    return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}
/** The `quality_check` class of a finding. */
export function qualityCategoryOf(f) {
    const sub = f.subcategory;
    if (sub === 'duplicate' || sub === 'complexity' || sub === 'smell' || sub === 'naming')
        return sub;
    if (f.tool === 'ruff') {
        const code = f.rule_id ?? '';
        if (/^C9\d/.test(code))
            return 'complexity';
        if (/^N\d/.test(code))
            return 'naming';
    }
    // A budget violation (subcategory 'budget', shared with perf_check's own
    // budget findings — see budgets/budgets.ts) names which budget it is in
    // `rule_id`: "quality.duplication_pct" / "quality.complexity". Classified
    // by that, not left in the 'smell' catch-all, so `categories: [duplicate]`
    // shows a duplication-budget breach alongside jscpd's own findings.
    if (f.tool === 'budgets') {
        if (f.rule_id === 'quality.duplication_pct')
            return 'duplicate';
        if (f.rule_id === 'quality.complexity')
            return 'complexity';
    }
    return 'smell';
}
/**
 * `categories` as a view over the stored findings — the ones outside the
 * requested classes are withheld from THIS response and counted, never
 * dropped from the scan. Null when no filter was asked for.
 */
export function qualityCategoriesView(categories, findings, scanId) {
    if (categories === undefined || categories.length === 0)
        return null;
    const visible = [];
    const withheldByCategory = {};
    for (const f of findings) {
        const category = qualityCategoryOf(f);
        if (categories.includes(category))
            visible.push(f);
        else
            withheldByCategory[category] = (withheldByCategory[category] ?? 0) + 1;
    }
    const withheld = findings.length - visible.length;
    return {
        visible,
        disclosure: {
            category_filter: { categories: [...categories], withheld, withheld_by_category: withheldByCategory },
        },
        warning: withheld === 0
            ? null
            : `categories ${JSON.stringify(categories)} withheld ${withheld} finding(s) from this response only; ` +
                `they are recorded in scan ${scanId}, and baselines and diffs against it include them.`,
    };
}
//# sourceMappingURL=qualityCheck.js.map