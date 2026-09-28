/**
 * Running a scanner over an explicit list of files: split below the command-
 * line budget (`argBatches.ts`), one report file per batch, every batch
 * checked on its own, results merged.
 *
 * The files always follow `--`, so a file named `-x.py` is a file — without
 * it Semgrep 1.176.1 answers `unknown option '-s'` (measured) and scans
 * nothing. They are passed as separate arguments with no shell in between, so
 * spaces and non-ASCII characters arrive intact.
 *
 * A batch whose check fails makes the whole tool `failed` with the batch's
 * reason; the results it did write are still kept, because they are real.
 * Nothing about one batch is ever inferred from another. A batch the check
 * calls partial (Semgrep: some files only partly parsed —
 * `semgrepReport.ts`) is not a failure: the run is `ok`, its reason and
 * `partially_parsed` name those files, and the result carries them in
 * `partial` for the caller to list the scanner missing as well. So is a
 * Semgrep batch whose only errors are rules that did not load (the judge's
 * `rules_not_loaded`): the rules go to `failed_rules` and `failedRules`,
 * once each however many batches reported them.
 */
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { readJsonSafe } from '../tools/scanHelpers.js';
import { batchArgs } from './argBatches.js';
import { runProcess } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson } from './scannerParsers/index.js';
import { checkSemgrepReport, describeNoRuleLoaded, describePartialParse, describeRulesNotLoaded, pythonUtf8Env, } from './semgrepReport.js';
import { localRuleIdNormalizer, noRuleLoaded } from './semgrepRuleIds.js';
import { toRelativeIfPossible } from './scannerParsers/index.js';
export async function scanFileBatches(opts) {
    const probeReport = join(opts.reportDir, `${opts.reportPrefix}-000.json`);
    const batches = batchArgs(opts.files, {
        command: opts.command,
        fixedArgs: [...opts.args, ...opts.reportArgs(probeReport), '--'],
    });
    const reports = [];
    const reportFiles = [];
    const failures = [];
    let configFailures = 0;
    const partial = [];
    const failedRules = [];
    let cancelled = false;
    let scanned = 0;
    for (const [i, batch] of batches.entries()) {
        if (opts.signal.aborted) {
            cancelled = true;
            break;
        }
        const reportFile = join(opts.reportDir, `${opts.reportPrefix}-${String(i + 1).padStart(3, '0')}.json`);
        rmSync(reportFile, { force: true });
        const run = await runProcess({
            command: opts.command,
            args: [...opts.args, ...opts.reportArgs(reportFile), '--', ...batch],
            cwd: opts.cwd,
            env: opts.env,
            signal: opts.signal,
            onLog: opts.onLog,
        });
        if (run.outcome === 'cancelled')
            cancelled = true;
        const raw = readJsonSafe(reportFile);
        if (raw !== null && parseInputAsJson(raw) !== null) {
            reports.push(raw);
            reportFiles.push(reportFile);
        }
        const verdict = opts.check({
            raw,
            exitCode: run.exitCode,
            outcome: run.outcome,
            // With requireScanned the count is judged below, over every batch.
            targets: opts.requireScanned === true ? 0 : batch.length,
        });
        scanned += verdict.scanned ?? 0;
        for (const p of verdict.partial ?? []) {
            const file = toRelativeIfPossible(p.file, opts.cwd);
            if (!partial.some((q) => q.file === file && q.type === p.type))
                partial.push({ ...p, file });
        }
        for (const r of verdict.failedRules ?? [])
            if (!failedRules.some((q) => q.rule_id === r.rule_id))
                failedRules.push(r);
        if (!verdict.ok) {
            const label = batches.length > 1 ? `batch ${i + 1}/${batches.length}: ` : '';
            failures.push(`${label}${verdict.reason ?? 'failed'}`);
            if (verdict.ruleConfigError === true)
                configFailures += 1;
        }
        if (cancelled)
            break;
    }
    const described = `${opts.files.length} file(s)${batches.length > 1 ? ` in ${batches.length} batches` : ''}`;
    if (failures.length === 0 && !cancelled && failedRules.length > 0 && opts.noRuleLoaded?.(failedRules) === true) {
        return {
            toolRun: {
                name: opts.name,
                status: 'failed',
                reason: `${described}: ${describeNoRuleLoaded(failedRules)}`,
                failed_rules: failedRules,
                rule_config_error: true,
            },
            reports,
            reportFiles,
            cancelled,
            nothingScanned: false,
            partial,
            failedRules,
        };
    }
    if (opts.requireScanned === true && !cancelled && failures.length === 0 && batches.length > 0 && scanned === 0) {
        return {
            toolRun: {
                name: opts.name,
                status: 'skipped',
                reason: `${described}: ${opts.name} scanned none of them — no rule applies to these files, ` +
                    'or the rules loaded nothing',
            },
            reports,
            reportFiles,
            cancelled,
            nothingScanned: true,
            partial,
            failedRules,
        };
    }
    let toolRun;
    if (failures.length === 0 && !cancelled) {
        toolRun = {
            name: opts.name,
            status: 'ok',
            reason: [
                `${described} scanned`,
                ...(failedRules.length > 0 ? [describeRulesNotLoaded(failedRules, scanned)] : []),
                ...(partial.length > 0 ? [describePartialParse(partial, 'findings in the unparsed spans may be missing')] : []),
            ].join('; '),
        };
        if (partial.length > 0)
            toolRun.partially_parsed = partial;
        if (failedRules.length > 0)
            toolRun.failed_rules = failedRules;
    }
    else {
        toolRun = {
            name: opts.name,
            status: 'failed',
            reason: cancelled && failures.length === 0 ? 'cancelled' : `${described}: ${failures.join('; ')}`,
        };
        // Every batch failed on its rule configuration: installed, the rules are the problem.
        if (!cancelled && failures.length > 0 && configFailures === failures.length)
            toolRun.rule_config_error = true;
    }
    return { toolRun, reports, reportFiles, cancelled, nothingScanned: false, partial, failedRules };
}
/** `scanFileBatches` for Semgrep: `--json --quiet --output <f> -- files`, UTF-8 mode, GC3 check. */
export function semgrepOnFiles(args) {
    const rules = args.rules;
    const ruleIdOf = rules === undefined ? undefined : localRuleIdNormalizer(rules.configs, rules.ctx);
    return scanFileBatches({
        name: 'semgrep',
        command: 'semgrep',
        args: [...args.configArgs, '--json', '--quiet'],
        reportArgs: (f) => ['--output', f],
        files: args.files,
        cwd: args.cwd,
        reportDir: args.reportDir,
        reportPrefix: 'sast',
        env: pythonUtf8Env(args.env),
        signal: args.signal,
        ...(args.onLog ? { onLog: args.onLog } : {}),
        // The shared judge's `partial` verdict is no failure of the batch, and
        // neither are rules that did not load while the others ran.
        check: (args) => {
            const c = checkSemgrepReport({ ...args, ...(ruleIdOf !== undefined ? { ruleIdOf } : {}) });
            if (c.verdict === 'partial' && c.partial !== undefined) {
                return { ok: true, scanned: c.scanned, partial: c.partial };
            }
            if (c.rules_not_loaded !== undefined && c.rules_not_loaded.length > 0) {
                return { ok: true, scanned: c.scanned, partial: c.partial ?? [], failedRules: c.rules_not_loaded };
            }
            return {
                ok: c.ok,
                scanned: c.scanned,
                ...(c.rule_config_error !== undefined
                    ? { reason: `the rule configuration did not load — ${c.rule_config_error} (semgrep exit ${String(args.exitCode)})` }
                    : c.reason !== undefined
                        ? { reason: c.reason }
                        : {}),
                ...(c.rule_config_error !== undefined ? { ruleConfigError: true } : {}),
            };
        },
        requireScanned: true,
        ...(rules !== undefined ? { noRuleLoaded: (failed) => noRuleLoaded(rules.configs, failed, rules.ctx) } : {}),
    });
}
/** `scanFileBatches` for Bandit: `-f json -o <f> -q -- files`. */
export function banditOnFiles(args) {
    return scanFileBatches({
        name: 'bandit',
        command: 'bandit',
        args: ['-f', 'json', '-q'],
        reportArgs: (f) => ['-o', f],
        files: args.files,
        cwd: args.cwd,
        reportDir: args.reportDir,
        reportPrefix: 'bandit',
        env: pythonUtf8Env(args.env),
        signal: args.signal,
        ...(args.onLog ? { onLog: args.onLog } : {}),
        check: checkBanditReport,
    });
}
/**
 * Bandit exits 0 (clean) or 1 (issues); its report lists files it could not
 * analyse under `errors`, which — like Semgrep's — means the run did not
 * cover what it was given.
 */
export function checkBanditReport(args) {
    if (args.outcome === 'cancelled' || args.outcome === 'timed_out' || args.outcome === 'output_too_large') {
        return { ok: false, reason: `bandit did not finish (${args.outcome})` };
    }
    if (args.exitCode !== 0 && args.exitCode !== 1)
        return { ok: false, reason: `exit ${String(args.exitCode)}` };
    const root = args.raw === null ? null : parseInputAsJson(args.raw);
    if (root === null || typeof root !== 'object')
        return { ok: false, reason: 'bandit wrote no JSON report' };
    const errors = asArray(getProp(root, 'errors')).map((e) => `${getString(e, 'filename') ?? '?'}: ${getString(e, 'reason') ?? 'error'}`);
    if (errors.length > 0)
        return { ok: false, reason: `${errors.length} file(s) not analysed: ${errors.join('; ')}` };
    return { ok: true };
}
//# sourceMappingURL=fileBatchScan.js.map