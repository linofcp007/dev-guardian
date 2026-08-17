/**
 * `bug_hunt` — bug-focused Semgrep scan using curated rule packs.
 *
 * Same shell-out pattern as `scan_sast` but with `--config=p/r2c-bug-scan`
 * and `--config=p/security-audit` instead of `--config=auto`. The
 * post-processing step re-tags findings so they land in the `bug` category
 * (instead of whatever the semgrep metadata says), so the model can ask for
 * "bug-category findings" via resources and get the right slice.
 *
 * `p/r2c-bug-scan` replaces the original `p/bugs`, which was retired from
 * Semgrep's registry (`https://semgrep.dev/c/p/bugs` now 404s) — see the
 * bug_hunt fix report. Registry packs can go away at any time, and a dead
 * `--config=` does not fail gracefully on its own: Semgrep aborts the WHOLE
 * invocation, including any *other* pack passed alongside it, and reports
 * the failure only inside the JSON's `errors[]` array. This file reads that
 * array (`semgrepConfigFailure.ts`) and re-runs with whatever packs still
 * resolve, so one retirement degrades coverage instead of erasing it — and
 * never lets a run that scanned nothing get reported as a clean bug report.
 */
import { join } from 'node:path';
import { z } from 'zod';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { runProcess } from '../runners/processRunner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { describeConfigFailures, findConfigDownloadFailures, survivingPacks, } from './semgrepConfigFailure.js';
import { makeScanTool, } from './scanToolFactory.js';
/**
 * The rule packs `bug_hunt` runs, in the order passed to `--config=`.
 * Exported so tests can assert against the real, current list instead of
 * duplicating the literal pack names.
 */
export const BUG_HUNT_PACKS = ['p/r2c-bug-scan', 'p/security-audit'];
const BUG_SUBCATEGORIES = new Set([
    'race_condition',
    'null_safety',
    'edge_case',
    'error_handling',
    'memory_leak',
    'off_by_one',
]);
/**
 * Wraps the semgrep parser to re-tag every finding as `category=bug` and
 * normalise the subcategory to the BUG_SUBCATEGORIES vocabulary when
 * possible. Fingerprints are recomputed because the original parser ran
 * with `category=security`/`quality`/etc — but tool, rule_id, file_path,
 * line range and snippet are unchanged, so the fingerprint identity stays
 * stable across `bug_hunt` invocations.
 */
const bugCategoryParser = {
    name: semgrepParser.name,
    parse(input, ctx) {
        const out = semgrepParser.parse(input, ctx);
        const recategorised = out.findings.map((f) => recategoriseAsBug(f));
        return { findings: recategorised, cves: out.cves };
    },
};
function recategoriseAsBug(f) {
    const category = 'bug';
    const subcategory = mapSubcategory(f.rule_id ?? '', f.subcategory);
    const refingerprintInput = { tool: f.tool };
    if (f.rule_id !== undefined)
        refingerprintInput.rule_id = f.rule_id;
    if (f.file_path !== undefined)
        refingerprintInput.file_path = f.file_path;
    if (f.line_start !== undefined)
        refingerprintInput.line_start = f.line_start;
    if (f.line_end !== undefined)
        refingerprintInput.line_end = f.line_end;
    if (f.snippet !== undefined)
        refingerprintInput.snippet = f.snippet;
    // Fingerprint inputs are unchanged compared to the security parser, so the
    // hash is stable. Compute once for consistency with the type discipline.
    const fingerprint = computeFingerprint(refingerprintInput);
    return { ...f, category, subcategory, fingerprint };
}
function mapSubcategory(ruleId, existing) {
    const lowered = ruleId.toLowerCase();
    if (/(race|concurren|thread.safety)/.test(lowered))
        return 'race_condition';
    if (/(null|undefined|nullable|none-check)/.test(lowered))
        return 'null_safety';
    if (/(off.by.one|boundary|index.out)/.test(lowered))
        return 'off_by_one';
    if (/(leak|unreleased|unclosed|disposed)/.test(lowered))
        return 'memory_leak';
    if (/(error.handling|swallow|catch.all|exception)/.test(lowered))
        return 'error_handling';
    if (/(edge.case|edge|empty.input|boundary)/.test(lowered))
        return 'edge_case';
    return existing && BUG_SUBCATEGORIES.has(existing) ? existing : existing;
}
registerToolModule(makeScanTool({
    name: 'bug_hunt',
    title: 'Bug hunt (Semgrep p/r2c-bug-scan + p/security-audit)',
    description: 'Semgrep with curated bug-finding rule packs (p/r2c-bug-scan, p/security-audit). ' +
        'Findings are categorised as `bug` with subcategories like race_condition, null_safety, ' +
        'edge_case, error_handling, memory_leak, off_by_one. Optional `categories` filter ' +
        'restricts the returned subcategories. If a pack is retired from the Semgrep registry, ' +
        'the scan re-runs with the packs that still resolve and reports the gap in `missing_tools` ' +
        'rather than silently scanning nothing.',
    scan_type: 'bugs',
    category: 'bug',
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        auto_fix: AutoFix,
        allow_dirty: AllowDirty,
        categories: z
            .array(z.string())
            .optional()
            .describe('Restrict to these bug subcategories (e.g. race_condition, null_safety).'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'bugs');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        const semgrepBin = await scannerAvailable('semgrep');
        if (!semgrepBin) {
            tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('semgrep');
            return {
                outcome: 'completed',
                tools_run,
                missing_tools,
                parser_inputs,
                report_paths: [reportDir],
            };
        }
        const outFile = join(reportDir, 'bugs.json');
        const runWithPacks = (packs) => {
            const args = packs.map((pack) => `--config=${pack}`);
            args.push('--json', '--quiet', '--output', outFile);
            if (input.auto_fix === true)
                args.push('--autofix');
            args.push(ctx.projectPath);
            return runProcess({
                command: 'semgrep',
                args,
                cwd: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
        };
        // A gap that survives every retry attempt: nothing scanned, and that
        // must never be reported as a clean bug report. `outcome: 'completed'`
        // matches scan_sast's convention for an expected, named gap — the
        // signal lives in `missing_tools` / `coverage`, not in `outcome`.
        const reportGap = (failures) => {
            tools_run.push({
                name: 'semgrep',
                status: 'failed',
                reason: `no configured pack could be scanned (${describeConfigFailures(failures)})`,
            });
            for (const f of failures)
                missing_tools.push(`semgrep:${f.pack ?? 'unknown-config'}`);
            return {
                outcome: 'completed',
                tools_run,
                missing_tools,
                parser_inputs,
                report_paths: [reportDir],
            };
        };
        const result = await runWithPacks(BUG_HUNT_PACKS);
        const raw = readJsonSafe(outFile);
        const failures = findConfigDownloadFailures(raw);
        if (failures.length === 0) {
            // The ordinary case: every configured pack resolved. Exit code /
            // outcome alone decide ok-ness here, same as before — there is
            // nothing in errors[] casting doubt on the result.
            if (raw)
                parser_inputs.push({ parser: bugCategoryParser, input: raw });
            const ok = result.outcome === 'completed' || result.exitCode === 1;
            tools_run.push({ name: 'semgrep', status: ok ? 'ok' : 'failed' });
            return {
                outcome: ok ? 'completed' : result.outcome,
                tools_run,
                missing_tools,
                parser_inputs,
                report_paths: [reportDir],
            };
        }
        // At least one configured pack failed to download (registry
        // retirement, outage, typo). A single bad `--config=` aborts the
        // WHOLE invocation — `raw` above has empty results/paths.scanned even
        // for packs that resolved fine — so it cannot be reused as-is. Re-run
        // with whatever survives rather than reporting a scan that covered
        // nothing.
        const survivors = survivingPacks(BUG_HUNT_PACKS, failures);
        if (survivors.length === 0 || survivors.length === BUG_HUNT_PACKS.length) {
            // Nothing to retry with (every pack failed), or the failure(s)
            // could not be attributed to a specific configured pack (so a retry
            // would just reproduce the same result).
            return reportGap(failures);
        }
        const retry = await runWithPacks(survivors);
        const retryRaw = readJsonSafe(outFile);
        const retryFailures = findConfigDownloadFailures(retryRaw);
        const retryOk = retryFailures.length === 0 && (retry.outcome === 'completed' || retry.exitCode === 1);
        if (!retryOk) {
            // The retry didn't help either (network flake, or the "survivor"
            // just got retired too) — combine every failure we saw and refuse
            // to trust either attempt's output.
            return reportGap([...failures, ...retryFailures]);
        }
        if (retryRaw)
            parser_inputs.push({ parser: bugCategoryParser, input: retryRaw });
        tools_run.push({
            name: 'semgrep',
            status: 'ok',
            reason: `ran with ${survivors.join(', ')} only — ${describeConfigFailures(failures)}`,
        });
        for (const f of failures)
            missing_tools.push(`semgrep:${f.pack ?? 'unknown-config'}`);
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
//# sourceMappingURL=bugHunt.js.map