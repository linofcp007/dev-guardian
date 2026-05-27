/**
 * `bug_hunt` — bug-focused Semgrep scan using curated rule packs.
 *
 * Same shell-out pattern as `scan_sast` but with `--config=p/bugs` and
 * `--config=p/security-audit` instead of `--config=auto`. The post-processing
 * step re-tags findings so they land in the `bug` category (instead of
 * whatever the semgrep metadata says), so the model can ask for
 * "bug-category findings" via resources and get the right slice.
 */
import { join } from 'node:path';
import { z } from 'zod';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { runProcess } from '../runners/processRunner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
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
    title: 'Bug hunt (Semgrep p/bugs + p/security-audit)',
    description: 'Semgrep with curated bug-finding rule packs (p/bugs, p/security-audit). ' +
        'Findings are categorised as `bug` with subcategories like race_condition, null_safety, ' +
        'edge_case, error_handling, memory_leak, off_by_one. Optional `categories` filter ' +
        'restricts the returned subcategories.',
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
        const args = [
            '--config=p/bugs',
            '--config=p/security-audit',
            '--json',
            '--quiet',
            '--output',
            outFile,
        ];
        if (input.auto_fix === true)
            args.push('--autofix');
        args.push(ctx.projectPath);
        const result = await runProcess({
            command: 'semgrep',
            args,
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
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
    },
}));
//# sourceMappingURL=bugHunt.js.map