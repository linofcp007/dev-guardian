/**
 * `review_pr` — the scans of a pull request, scoped to what it changes.
 *
 *   - Semgrep over every file the PR adds, copies, modifies or renames
 *     (`git diff -z --diff-filter=ACMR base...head`) that is present in the
 *     working tree, with the same rule sources as `scan_sast`;
 *   - gitleaks over exactly the PR's commits (`--log-opts=<base>..<head>`),
 *     so a secret added in one commit and removed in the next is still found;
 *   - Bandit over the changed `.py` files;
 *   - Trivy over the project when a dependency manifest or lockfile changed.
 *
 * It used to hand a space-joined file list to `scripts/scan/review-scan.sh`,
 * which lost every one of: deleted files (one aborted the whole Semgrep run),
 * paths with spaces (split), non-ASCII paths (git-quoted), long lists (xargs
 * batches overwriting one report), files named `-x` (read as options), and the
 * branch's commits (`gitleaks protect --staged` reads the index). See
 * `runners/git.ts`, `runners/argBatches.ts` and `runners/fileBatchScan.ts`.
 *
 * Refs are resolved before anything runs: an unresolvable `base_ref` (a typo,
 * a `master` repository asked about `main`) is `target_not_found`, never "no
 * files changed". The resolved commit ids are what the scan is keyed and
 * cached by, so a moved branch is a new review, not a stale hit.
 */
import { lstatSync } from 'node:fs';
import { basename, join } from 'node:path';
import { z } from 'zod';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { banditOnFiles, semgrepOnFiles } from '../runners/fileBatchScan.js';
import { changedFiles, git, repoState, resolveCommit } from '../runners/git.js';
import { runGitleaksScan } from '../runners/gitleaksScan.js';
import { runProcess } from '../runners/processRunner.js';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { planSemgrepConfigs } from '../runners/semgrepConfigs.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
/** A change to one of these means the dependency set may have changed. */
const MANIFEST_RE = /^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|composer\.(json|lock)|Gemfile(\.lock)?|Cargo\.(toml|lock)|go\.(mod|sum)|.*\.csproj|packages\.lock\.json|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile)$/;
const reviewPr = makeScanTool({
    name: 'review_pr',
    title: 'Pre-PR diff review',
    description: 'Scan what a pull request changes: Semgrep (same rules as scan_sast) over every added/modified/' +
        'renamed file between base_ref and head_ref, gitleaks over exactly those commits, Bandit over ' +
        'changed .py files, and Trivy when a dependency manifest changed. base_ref defaults to ' +
        'origin/HEAD, then main, then master; head_ref to HEAD. An unresolvable ref is an error, never ' +
        '"no files changed". Pass local_only=true to skip the Semgrep registry (no telemetry).',
    scan_type: 'review_pr',
    category: 'security',
    supportsAutoFix: false,
    rulePacks: (input, { projectPath, plugin }) => planSemgrepConfigs(projectPath, plugin, input.local_only === true).rulePacks,
    inputSchema: {
        project_path: ProjectPath,
        base_ref: z
            .string()
            .optional()
            .describe('Base ref for the diff. Defaults to origin/HEAD, then main, then master.'),
        head_ref: z.string().optional().describe('Head ref. Defaults to HEAD.'),
        local_only: z
            .boolean()
            .optional()
            .describe("Semgrep runs only the project's own rules and registered custom rules, with --metrics=off. " +
            'Default: false.'),
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (input, ctx) => {
        // The handler below resolved both refs to commit ids; re-resolved here so
        // no other caller of `invoke` can pass an unchecked ref to git.
        const base = await resolveCommit(ctx.projectPath, input.base_ref ?? '');
        const head = await resolveCommit(ctx.projectPath, input.head_ref ?? 'HEAD');
        if (base === null || head === null)
            throw new Error('review_pr: base_ref/head_ref do not name commits');
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'review');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        let cancelled = false;
        const changed = await changedFiles(ctx.projectPath, base, head);
        const present = changed.filter((f) => isFileOnDisk(join(ctx.projectPath, f)));
        const notOnDisk = changed.length - present.length;
        // --- Semgrep ---------------------------------------------------------
        if (present.length === 0) {
            tools_run.push({
                name: 'semgrep',
                status: 'skipped',
                reason: changed.length === 0
                    ? 'no changed file between base and head'
                    : `no changed file is present in the working tree (${notOnDisk} missing)`,
            });
        }
        else if (!(await scannerAvailable('semgrep'))) {
            tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('semgrep');
        }
        else {
            const plan = planSemgrepConfigs(ctx.projectPath, ctx.plugin, input.local_only === true);
            if (plan.nothingToRun) {
                tools_run.push({
                    name: 'semgrep',
                    status: 'skipped',
                    reason: 'local_only=true but this project has no local Semgrep rules — nothing to run',
                });
                missing_tools.push('semgrep');
            }
            else {
                const run = await semgrepOnFiles({
                    configArgs: plan.args,
                    files: present,
                    cwd: ctx.projectPath,
                    reportDir,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
                });
                for (const raw of run.reports)
                    parser_inputs.push({ parser: semgrepParser, input: raw });
                const notes = [...plan.notes];
                if (notOnDisk > 0)
                    notes.push(`${notOnDisk} changed path(s) not in the working tree were skipped`);
                tools_run.push(withNotes(run.toolRun, notes));
                // Scanned nothing at all: not a clean result, a gap.
                if (run.nothingScanned)
                    missing_tools.push('semgrep');
                cancelled ||= run.cancelled;
            }
        }
        // --- gitleaks over the PR's commits ----------------------------------
        if (!cancelled) {
            const secrets = await runGitleaksScan({
                projectPath: ctx.projectPath,
                reportDir,
                scope: { kind: 'range', base, head },
                env: ctx.scriptEnv,
                signal: ctx.signal,
                ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
            });
            tools_run.push(...secrets.tools_run);
            missing_tools.push(...secrets.missing_tools);
            parser_inputs.push(...secrets.parser_inputs);
            cancelled ||= secrets.cancelled;
        }
        // --- Bandit over changed Python files --------------------------------
        const python = present.filter((f) => f.toLowerCase().endsWith('.py'));
        if (!cancelled && python.length > 0) {
            if (!(await scannerAvailable('bandit'))) {
                tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('bandit');
            }
            else {
                const run = await banditOnFiles({
                    files: python,
                    cwd: ctx.projectPath,
                    reportDir,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
                });
                for (const raw of run.reports)
                    parser_inputs.push({ parser: banditParser, input: raw });
                tools_run.push(run.toolRun);
                cancelled ||= run.cancelled;
            }
        }
        // --- Trivy when the dependency set changed ---------------------------
        if (!cancelled && changed.some((f) => MANIFEST_RE.test(basename(f)))) {
            if (!(await scannerAvailable('trivy'))) {
                tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('trivy');
            }
            else {
                const outFile = join(reportDir, 'deps.json');
                const run = await runProcess({
                    command: 'trivy',
                    args: ['fs', '--scanners', 'vuln', '--format', 'json', '--output', outFile, '--quiet', ctx.projectPath],
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                const raw = readJsonSafe(outFile);
                if (run.outcome === 'cancelled')
                    cancelled = true;
                if (run.outcome === 'completed' && raw !== null) {
                    parser_inputs.push({ parser: trivyParser, input: raw });
                    tools_run.push({ name: 'trivy', status: 'ok', reason: 'a dependency manifest changed' });
                }
                else {
                    tools_run.push({
                        name: 'trivy',
                        status: 'failed',
                        reason: raw === null ? `no report (${run.outcome}, exit ${String(run.exitCode)})` : run.outcome,
                    });
                }
            }
        }
        return {
            outcome: cancelled ? 'cancelled' : 'completed',
            tools_run,
            missing_tools: [...new Set(missing_tools)],
            parser_inputs,
            report_paths: [reportDir],
            extras: {
                base_sha: base,
                head_sha: head,
                changed_files: changed.length,
                scanned_files: present.length,
            },
        };
    },
});
function isFileOnDisk(path) {
    try {
        return lstatSync(path).isFile();
    }
    catch {
        return false;
    }
}
function withNotes(run, notes) {
    if (notes.length === 0)
        return run;
    return { ...run, reason: [run.reason, ...notes].filter((s) => s !== undefined).join('; ') };
}
/** origin/HEAD, then main, master, origin/main, origin/master — the first that names a commit. */
async function defaultBaseRef(cwd) {
    const originHead = await git(cwd, ['symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD']);
    const candidates = [];
    if (originHead.exitCode === 0)
        candidates.push(originHead.stdout.trim().replace(/^refs\/remotes\//, ''));
    candidates.push('main', 'master', 'origin/main', 'origin/master');
    for (const ref of candidates) {
        if (ref.length > 0 && (await resolveCommit(cwd, ref)) !== null)
            return ref;
    }
    return null;
}
function refused(code, message) {
    return { ok: false, error: { code, message } };
}
const tool = {
    ...reviewPr,
    handler: async (input, plugin, callMeta) => {
        const inp = input;
        let projectPath;
        try {
            projectPath = resolveProjectPath(inp.project_path).path;
        }
        catch (e) {
            // The pipeline reports an invalid project_path itself.
            if (e instanceof InvalidProjectPathError)
                return reviewPr.handler(input, plugin, callMeta);
            throw e;
        }
        const state = await repoState(projectPath);
        if (state.kind === 'not_git') {
            return refused('not_a_git_repo', `${projectPath} is not inside a git repository — there is no diff to review.`);
        }
        if (state.kind === 'error')
            return refused('not_a_git_repo', `git could not read ${projectPath}: ${state.message}`);
        if (state.kind === 'no_commits') {
            return refused('target_not_found', 'The repository has no commits yet — there is no base or head to diff.');
        }
        const headLabel = typeof inp.head_ref === 'string' && inp.head_ref.length > 0 ? inp.head_ref : 'HEAD';
        let baseLabel;
        if (typeof inp.base_ref === 'string' && inp.base_ref.length > 0) {
            baseLabel = inp.base_ref;
        }
        else {
            const found = await defaultBaseRef(projectPath);
            if (found === null) {
                return refused('target_not_found', 'No base ref given and none found (no origin/HEAD, main, master, origin/main or origin/master). ' +
                    'Pass base_ref.');
            }
            baseLabel = found;
        }
        const baseSha = await resolveCommit(projectPath, baseLabel);
        if (baseSha === null)
            return refused('target_not_found', `base_ref "${baseLabel}" does not name a commit.`);
        const headSha = await resolveCommit(projectPath, headLabel);
        if (headSha === null)
            return refused('target_not_found', `head_ref "${headLabel}" does not name a commit.`);
        const result = await reviewPr.handler({ ...input, base_ref: baseSha, head_ref: headSha }, plugin, callMeta);
        return result.ok ? { ...result, base_ref: baseLabel, head_ref: headLabel } : result;
    },
};
registerToolModule(tool);
//# sourceMappingURL=reviewPr.js.map