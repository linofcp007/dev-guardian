/**
 * `scan_iac` — Trivy config against Infrastructure-as-Code, plus zizmor and
 * actionlint against GitHub Actions workflows.
 *
 * Trivy's `config` subcommand auto-detects Terraform (.tf), Kubernetes
 * manifests, CloudFormation templates, and Helm charts. We hand it the
 * whole project root and let it scan whatever it finds. The IaC detection
 * itself is owned by Trivy, not by us — keeps us decoupled from rule sets
 * Trivy adds in future releases.
 *
 * A GitHub Actions workflow is IaC too — it is what actually runs with the
 * repository's secrets — and neither of Trivy's own passes reads it. So,
 * independently of Trivy and, between themselves, run concurrently (neither
 * depends on the other or on Trivy — only on `listWorkflowFiles`), only when
 * `.github/workflows/*.yml` (or `.yaml`) exist:
 *
 *   - zizmor (`--format=json`, `--no-exit-codes`, `--collect=workflows`,
 *     one positional arg per workflow file — see "Explicit paths" below) —
 *     the security-focused auditor: template injection, unpinned `uses:`,
 *     excessive `permissions:`, credential persistence, and the rest of its
 *     rule set.
 *   - actionlint (`-format '{{json .}}'`, `-pyflakes=`, `-shellcheck=`, one
 *     positional arg per workflow file) — workflow schema/expression
 *     correctness, run independently: it catches a class of bug (a
 *     misspelled context, an `${{ }}` referring to nothing) zizmor's own
 *     rule set does not attempt. Its `shellcheck`/`pyflakes` integrations —
 *     linting the shell of a `run:` step, or a `python` step's own script —
 *     are explicitly NOT what this pass checks: `-pyflakes=` and
 *     `-shellcheck=` disable both, because neither underlying linter is in
 *     dev-guardian's tool catalogue and leaving them on would make a
 *     workflow scan's result depend on binaries we never check for.
 *
 * ---- Explicit paths, for both -----------------------------------------
 *
 * Both are handed the exact file list `listWorkflowFiles` computed, never a
 * directory either scanner decides how to walk on its own — zizmor accepts
 * multiple individual input files as separate positional arguments (its own
 * docs' worked example: `zizmor ../example.yml ../other-repo/ …`), so there
 * is no need to hand it the directory and trust its own collection to agree
 * with the fileset that gated whether this pass runs at all. Every other
 * scanner invocation in this codebase follows the same rule.
 *
 * ---- Optional, and never a silent "0 findings" -------------------------
 *
 * When a workflow directory exists but a binary does not, that pass is
 * `skipped`/`not_installed` and added to `missing_tools` (coverage drops to
 * `partial`), the same convention scan_containers uses for hadolint. When
 * there is no `.github/workflows` directory at all, neither runs — recorded
 * as `skipped`/`no_workflows` (never silently absent from `tools_run`,
 * matching scan_containers' own `trivy`/`no_dockerfile_or_image` entry) —
 * and neither counts as a gap: nothing to scan is coverage `full`, per
 * `scanCoverage.ts`'s own rule.
 *
 * ---- One scanner's own anomaly must never erase the others' findings ---
 *
 * `scanToolFactory.ts` discards the ENTIRE `ScanResult` for two specific
 * outcomes — `cancelled` and `output_too_large` — regardless of what the
 * other scanners in this same call already found. `absorbOutcome` below is
 * what keeps a single scanner's own bad day from reaching the top as either:
 * `output_too_large` never propagates at all (zizmor/actionlint's output is
 * captured stdout with a 5 MB cap — see `runWorkflowScanner`'s own file-write
 * below for why that is still inspectable), and `cancelled` propagates only
 * when the call's OWN abort signal actually fired — never inferred from a
 * single scanner's result alone, which is indistinguishable from "one
 * scanner got unlucky" without checking. `timed_out` and a plain `failed`
 * are safe to surface as the scan's own outcome (scanToolFactory marks the
 * scan row `status: 'failed'` for either but still returns the full result),
 * so those pass through unchanged, same as before this comment.
 *
 * ---- report_paths must point at something real -------------------------
 *
 * Trivy writes its own report to a file (`--output`); zizmor and actionlint
 * have no such flag and are read from captured stdout, so `runWorkflowScanner`
 * writes that capture to `reportDir/<name>.json` itself, best-effort,
 * whatever the outcome — a human (or `set_baseline`'s failure path) pointed
 * at `report_paths` always finds a real file for every scanner that actually
 * ran, not just the one (Trivy) that happened to have its own `--output` flag.
 *
 * Findings from both land at `category: 'security'`, `subcategory: 'ci'` —
 * the same `category: 'security'` Trivy's own misconfiguration pass uses,
 * tagged `ci` the way Trivy's own findings are tagged `dockerfile` /
 * `kubernetes` / `terraform` by its `Type` field (trivy.ts's
 * `mapMisconfiguration`).
 */
import { readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';
import { actionlintParser } from '../runners/scannerParsers/actionlint.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { zizmorParser } from '../runners/scannerParsers/zizmor.js';
import { runProcess } from '../runners/processRunner.js';
import { presentProjectFiles, withProjectConfig } from '../runners/repoConfig.js';
import { iacLookingFiles, judgeTrivyConfig } from '../runners/trivyConfig.js';
import { runTrivy } from '../runners/trivyRun.js';
import { trivySkipArgs } from '../platform/guardianIgnore.js';
import { toPosixPath } from '../runners/scannerParsers/index.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
const WORKFLOWS_DIR = '.github/workflows';
const WORKFLOW_EXTENSIONS = ['.yml', '.yaml'];
/**
 * `.github/workflows/*.yml` (or `.yaml`), as paths relative to `projectPath`
 * with forward slashes — what zizmor's own `verbatim_path` reports and what
 * both scanners are handed as positional arguments (see the module doc's
 * "Explicit paths" section). Non-recursive: GitHub itself only ever reads
 * workflows directly inside this directory, never a subdirectory of it.
 *
 * `exclusions` — the project's `.guardianignore` (`platform/guardianIgnore.ts`),
 * or null when it has none — is applied HERE, not left to the factory's own
 * result filter alone: unlike Semgrep/Trivy/Bandit's native `--exclude`
 * flags, zizmor and actionlint have no such flag at all, but this function
 * already builds an explicit file list, so leaving an ignored file OUT of
 * that list before either scanner ever runs is the equivalent mechanism —
 * cheaper (never spawns a process over a file whose findings would be
 * dropped anyway) and, unlike the result filter, also affects whether the
 * pass runs AT ALL: a `.github/workflows` holding only ignored files must
 * read `skipped/no_workflows`, not run the scanners over nothing.
 *
 * Two symlink hazards, both containment-checked the same way
 * `scanContainers.ts`'s own `isInside` checks `dockerfile_path`:
 *
 *   - A symlinked WORKFLOW FILE counts, not just a plain one: `Dirent`
 *     reports a symlink's own type (`isFile()` false, `isSymbolicLink()`
 *     true) regardless of what it points at, so a directory of nothing but
 *     symlinks — a shared workflow template linked in from elsewhere, a
 *     legitimate and not even unusual layout — would otherwise leave
 *     `workflowFiles` empty even though real workflows are right there.
 *     Followed only when it resolves to a regular file INSIDE the project.
 *   - `.github/workflows` ITSELF can be a symlink (or `.github` can), and
 *     `readdirSync` follows symlinks that lie on the path to the directory
 *     it is asked to read — so without a check here, a `.github/workflows`
 *     symlinked to, say, `/etc` would have this function list (and hand to
 *     two scanners) files that are not part of this project at all. Checked
 *     before the directory is ever read.
 */
function listWorkflowFiles(projectPath, exclusions) {
    const dir = join(projectPath, WORKFLOWS_DIR);
    if (!realWithinProject(projectPath, dir, false))
        return [];
    let entries;
    try {
        entries = readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return [];
    }
    const abs = [];
    for (const e of entries) {
        if (!WORKFLOW_EXTENSIONS.some((ext) => e.name.toLowerCase().endsWith(ext)))
            continue;
        const candidate = join(dir, e.name);
        if (e.isFile()) {
            abs.push(candidate);
        }
        else if (e.isSymbolicLink() && realWithinProject(projectPath, candidate, true)) {
            abs.push(candidate);
        }
    }
    const relPaths = abs.map((a) => toPosixPath(relative(projectPath, a))).sort();
    if (exclusions === null)
        return relPaths;
    return relPaths.filter((p) => !exclusions.ignores(p));
}
/**
 * Whether `candidate` (already known to exist) resolves — following any
 * symlink on its own path or at its end — to something inside `root`.
 * `requireFile` additionally requires the resolved target to be a regular
 * file (for a workflow FILE candidate); false for a directory candidate
 * (`.github/workflows` itself), which only needs to resolve inside the
 * project, not be any particular type.
 */
function realWithinProject(root, candidate, requireFile) {
    let real;
    try {
        real = realpathSync.native(candidate);
    }
    catch {
        return false; // does not exist, or a broken link
    }
    if (requireFile) {
        try {
            if (!statSync(real).isFile())
                return false;
        }
        catch {
            return false;
        }
    }
    let realRoot;
    try {
        realRoot = realpathSync.native(root);
    }
    catch {
        return false;
    }
    const rel = relative(realRoot, real);
    return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}
/**
 * The process ran to its own exit: not stopped for a timeout, a cancellation
 * or an oversized output — the same line fileBatchScan's and gitleaksScan's
 * exit-code checks draw.
 */
function finished(outcome) {
    return outcome === 'completed' || outcome === 'failed';
}
/**
 * Runs one workflow scanner (zizmor or actionlint — both read from captured
 * stdout, unlike Trivy's `--output <file>`) and normalises its result. Always
 * persists whatever stdout was captured to `reportDir/<name>.json`,
 * regardless of outcome — see the module doc's "report_paths" section for
 * why: a timed-out or oversized run still leaves something real to inspect,
 * not just a directory holding Trivy's report and nothing else.
 */
async function runWorkflowScanner(spec, ctx, reportDir) {
    const bin = await scannerAvailable(spec.binary);
    if (!bin) {
        return { toolRun: { name: spec.name, status: 'skipped', reason: 'not_installed' }, missing: true };
    }
    const result = await runProcess({
        command: spec.binary,
        args: spec.args,
        cwd: ctx.projectPath,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        onLog: ctx.onLog,
    });
    if (result.stdout.length > 0) {
        try {
            writeFileSync(join(reportDir, `${spec.name}.json`), result.stdout, 'utf8');
        }
        catch {
            // Best-effort: the scan itself never depends on this file existing —
            // only report_paths' truthfulness does, and a write failure here must
            // not fail the scan over a report artifact.
        }
    }
    const honoured = presentProjectFiles(ctx.projectPath, spec.projectConfig.files);
    const named = (run) => withProjectConfig(run, honoured, spec.projectConfig.decides);
    if (spec.isOk(result)) {
        return {
            toolRun: named({ name: spec.name, status: 'ok' }),
            missing: false,
            parserInput: { parser: spec.parser, input: result.stdout },
            // A run its spec accepts is a completed one, whatever the runner
            // called its exit code (actionlint's exit 1 arrives as `failed`).
            processOutcome: 'completed',
        };
    }
    const toolRun = result.outcome === 'completed'
        ? { name: spec.name, status: 'failed' }
        : { name: spec.name, status: 'failed', reason: result.outcome };
    return { toolRun: named(toolRun), missing: false, processOutcome: result.outcome };
}
registerToolModule(makeScanTool({
    name: 'scan_iac',
    title: 'IaC config scan (Terraform / K8s / CloudFormation / GitHub Actions)',
    description: 'Run Trivy config against the project root (Terraform, Kubernetes manifests, CloudFormation ' +
        'templates, Helm charts). When .github/workflows/*.yml exist, also run zizmor (GitHub Actions ' +
        'security auditor: template injection, unpinned actions, excessive permissions) and actionlint ' +
        '(workflow schema/expression correctness), each when installed.',
    scan_type: 'iac',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'iac');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        let anyOutcome = 'completed';
        // See the module doc's "One scanner's own anomaly must never erase
        // the others' findings" section for exactly what this does and does
        // not let through.
        const absorbOutcome = (processOutcome) => {
            if (processOutcome === 'completed')
                return;
            if (processOutcome === 'cancelled') {
                if (ctx.signal.aborted)
                    anyOutcome = 'cancelled';
                return;
            }
            if (processOutcome === 'output_too_large')
                return;
            anyOutcome = processOutcome; // 'timed_out' / 'failed'
        };
        const trivyBin = await scannerAvailable('trivy');
        if (!trivyBin) {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        else {
            const outFile = join(reportDir, 'iac.json');
            // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
            // No --quiet: a file Trivy cannot parse is one ERROR line in its log,
            // and --quiet hides it (runners/trivyConfig.ts, review I3).
            const result = await runTrivy({
                args: ['config', '--format', 'json', '--output', outFile, ...trivySkipArgs(ctx.exclusions)],
                target: ctx.projectPath,
                workDir: reportDir,
                ignoreFrom: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw)
                parser_inputs.push({ parser: trivyParser, input: raw });
            const judged = judgeTrivyConfig({
                name: 'trivy-config',
                run: result,
                raw,
                iacFiles: result.outcome === 'completed' ? iacLookingFiles(ctx.projectPath, ctx.exclusions).files : [],
            });
            tools_run.push(judged.toolRun);
            missing_tools.push(...judged.missing);
            absorbOutcome(result.outcome);
        }
        const workflowFiles = listWorkflowFiles(ctx.projectPath, ctx.exclusions);
        if (workflowFiles.length === 0) {
            // Explicit, never silently absent — mirrors scan_containers' own
            // `trivy`/`no_dockerfile_or_image` entry for "nothing to scan".
            // Neither name goes into `missing_tools`: this is not a gap.
            tools_run.push({ name: 'zizmor', status: 'skipped', reason: 'no_workflows' });
            tools_run.push({ name: 'actionlint', status: 'skipped', reason: 'no_workflows' });
        }
        else {
            // Independent of Trivy and of each other — run concurrently, then
            // apply their results in a fixed order (zizmor, actionlint) so
            // tools_run/missing_tools/parser_inputs never depend on which
            // process happened to finish first.
            const [zizmorRun, actionlintRun] = await Promise.all([
                runWorkflowScanner({
                    name: 'zizmor',
                    binary: 'zizmor',
                    args: ['--format=json', '--no-exit-codes', '--collect=workflows', ...workflowFiles],
                    parser: zizmorParser,
                    // zizmor discovers its config beside the inputs (`rules:` can
                    // disable or ignore an audit).
                    projectConfig: { files: ['zizmor.yml', '.github/zizmor.yml'], decides: 'its rules can disable or ignore audits' },
                    // `--no-exit-codes` collapses the "findings by highest
                    // severity" codes (11-14) into 0; 1/2/3 are still real
                    // errors — see zizmor.ts's own doc comment for the exit-code
                    // table.
                    isOk: (r) => r.outcome === 'completed' && r.exitCode === 0,
                }, ctx, reportDir),
                runWorkflowScanner({
                    name: 'actionlint',
                    binary: 'actionlint',
                    args: ['-pyflakes=', '-shellcheck=', '-format', '{{json .}}', ...workflowFiles],
                    parser: actionlintParser,
                    // actionlint loads the repository's config (`paths: … ignore:`
                    // silences errors by pattern).
                    projectConfig: {
                        files: ['.github/actionlint.yaml', '.github/actionlint.yml'],
                        decides: 'its ignore patterns silence errors',
                    },
                    // exit 0 (no problems) or 1 (problems found) are both a
                    // finished run — same convention as hadolint/jscpd/ruff/
                    // bandit elsewhere. The runner reports EVERY non-zero exit as
                    // `outcome: 'failed'` (processRunner.ts), so exit 1 arrives as
                    // `failed` + 1: requiring `completed` here made actionlint with
                    // findings always a failed pass, its findings unparsed and the
                    // whole iac row failed (Task 24 fix round 1, M7). Only a run
                    // that did not finish is refused on its outcome.
                    isOk: (r) => finished(r.outcome) && (r.exitCode === 0 || r.exitCode === 1),
                }, ctx, reportDir),
            ]);
            for (const run of [zizmorRun, actionlintRun]) {
                tools_run.push(run.toolRun);
                if (run.missing)
                    missing_tools.push(run.toolRun.name);
                if (run.parserInput)
                    parser_inputs.push(run.parserInput);
                if (run.processOutcome !== undefined)
                    absorbOutcome(run.processOutcome);
            }
        }
        return {
            outcome: anyOutcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
//# sourceMappingURL=scanIac.js.map