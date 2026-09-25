/**
 * `deps_audit` — dependency audit (Trivy + bot detection + stack-specific
 * auditors).
 *
 * Builds on `scan_deps` (same Trivy invocation, plus a manifest-coverage
 * check — see `trivy.ts`'s own module comment for the bare-`.csproj` /
 * bare-`package.json` silent gap it closes) and adds:
 *
 *   - `bot_configured` flag — whether the project already has renovate.json
 *     or .github/dependabot.yml in place;
 *   - `npm audit --json` (npm 7+/6 both supported) parsed into Findings via
 *     `npmAuditParser` — npm's GitHub-advisory coverage is complementary to
 *     Trivy's, so its vulnerabilities are counted rather than merely
 *     captured. To avoid double-counting, an npm finding for a package Trivy
 *     already reported as a CVE is dropped (Trivy is canonical); npm findings
 *     for packages Trivy missed are kept;
 *   - `pip-audit --format json`, run per `requirements*.txt` file (`-r`) when
 *     any exist, else against the project directory for a `pyproject.toml`
 *     project — NEVER bare, which audits whatever Python is on PATH (the MCP
 *     host's own interpreter, not this project's dependencies). Parsed via
 *     `pipAuditParser`;
 *   - `dotnet list <target> package --vulnerable --include-transitive
 *     --format json`, one call per `.sln` (preferred) or `.csproj` found at
 *     the project root, when the .NET SDK is on PATH. **Running this
 *     restores the project first** (`dotnet restore`), which executes the
 *     project's own MSBuild targets — the same trust boundary
 *     `deps_update_plan`'s own dotnet branch already crosses. Parsed via
 *     `dotnetScaParser`. Trivy cannot cover this stack at all without a
 *     `packages.lock.json` (see `trivy.ts`), so this is NuGet's only source
 *     of CVE-adjacent findings, not a complementary one like npm's.
 *
 * All raw outputs are persisted under `.guardian/reports/depsaudit-<scan>/`.
 */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { dotnetScaParser } from '../runners/scannerParsers/dotnetSca.js';
import { NPM_AUDIT_TOOL_NAME, npmAuditParser } from '../runners/scannerParsers/npmAudit.js';
import { pipAuditParser } from '../runners/scannerParsers/pipAudit.js';
import { assessManifestCoverage, TRIVY_TOOL_NAME, trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
/**
 * The package name a scanner encoded in a finding's snippet. Both parsers write
 * `${pkg}@${version…}` (Trivy: `pkg@installed->fixed`; npm: `pkg@range`), so the
 * name is everything before the LAST `@` — which keeps scoped names like
 * `@babel/core` intact. Returns null when no package can be recovered.
 */
function packageFromSnippet(snippet) {
    if (!snippet)
        return null;
    const at = snippet.lastIndexOf('@');
    if (at <= 0)
        return null; // no version marker, or a leading '@' with empty name
    return snippet.slice(0, at).trim().toLowerCase() || null;
}
/**
 * Trivy is the canonical CVE source across stacks; npm audit is here for the
 * GitHub advisories Trivy misses. When both flag the SAME package they are
 * (almost always) the same vulnerability seen twice — Trivy by CVE, npm by
 * GHSA — and npm's finding would otherwise inflate the counts. So we drop each
 * npm-audit finding whose package Trivy already reported as a CVE. npm findings
 * for packages Trivy did NOT flag (its complementary value) are kept.
 */
function dropNpmDuplicatesOfTrivy(findings) {
    const trivyPackages = new Set();
    for (const f of findings) {
        if (f.tool === TRIVY_TOOL_NAME && f.subcategory === 'cve') {
            const pkg = packageFromSnippet(f.snippet);
            if (pkg)
                trivyPackages.add(pkg);
        }
    }
    if (trivyPackages.size === 0)
        return findings;
    return findings.filter((f) => {
        if (f.tool !== NPM_AUDIT_TOOL_NAME)
            return true;
        const pkg = packageFromSnippet(f.snippet);
        return !(pkg !== null && trivyPackages.has(pkg));
    });
}
function detectBots(projectPath) {
    return {
        renovate: existsSync(join(projectPath, 'renovate.json')) ||
            existsSync(join(projectPath, '.renovaterc')) ||
            existsSync(join(projectPath, '.renovaterc.json')),
        dependabot: existsSync(join(projectPath, '.github', 'dependabot.yml')),
    };
}
registerToolModule(makeScanTool({
    name: 'deps_audit',
    title: 'Dependency audit (Trivy + native auditors + bot detection)',
    description: 'Run Trivy fs (vuln+license) plus stack-specific auditors when applicable: npm audit, ' +
        'pip-audit (run against this project\'s own requirements*.txt / pyproject.toml, never the ' +
        'host Python), and `dotnet list package --vulnerable --include-transitive` for any .sln/' +
        '.csproj (this restores the project first, which runs its own MSBuild targets). Returns ' +
        'Findings, indexed CVEs, and a `bot_configured` flag indicating whether Renovate or ' +
        'Dependabot is set up in this repo.',
    // Its own type, not scan_deps' 'deps': the two shared cache entries and
    // answered for each other. Readers that want "the latest deps_audit" use
    // `isDepsAuditScan`, which also recognises the 2.0.x rows typed 'deps'.
    scan_type: 'deps_audit',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'depsaudit');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        // --- Trivy fs (canonical CVE source for all stacks) ---------------
        let manifestCoverageGaps = [];
        const trivyBin = await scannerAvailable('trivy');
        if (trivyBin) {
            const outFile = join(reportDir, 'deps.json');
            const result = await runProcess({
                command: 'trivy',
                args: [
                    'fs',
                    '--scanners',
                    'vuln,license',
                    '--format',
                    'json',
                    '--output',
                    outFile,
                    '--quiet',
                    ctx.projectPath,
                ],
                cwd: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw)
                parser_inputs.push({ parser: trivyParser, input: raw });
            if (result.outcome !== 'completed') {
                tools_run.push({ name: 'trivy', status: 'failed' });
            }
            else {
                // See scanDeps.ts / trivy.ts's own module comment: a manifest
                // Trivy recognises nothing for (e.g. a bare .csproj with no
                // packages.lock.json) must never read as a clean scan.
                const coverage = assessManifestCoverage(ctx.projectPath, raw ?? '');
                manifestCoverageGaps = coverage.gaps;
                if (coverage.gaps.length > 0) {
                    tools_run.push({
                        name: 'trivy',
                        status: coverage.sawAnyResults ? 'ok' : 'skipped',
                        reason: 'no_supported_manifest',
                    });
                    missing_tools.push('trivy');
                }
                else {
                    tools_run.push({ name: 'trivy', status: 'ok' });
                }
            }
        }
        else {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        // --- Native auditors ----------------------------------------------
        // npm audit is parsed into Findings; so is pip-audit, now that it is
        // pointed at this project's own manifests instead of the host Python.
        if (existsSync(join(ctx.projectPath, 'package.json'))) {
            await tryNativeAudit({
                command: 'npm',
                args: ['audit', '--json', '--audit-level=info'],
                outFile: join(reportDir, 'npm-audit.json'),
                ctx,
                tools_run,
                missing_tools,
                parser_inputs,
                parser: npmAuditParser,
            });
        }
        // pip-audit: NEVER invoked bare — a bare `pip-audit` audits whatever
        // Python is on PATH (the MCP host's own interpreter), not this
        // project's dependencies. `-r` per requirements file when any exist;
        // otherwise, for a pyproject.toml-only project, the project directory
        // itself (pip-audit reads its declared dependencies from there).
        const requirementsFiles = findRequirementsFiles(ctx.projectPath);
        const hasPyproject = existsSync(join(ctx.projectPath, 'pyproject.toml'));
        if (requirementsFiles.length > 0 || hasPyproject) {
            const outFile = join(reportDir, 'pip-audit.json');
            const target = requirementsFiles.length > 0
                ? requirementsFiles.flatMap((f) => ['-r', f])
                : [ctx.projectPath];
            await tryNativeAudit({
                command: 'pip-audit',
                args: [...target, '--format', 'json', '-o', outFile],
                outFile,
                ctx,
                tools_run,
                missing_tools,
                parser: pipAuditParser,
                parser_inputs,
            });
        }
        // .NET SCA: Trivy cannot cover NuGet at all without a
        // packages.lock.json (trivy.ts's own module comment), so this is the
        // stack's only source of dependency findings, run whenever a
        // .sln/.csproj exists and the SDK is on PATH.
        await runDotnetSca({ ctx, reportDir, tools_run, missing_tools, parser_inputs });
        const bot_configured = detectBots(ctx.projectPath);
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            dedupeFindings: dropNpmDuplicatesOfTrivy,
            report_paths: [reportDir],
            extras: {
                bot_configured,
                ...(manifestCoverageGaps.length > 0 ? { manifest_coverage_gaps: manifestCoverageGaps } : {}),
            },
        };
    },
}));
/**
 * A real `npm audit --json` report has a `vulnerabilities` (npm 7+) or
 * `advisories` (npm 6) object. When npm cannot audit (no lockfile, config
 * error) it exits non-zero — often with the *same* code 1 it uses for
 * "vulnerabilities found" — and prints an `{ error: … }` object instead. We
 * must not mistake that error for a clean scan, so success is gated on the
 * output actually being a report.
 */
function looksLikeNpmAuditReport(raw) {
    try {
        const j = JSON.parse(raw);
        if (!j || typeof j !== 'object' || 'error' in j)
            return false;
        const isObj = (v) => typeof v === 'object' && v !== null;
        return isObj(j['vulnerabilities']) || isObj(j['advisories']);
    }
    catch {
        return false;
    }
}
async function tryNativeAudit(opts) {
    const bin = await scannerAvailable(opts.command);
    if (!bin) {
        opts.tools_run.push({
            name: opts.command,
            status: 'skipped',
            reason: 'not_installed',
        });
        // The manifest exists but its auditor is absent — a real coverage gap.
        opts.missing_tools?.push(opts.command);
        return;
    }
    const isNpmStdout = opts.command === 'npm';
    const result = await runProcess({
        command: opts.command,
        args: opts.args,
        cwd: opts.ctx.projectPath,
        env: opts.ctx.scriptEnv,
        signal: opts.ctx.signal,
        onLog: opts.ctx.onLog,
    });
    // npm audit writes to stdout; redirect ourselves.
    if (isNpmStdout && result.stdout.length > 0) {
        try {
            const { writeFileSync } = await import('node:fs');
            writeFileSync(opts.outFile, result.stdout, 'utf8');
        }
        catch {
            /* swallow */
        }
    }
    // Exit code 0/1 (or `completed`) is a run that produced output — npm and
    // pip-audit both exit 1 when vulnerabilities are present, which is
    // information, not failure. But npm ALSO exits 1 on a hard error (no
    // lockfile), so for npm we additionally require the output to be a real
    // audit report. An error masquerading as exit 1 must count as a gap, not a
    // clean "0 findings".
    const exitOk = result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
    const ok = isNpmStdout ? exitOk && looksLikeNpmAuditReport(result.stdout) : exitOk;
    // Feed the captured JSON to its parser so the findings are counted. npm
    // prints to stdout; file-output tools (pip-audit) are read back from disk.
    let parsed = false;
    if (ok && opts.parser && opts.parser_inputs) {
        const rawText = isNpmStdout ? result.stdout : readJsonSafe(opts.outFile);
        if (rawText && rawText.length > 0) {
            opts.parser_inputs.push({ parser: opts.parser, input: rawText });
            parsed = true;
        }
    }
    if (ok) {
        opts.tools_run.push({
            name: opts.command,
            status: 'ok',
            reason: parsed ? 'parsed into findings' : 'captured (evidence only)',
        });
    }
    else {
        const reason = isNpmStdout && exitOk
            ? 'ran but produced no audit report (missing lockfile?)'
            : 'failed to run';
        opts.tools_run.push({ name: opts.command, status: 'failed', reason });
        // A failed auditor is a coverage gap — surface it so the roll-up and the
        // executive summary do not read the result as fully covered.
        opts.missing_tools?.push(opts.command);
    }
}
// --------------------------------------------------------------- pip-audit target
/**
 * `requirements*.txt` at the project root, plus one level into a
 * `requirements/` directory (the common `requirements/base.txt` +
 * `requirements/dev.txt` split) — never a recursive walk, matching this
 * file's other manifest checks (`package.json`, `pyproject.toml`), which are
 * root-level existence checks too. Each one becomes its own `-r` flag on a
 * single `pip-audit` invocation; pip-audit accepts multiple `-r` in one call.
 */
function findRequirementsFiles(projectPath) {
    const out = [];
    let entries = [];
    try {
        entries = readdirSync(projectPath);
    }
    catch {
        return out;
    }
    for (const name of entries) {
        if (/^requirements.*\.txt$/i.test(name))
            out.push(join(projectPath, name));
    }
    const reqDir = join(projectPath, 'requirements');
    if (existsSync(reqDir)) {
        try {
            for (const name of readdirSync(reqDir)) {
                if (name.toLowerCase().endsWith('.txt'))
                    out.push(join(reqDir, name));
            }
        }
        catch {
            /* ignore — best-effort */
        }
    }
    return out;
}
// --------------------------------------------------------------- .NET SCA
const DOTNET_SKIP_DIRS = new Set(['bin', 'obj', 'node_modules', '.git', '.guardian', 'packages', '.vs']);
/**
 * The target(s) `dotnet list package --vulnerable` should be run against: a
 * `.sln` at the project root when one exists (covers every project it
 * references in a single call), otherwise every `.csproj` found by a bounded
 * recursive walk (same `SKIP_DIRS` shape as
 * `dotnetTargetFrameworkCheck.ts#collectCsprojFiles`, duplicated rather than
 * imported — that module is owned by a different tool and this one's job is
 * narrower: vulnerable NuGet packages, not target-framework EOL).
 */
function findDotnetTargets(projectPath) {
    let rootEntries = [];
    try {
        rootEntries = readdirSync(projectPath);
    }
    catch {
        return [];
    }
    const sln = rootEntries.find((n) => n.toLowerCase().endsWith('.sln'));
    if (sln)
        return [join(projectPath, sln)];
    const out = [];
    const maxDepth = 4;
    function walk(dir, depth) {
        if (depth > maxDepth)
            return;
        let entries;
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const name of entries) {
            if (DOTNET_SKIP_DIRS.has(name))
                continue;
            const abs = join(dir, name);
            let isDir;
            try {
                isDir = statSync(abs).isDirectory();
            }
            catch {
                continue;
            }
            if (isDir)
                walk(abs, depth + 1);
            else if (name.toLowerCase().endsWith('.csproj'))
                out.push(abs);
        }
    }
    walk(projectPath, 0);
    return out;
}
/**
 * Runs `dotnet list <target> package --vulnerable --include-transitive
 * --format json` for every target `findDotnetTargets` finds, restoring each
 * one first (`dotnet list package` requires a resolved `project.assets.json`
 * — restoring runs the project's own MSBuild targets, same trust boundary
 * `deps_update_plan`'s dotnet branch already crosses). A target whose
 * restore fails is one coverage gap, not a whole-scan failure — the other
 * targets still run.
 */
async function runDotnetSca(opts) {
    const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = opts;
    const targets = findDotnetTargets(ctx.projectPath);
    if (targets.length === 0)
        return; // no .csproj/.sln — nothing to do, not a gap
    const dotnetBin = await scannerAvailable('dotnet');
    if (!dotnetBin) {
        tools_run.push({ name: 'dotnet', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('dotnet');
        return;
    }
    let anyOk = false;
    let anyFailed = false;
    for (const [i, target] of targets.entries()) {
        const restore = await runProcess({
            command: 'dotnet',
            args: ['restore', target, '--nologo', '--verbosity', 'quiet'],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        if (restore.outcome !== 'completed') {
            anyFailed = true;
            continue;
        }
        const list = await runProcess({
            command: 'dotnet',
            args: ['list', target, 'package', '--vulnerable', '--include-transitive', '--format', 'json'],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        if (list.outcome === 'completed' && list.stdout.trim().length > 0) {
            anyOk = true;
            parser_inputs.push({ parser: dotnetScaParser, input: list.stdout });
            try {
                const { writeFileSync } = await import('node:fs');
                writeFileSync(join(reportDir, `dotnet-list-${i}.json`), list.stdout, 'utf8');
            }
            catch {
                /* best-effort evidence copy */
            }
        }
        else {
            anyFailed = true;
        }
    }
    if (anyOk) {
        tools_run.push({
            name: 'dotnet',
            status: 'ok',
            reason: anyFailed
                ? 'parsed into findings (restore or list failed for at least one target)'
                : 'parsed into findings',
        });
        if (anyFailed)
            missing_tools.push('dotnet');
    }
    else {
        tools_run.push({ name: 'dotnet', status: 'failed', reason: 'restore or list package failed for every target' });
        missing_tools.push('dotnet');
    }
}
//# sourceMappingURL=depsAudit.js.map