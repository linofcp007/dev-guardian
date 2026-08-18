/**
 * `scan_sast` — Semgrep-only static analysis (plus Bandit when Python is
 * present).
 *
 * Invokes Semgrep directly (no shell script), writing the JSON report to
 * `.guardian/reports/sast-<short-scan-id>/sast.json`. Bandit, if installed
 * and Python sources are detected, is run in the same pass.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { securityCodeScanParser } from '../runners/scannerParsers/securityCodeScan.js';
import { runProcess } from '../runners/processRunner.js';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE, } from '../runners/dockerScanner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { resolveCustomSemgrepConfigs } from '../platform/customRules.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
registerToolModule(makeScanTool({
    name: 'scan_sast',
    title: 'SAST scan (Semgrep)',
    description: 'Static analysis with Semgrep against the project (config=auto). ' +
        'Also runs Bandit when Python files are present and the CLI is installed. ' +
        'Output JSON is written to .guardian/reports/sast-<scan>/ and parsed into Findings.',
    scan_type: 'sast',
    category: 'security',
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        auto_fix: AutoFix,
        allow_dirty: AllowDirty,
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'sast');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        const autoFix = input.auto_fix === true;
        // --- Semgrep -----------------------------------------------------
        const semgrepBin = await scannerAvailable('semgrep');
        // C# / .NET signal: when csproj exists, also pin p/csharp rule pack.
        const hasCsproj = anyCsprojInProject(ctx.projectPath);
        const outFile = join(reportDir, 'sast.json');
        if (semgrepBin) {
            const args = ['--config=auto'];
            if (hasCsproj)
                args.push('--config=p/csharp');
            // The project's own registered rules (register_custom_rules). Vanished
            // paths are dropped by the resolver, because a --config that fails to
            // resolve aborts the WHOLE semgrep run, not just that pack.
            for (const cfg of resolveCustomSemgrepConfigs(ctx.plugin)) {
                args.push(`--config=${cfg}`);
            }
            args.push('--json', '--quiet', '--output', outFile);
            if (autoFix)
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
            if (raw) {
                parser_inputs.push({ parser: semgrepParser, input: raw });
            }
            // exit 0 = no findings; exit 1 = findings present; both are OK.
            const ok = result.outcome === 'completed' || result.exitCode === 1;
            tools_run.push({ name: 'semgrep', status: ok ? 'ok' : 'failed' });
            if (!ok && result.stderr) {
                // Surface the first stderr line for diagnostics.
                const reason = result.stderr.split(/\r?\n/)[0] ?? 'unknown';
                tools_run[tools_run.length - 1].reason = reason;
            }
        }
        else {
            // Semgrep not on PATH — fall back to the official Docker image when a
            // daemon is reachable. This is what makes a SAST scan actually run on
            // hosts where the user only has Semgrep via Docker. If the Docker
            // attempt fails (no image, offline, daemon down), we record it as
            // failed + missing so coverage is honestly 'none' rather than a silent
            // "0 findings".
            const dockerBin = await scannerAvailable('docker');
            if (dockerBin) {
                const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
                const args = buildSemgrepDockerArgs({
                    projectPath: ctx.projectPath,
                    outFileHost: outFile,
                    hasCsproj,
                    autoFix,
                    image,
                });
                const result = await runProcess({
                    command: 'docker',
                    args,
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                const raw = readJsonSafe(outFile);
                if (raw)
                    parser_inputs.push({ parser: semgrepParser, input: raw });
                // exit 0/1 AND a report file means Semgrep actually ran in the
                // container. Anything else (image pull failed, daemon down) is a
                // real coverage gap, not a clean scan.
                const ranInDocker = (result.outcome === 'completed' || result.exitCode === 1) && raw !== null;
                if (ranInDocker) {
                    tools_run.push({
                        name: 'semgrep',
                        status: 'ok',
                        reason: `ran via docker (${image})`,
                    });
                }
                else {
                    const reason = result.stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ??
                        'docker fallback failed';
                    tools_run.push({ name: 'semgrep', status: 'failed', reason: `docker: ${reason}` });
                    missing_tools.push('semgrep');
                }
            }
            else {
                tools_run.push({
                    name: 'semgrep',
                    status: 'skipped',
                    reason: 'not_installed (no docker fallback available)',
                });
                missing_tools.push('semgrep');
            }
        }
        // --- Bandit ------------------------------------------------------
        // Only attempt Bandit when the project obviously has Python sources.
        const looksPython = existsSync(join(ctx.projectPath, 'pyproject.toml')) ||
            existsSync(join(ctx.projectPath, 'requirements.txt')) ||
            existsSync(join(ctx.projectPath, 'setup.py'));
        if (looksPython) {
            const banditBin = await scannerAvailable('bandit');
            if (banditBin) {
                const outFile = join(reportDir, 'bandit.json');
                const result = await runProcess({
                    command: 'bandit',
                    args: ['-r', ctx.projectPath, '-f', 'json', '-o', outFile, '-q'],
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                const raw = readJsonSafe(outFile);
                if (raw)
                    parser_inputs.push({ parser: banditParser, input: raw });
                // Bandit returns 1 when issues are found; treat as ok.
                const ok = result.outcome === 'completed' || result.exitCode === 1;
                tools_run.push({ name: 'bandit', status: ok ? 'ok' : 'failed' });
            }
            else {
                tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('bandit');
            }
        }
        // --- security-code-scan (Roslyn analyzer) -----------------------
        // Only fires when csproj refs `security-code-scan` already — we never
        // mutate user .csproj files. If the project opted-in, run dotnet build
        // and harvest the SCS#### lines from the log.
        if (hasCsproj && csprojReferencesScs(ctx.projectPath)) {
            const dotnetBin = await scannerAvailable('dotnet');
            if (dotnetBin) {
                const result = await runProcess({
                    command: 'dotnet',
                    args: ['build', '--no-incremental', '--verbosity:diag', ctx.projectPath],
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                    timeoutMs: 10 * 60_000,
                });
                // Parse SCS lines from stdout (build log).
                parser_inputs.push({ parser: securityCodeScanParser, input: result.stdout });
                tools_run.push({
                    name: 'security-code-scan',
                    status: result.outcome === 'completed' || result.exitCode === 1 ? 'ok' : 'failed',
                    reason: result.outcome === 'completed'
                        ? undefined
                        : (result.stderr.split(/\r?\n/)[0] ?? 'dotnet build failed'),
                });
            }
            else {
                tools_run.push({
                    name: 'security-code-scan',
                    status: 'skipped',
                    reason: 'dotnet SDK not installed',
                });
                missing_tools.push('dotnet-sdk');
            }
        }
        const anyOk = tools_run.some((t) => t.status === 'ok');
        const outcome = anyOk ? 'completed' : missing_tools.length > 0 ? 'completed' : 'failed';
        return {
            outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
function anyCsprojInProject(projectPath) {
    try {
        return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.fsproj'));
    }
    catch {
        return false;
    }
}
function csprojReferencesScs(projectPath) {
    // Cheap check: scan the first-level *.csproj files for the
    // security-code-scan package name. We don't recurse — projects opting in
    // typically put the analyzer ref at the root csproj or a Directory.Build.props.
    let csprojs;
    try {
        csprojs = readdirSync(projectPath).filter((n) => n.endsWith('.csproj'));
    }
    catch {
        return false;
    }
    for (const file of csprojs) {
        try {
            const xml = readFileSync(join(projectPath, file), 'utf8');
            if (/security[-_]?code[-_]?scan/i.test(xml))
                return true;
        }
        catch {
            /* ignore */
        }
    }
    // Also check Directory.Build.props if present.
    const dbProps = join(projectPath, 'Directory.Build.props');
    if (existsSync(dbProps)) {
        try {
            const xml = readFileSync(dbProps, 'utf8');
            if (/security[-_]?code[-_]?scan/i.test(xml))
                return true;
        }
        catch {
            /* ignore */
        }
    }
    return false;
}
//# sourceMappingURL=scanSast.js.map