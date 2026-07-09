/**
 * `deps_audit` — dependency audit (Trivy + bot detection + optional
 * stack-specific auditors).
 *
 * Builds on `scan_deps` (same Trivy invocation) and adds:
 *   - `bot_configured` flag — whether the project already has renovate.json
 *     or .github/dependabot.yml in place;
 *   - `npm audit --json` (npm 7+/6 both supported) parsed into Findings via
 *     `npmAuditParser` — npm's GitHub-advisory coverage is complementary to
 *     Trivy's, so its vulnerabilities are now counted rather than merely
 *     captured. To avoid double-counting, an npm finding for a package Trivy
 *     already reported as a CVE is dropped (Trivy is canonical); npm findings
 *     for packages Trivy missed are kept. `pip-audit -f json` is still captured
 *     as evidence only (no parser yet). All raw outputs are persisted under
 *     .guardian/reports/depsaudit-<scan>/. Adding the pip-audit parser later
 *     is the same one-line wiring used for npm here.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { NPM_AUDIT_TOOL_NAME, npmAuditParser } from '../runners/scannerParsers/npmAudit.js';
import { TRIVY_TOOL_NAME, trivyParser } from '../runners/scannerParsers/trivy.js';
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
    description: 'Run Trivy fs (vuln+license) plus stack-specific auditors (npm audit, pip-audit) when ' +
        'applicable. Returns Findings, indexed CVEs, and a `bot_configured` flag indicating whether ' +
        'Renovate or Dependabot is set up in this repo.',
    scan_type: 'deps',
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
            tools_run.push({
                name: 'trivy',
                status: result.outcome === 'completed' ? 'ok' : 'failed',
            });
        }
        else {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        // --- Native auditors ----------------------------------------------
        // npm audit is parsed into Findings; pip-audit is captured as evidence.
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
        if (existsSync(join(ctx.projectPath, 'pyproject.toml')) ||
            existsSync(join(ctx.projectPath, 'requirements.txt'))) {
            await tryNativeAudit({
                command: 'pip-audit',
                args: ['-f', 'json', '-o', join(reportDir, 'pip-audit.json')],
                outFile: join(reportDir, 'pip-audit.json'),
                ctx,
                tools_run,
                missing_tools,
            });
        }
        const bot_configured = detectBots(ctx.projectPath);
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            dedupeFindings: dropNpmDuplicatesOfTrivy,
            report_paths: [reportDir],
            extras: { bot_configured },
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
//# sourceMappingURL=depsAudit.js.map