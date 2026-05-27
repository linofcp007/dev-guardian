/**
 * `scan_deps` — dependency CVE + license scan.
 *
 * Runs Trivy fs with both `vuln` and `license` scanners and writes the
 * JSON report to `.guardian/reports/deps-<scan>/deps.json`. The Trivy
 * parser splits the output into Findings (one per vulnerability + one per
 * risky license) plus CVE rows the factory persists into `cves`.
 *
 * Stack-specific deeper audits (`npm audit`, `pip-audit`, etc.) live in
 * `deps_audit` (Phase 7) so they can also report fix counts.
 */
import { join } from 'node:path';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
registerToolModule(makeScanTool({
    name: 'scan_deps',
    title: 'Dependency vuln + license scan',
    description: 'Run Trivy fs with vuln+license scanners. Findings carry CVE id, severity, ' +
        'and fix version; CVEs are also indexed for the guardian://cves/active resource.',
    scan_type: 'deps',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'deps');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        const trivyBin = await scannerAvailable('trivy');
        if (!trivyBin) {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
            return {
                outcome: 'completed',
                tools_run,
                missing_tools,
                parser_inputs,
                report_paths: [reportDir],
            };
        }
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
        return {
            outcome: result.outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
//# sourceMappingURL=scanDeps.js.map