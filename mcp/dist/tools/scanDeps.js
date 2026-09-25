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
import { assessManifestCoverage, trivyParser } from '../runners/scannerParsers/trivy.js';
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
        const extras = {};
        if (result.outcome !== 'completed') {
            tools_run.push({ name: 'trivy', status: 'failed' });
        }
        else {
            const coverage = assessManifestCoverage(ctx.projectPath, raw ?? '');
            if (coverage.gaps.length > 0) {
                // A manifest Trivy recognises nothing for (e.g. a bare .csproj with
                // no packages.lock.json) must never read as a clean scan — see
                // trivy.ts's own module comment. `skipped` when Trivy's whole
                // Results array was empty (it ran, but covered nothing this
                // project has); `ok` with a reason when SOME ecosystems were
                // covered and this one specifically was not.
                tools_run.push({
                    name: 'trivy',
                    status: coverage.sawAnyResults ? 'ok' : 'skipped',
                    reason: 'no_supported_manifest',
                });
                missing_tools.push('trivy');
                extras['manifest_coverage_gaps'] = coverage.gaps;
            }
            else {
                tools_run.push({ name: 'trivy', status: 'ok' });
            }
        }
        return {
            outcome: result.outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
            ...(Object.keys(extras).length > 0 ? { extras } : {}),
        };
    },
}));
//# sourceMappingURL=scanDeps.js.map