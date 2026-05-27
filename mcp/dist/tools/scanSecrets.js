/**
 * `scan_secrets` — secret-leak detection via gitleaks.
 *
 * Always runs with `--redact` so the actual secret bytes never reach the
 * MCP wire. The parser strips Match/Secret fields too, but `--redact`
 * is a belt-and-braces guarantee.
 */
import { join } from 'node:path';
import { gitleaksParser } from '../runners/scannerParsers/gitleaks.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
registerToolModule(makeScanTool({
    name: 'scan_secrets',
    title: 'Secret scan (gitleaks)',
    description: 'Detect committed secrets / API keys / tokens with gitleaks. Always runs with --redact ' +
        'so the raw secret never reaches MCP output.',
    scan_type: 'secrets',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'secrets');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        const gitleaksBin = await scannerAvailable('gitleaks');
        if (!gitleaksBin) {
            tools_run.push({ name: 'gitleaks', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('gitleaks');
            return {
                outcome: 'completed',
                tools_run,
                missing_tools,
                parser_inputs,
                report_paths: [reportDir],
            };
        }
        const outFile = join(reportDir, 'secrets.json');
        const result = await runProcess({
            command: 'gitleaks',
            args: [
                'detect',
                '--no-banner',
                '--report-format=json',
                `--report-path=${outFile}`,
                '--redact',
                '-s',
                ctx.projectPath,
            ],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw)
            parser_inputs.push({ parser: gitleaksParser, input: raw });
        // exit 0 = no leaks; exit 1 = leaks found; both are valid runs.
        const ok = result.outcome === 'completed' || result.exitCode === 1;
        tools_run.push({ name: 'gitleaks', status: ok ? 'ok' : 'failed' });
        return {
            outcome: ok ? 'completed' : result.outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
}));
//# sourceMappingURL=scanSecrets.js.map