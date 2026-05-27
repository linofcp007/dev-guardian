/**
 * `scan_iac` — Trivy config against Infrastructure-as-Code.
 *
 * Trivy's `config` subcommand auto-detects Terraform (.tf), Kubernetes
 * manifests, CloudFormation templates, and Helm charts. We hand it the
 * whole project root and let it scan whatever it finds. The IaC detection
 * itself is owned by Trivy, not by us — keeps us decoupled from rule sets
 * Trivy adds in future releases.
 */
import { join } from 'node:path';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
registerToolModule(makeScanTool({
    name: 'scan_iac',
    title: 'IaC config scan (Terraform / K8s / CloudFormation)',
    description: 'Run Trivy config against the project root. Auto-detects Terraform, Kubernetes manifests, ' +
        'CloudFormation templates, and Helm charts.',
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
        const outFile = join(reportDir, 'iac.json');
        const result = await runProcess({
            command: 'trivy',
            args: ['config', '--format', 'json', '--output', outFile, '--quiet', ctx.projectPath],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw)
            parser_inputs.push({ parser: trivyParser, input: raw });
        tools_run.push({
            name: 'trivy-config',
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
//# sourceMappingURL=scanIac.js.map