/**
 * `scan_containers` — Trivy on Dockerfile and/or container images.
 *
 * Strategy:
 *   - If `dockerfile_path` is given (or a `Dockerfile` exists at project
 *     root), run `trivy config --format json --output … <dockerfile>`.
 *   - If `image` is given, run `trivy image --format json --output … <image>`.
 *   - Both can be requested in the same call; outputs land in
 *     `.guardian/reports/containers-<scan>/`.
 *
 * Returns `tools_run` with one entry per scanner pass (dockerfile / image).
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
registerToolModule(makeScanTool({
    name: 'scan_containers',
    title: 'Container scan (Dockerfile + image)',
    description: 'Run Trivy against a Dockerfile (config check) and/or a container image (vulnerability check). ' +
        'If neither dockerfile_path nor image is provided, scans ./Dockerfile when present.',
    scan_type: 'containers',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        dockerfile_path: z
            .string()
            .optional()
            .describe('Path to a Dockerfile to scan with `trivy config`.'),
        image: z
            .string()
            .optional()
            .describe('Container image reference to scan with `trivy image`.'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'containers');
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
        const inp = input;
        const dockerfile = inp.dockerfile_path ??
            (existsSync(join(ctx.projectPath, 'Dockerfile'))
                ? join(ctx.projectPath, 'Dockerfile')
                : undefined);
        let anyOutcome = 'completed';
        if (dockerfile) {
            const outFile = join(reportDir, 'dockerfile.json');
            const result = await runProcess({
                command: 'trivy',
                args: ['config', '--format', 'json', '--output', outFile, '--quiet', dockerfile],
                cwd: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw)
                parser_inputs.push({ parser: trivyParser, input: raw });
            tools_run.push({
                name: 'trivy-dockerfile',
                status: result.outcome === 'completed' ? 'ok' : 'failed',
            });
            if (result.outcome !== 'completed')
                anyOutcome = result.outcome;
        }
        if (inp.image) {
            const outFile = join(reportDir, 'image.json');
            const result = await runProcess({
                command: 'trivy',
                args: [
                    'image',
                    '--format',
                    'json',
                    '--output',
                    outFile,
                    '--quiet',
                    '--scanners',
                    'vuln',
                    inp.image,
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
                name: 'trivy-image',
                status: result.outcome === 'completed' ? 'ok' : 'failed',
            });
            if (result.outcome !== 'completed')
                anyOutcome = result.outcome;
        }
        if (tools_run.length === 0) {
            // No Dockerfile, no image — nothing to scan.
            tools_run.push({
                name: 'trivy',
                status: 'skipped',
                reason: 'no_dockerfile_or_image',
            });
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
//# sourceMappingURL=scanContainers.js.map