/**
 * `quality_check` — code-quality scan.
 *
 * Invokes `scripts/scan/quality-scan.sh`, then parses whichever JSON reports
 * the script produced:
 *
 *   - `dup/jscpd-report.json` → jscpd parser (duplication)
 *   - `ruff.json`             → ruff parser (Python lint / smells)
 *   - eslint.json, complexity-py.json, staticcheck.json → recognised but
 *     not parsed in this version; surfaced in `tools_run` as `ok`
 *     without findings. Add dedicated parsers later if the data becomes
 *     valuable enough to model on.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { jscpdParser } from '../runners/scannerParsers/jscpd.js';
import { ruffParser } from '../runners/scannerParsers/ruff.js';
import { runShellScript } from '../runners/shellRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
import { findNewestDir, readJsonSafe } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
const SCRIPT_REL_PATH = ['scan', 'quality-scan.sh'];
registerToolModule(makeScanTool({
    name: 'quality_check',
    title: 'Code quality scan',
    description: 'Run the open-source quality toolchain (jscpd, ruff, optional eslint/radon/staticcheck) ' +
        'via scripts/scan/quality-scan.sh. Findings cover duplication and language-specific code smells.',
    scan_type: 'quality',
    category: 'quality',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        categories: z
            .array(z.enum(['duplicate', 'complexity', 'smell', 'naming']))
            .optional()
            .describe('Restrict findings to these quality subcategories.'),
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const startedAt = Date.now() - 1000;
        const scriptPath = join(ctx.plugin.scriptsDir, ...SCRIPT_REL_PATH);
        const shellResult = await runShellScript({
            shell: ctx.plugin.shell,
            scriptPath,
            args: [ctx.projectPath],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const reportsRoot = join(ctx.projectPath, '.guardian', 'reports');
        const reportDir = findNewestDir(reportsRoot, 'quality-', startedAt);
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        if (reportDir) {
            // jscpd writes into a subdirectory (`dup/`). The actual report file
            // is `jscpd-report.json` under that subdir.
            const dupDir = join(reportDir, 'dup');
            if (existsSync(dupDir)) {
                const candidate = readdirSync(dupDir).find((n) => /jscpd.*\.json$/.test(n));
                const path = candidate ? join(dupDir, candidate) : null;
                const raw = path ? readJsonSafe(path) : null;
                if (raw) {
                    parser_inputs.push({ parser: jscpdParser, input: raw });
                    tools_run.push({ name: 'jscpd', status: 'ok' });
                }
            }
            const ruffPath = join(reportDir, 'ruff.json');
            const ruffRaw = readJsonSafe(ruffPath);
            if (ruffRaw) {
                parser_inputs.push({ parser: ruffParser, input: ruffRaw });
                tools_run.push({ name: 'ruff', status: 'ok' });
            }
            // Recognised but unparsed in this version.
            for (const f of ['eslint.json', 'staticcheck.json', 'complexity-py.json']) {
                if (readJsonSafe(join(reportDir, f))) {
                    tools_run.push({
                        name: f.replace('.json', ''),
                        status: 'ok',
                        reason: 'present but no MCP parser yet',
                    });
                }
            }
        }
        // If the script ran but no scanners reported, surface them as missing.
        if (tools_run.length === 0) {
            missing_tools.push('jscpd', 'ruff');
            tools_run.push({ name: 'jscpd', status: 'skipped', reason: 'not_installed' }, { name: 'ruff', status: 'skipped', reason: 'not_installed' });
        }
        return {
            outcome: shellResult.outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: reportDir ? [reportDir] : [],
        };
    },
}));
//# sourceMappingURL=qualityCheck.js.map