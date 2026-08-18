/**
 * `security_scan_full` — orchestrated security scan.
 *
 * Invokes the existing `scripts/scan/full-security-scan.sh` (Semgrep +
 * gitleaks + Trivy fs + Bandit when Python detected + Trivy on Dockerfile
 * when present). The script writes JSON reports to
 * `.guardian/reports/security-<TS>/`; we locate that directory after the
 * run and feed each report file to its parser.
 *
 * The factory handles caching, persistence, severity filtering, and the
 * MCP response shape. This file only knows about file layout and parser
 * routing.
 */
import { join } from 'node:path';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { gitleaksParser } from '../runners/scannerParsers/gitleaks.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runShellScript } from '../runners/shellRunner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { registerToolModule } from './index.js';
import { findNewestDir, readJsonSafe } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
const SCRIPT_REL_PATH = ['scan', 'full-security-scan.sh'];
const ROUTES = [
    { filename: 'sast.json', toolName: 'semgrep', parser: semgrepParser },
    { filename: 'secrets.json', toolName: 'gitleaks', parser: gitleaksParser },
    { filename: 'deps.json', toolName: 'trivy', parser: trivyParser },
    { filename: 'dockerfile.json', toolName: 'trivy-dockerfile', parser: trivyParser },
    { filename: 'bandit.json', toolName: 'bandit', parser: banditParser },
];
registerToolModule(makeScanTool({
    name: 'security_scan_full',
    title: 'Full security scan',
    description: 'Run the full open-source security toolchain (Semgrep, gitleaks, Trivy, Bandit when applicable). ' +
        'Returns a scan_id, severity counts, the top findings, and the report directory.',
    scan_type: 'security_full',
    category: 'security',
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        auto_fix: AutoFix,
        allow_dirty: AllowDirty,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        // Capture the start time so we can locate the script's timestamped
        // output directory by mtime, not by name parsing.
        const startedAt = Date.now() - 1000;
        const scriptPath = join(ctx.plugin.scriptsDir, ...SCRIPT_REL_PATH);
        // `scanToolFactory` already rejects a null shell with `no_bash_shell`
        // before invoke runs, so this cannot fire — narrowed rather than
        // asserted so the compiler keeps enforcing that guarantee if the
        // factory's ordering ever changes. A throw here is a defined path:
        // the factory finalises the scan as `scanner_failed`.
        const shell = ctx.plugin.shell;
        if (shell === null)
            throw new Error('no usable bash shell');
        const shellResult = await runShellScript({
            shell,
            scriptPath,
            args: [ctx.projectPath],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const reportsRoot = join(ctx.projectPath, '.guardian', 'reports');
        const reportDir = findNewestDir(reportsRoot, 'security-', startedAt);
        const parser_inputs = [];
        const tools_run = [];
        const missing_tools = [];
        for (const route of ROUTES) {
            const path = reportDir ? join(reportDir, route.filename) : null;
            const raw = path ? readJsonSafe(path) : null;
            if (raw) {
                parser_inputs.push({ parser: route.parser, input: raw });
                tools_run.push({ name: route.toolName, status: 'ok' });
            }
            else if (route.toolName === 'trivy-dockerfile' || route.toolName === 'bandit') {
                // These two are conditional in the script (only run when a
                // Dockerfile or Python files are present). Missing JSON means
                // "not applicable" rather than "not installed" — don't surface
                // them in missing_tools.
            }
            else {
                tools_run.push({ name: route.toolName, status: 'skipped', reason: 'not_installed' });
                missing_tools.push(route.toolName);
            }
        }
        const result = {
            outcome: shellResult.outcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: reportDir ? [reportDir] : [],
        };
        if (shellResult.outcome !== 'completed' && shellResult.stderr) {
            result.error = shellResult.stderr.split(/\r?\n/).slice(-5).join('\n');
        }
        return result;
    },
}));
//# sourceMappingURL=securityScanFull.js.map