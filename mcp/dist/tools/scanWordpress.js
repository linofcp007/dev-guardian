/**
 * `scan_wordpress` — WordPress code scan.
 *
 * Source-side scan (no live WP install required). Aggregates:
 *   - Semgrep with `p/php` (and `p/wordpress` if available locally)
 *   - Trivy fs for composer.lock CVEs
 *   - gitleaks for secrets
 *   - PHPCS with `WordPress` standard (when phpcs + WPCS installed)
 *
 * For live-install audits, use `wp_audit`. For WPScan vuln-DB lookup,
 * use `wp_vuln_check`.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { historyState } from '../runners/git.js';
import { runGitleaksScan } from '../runners/gitleaksScan.js';
import { phpcsParser } from '../runners/scannerParsers/phpcs.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
const WP_STANDARDS = ['WordPress', 'WordPress-Core', 'WordPress-Extra', 'WordPress-VIP-Go'];
registerToolModule(makeScanTool({
    name: 'scan_wordpress',
    title: 'WordPress code scan (Semgrep + Trivy + gitleaks + PHPCS-WPCS)',
    description: 'Aggregated source-side scan for a WordPress plugin / theme / site project: Semgrep PHP + ' +
        'WP rule pack, Trivy fs for composer.lock CVEs, gitleaks for secrets, PHPCS WordPress ' +
        'standard. Each scanner that is missing is skipped with reason. Use wp_audit / wp_vuln_check ' +
        'for live-install scenarios.',
    scan_type: 'wordpress',
    // Its secrets pass reads git history: HEAD and every ref join the key.
    cacheState: (_input, { projectPath }) => historyState(projectPath),
    category: 'security',
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        auto_fix: AutoFix,
        allow_dirty: AllowDirty,
        force: Force,
        standard: z
            .enum(WP_STANDARDS)
            .optional()
            .describe('PHPCS standard to apply. Default: WordPress.'),
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'wordpress');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        const inp = input;
        const standard = inp.standard ?? 'WordPress';
        const looksWp = existsSync(join(ctx.projectPath, 'wp-config.php')) ||
            existsSync(join(ctx.projectPath, 'wp-config-sample.php')) ||
            existsSync(join(ctx.projectPath, 'style.css')) || // theme root
            existsSync(join(ctx.projectPath, 'readme.txt')); // plugin/theme readme
        const warnings = [];
        if (!looksWp) {
            warnings.push('not_a_wordpress_project: no wp-config.php / style.css / readme.txt at the root — running generic PHP scans anyway.');
        }
        // The 4 scanners are independent: separate report files, separate
        // CLIs. Run in parallel — wall-clock drops from sum to max.
        const [semgrepBin, trivyBin, phpcsBin] = await Promise.all([
            scannerAvailable('semgrep'),
            scannerAvailable('trivy'),
            scannerAvailable('phpcs'),
        ]);
        const tasks = [];
        if (semgrepBin) {
            tasks.push((async () => {
                const outFile = join(reportDir, 'sast.json');
                const args = [
                    '--config=p/php',
                    '--config=p/wordpress',
                    '--json',
                    '--quiet',
                    '--output',
                    outFile,
                ];
                if (inp.auto_fix === true)
                    args.push('--autofix');
                args.push(ctx.projectPath);
                const r = await runProcess({
                    command: 'semgrep',
                    args,
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                const raw = readJsonSafe(outFile);
                if (raw)
                    parser_inputs.push({ parser: semgrepParser, input: raw });
                const ok = r.outcome === 'completed' || r.exitCode === 1;
                tools_run.push({ name: 'semgrep-wp', status: ok ? 'ok' : 'failed' });
            })());
        }
        else {
            tools_run.push({ name: 'semgrep-wp', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('semgrep');
        }
        // Secrets: history AND uncommitted files (or the whole directory when
        // this is not a git repository — the common case for a WordPress site
        // copied off a server). See runners/gitleaksScan.ts.
        tasks.push((async () => {
            // Inside Promise.all with the other scanners: an exception here
            // must cost the secrets pass, never Semgrep's or Trivy's results.
            try {
                const secrets = await runGitleaksScan({
                    projectPath: ctx.projectPath,
                    reportDir,
                    scope: { kind: 'project' },
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                tools_run.push(...secrets.tools_run);
                missing_tools.push(...secrets.missing_tools);
                parser_inputs.push(...secrets.parser_inputs);
            }
            catch (e) {
                tools_run.push({
                    name: 'gitleaks',
                    status: 'failed',
                    reason: `secret scan failed: ${e instanceof Error ? e.message : String(e)}`,
                });
            }
        })());
        if (trivyBin) {
            tasks.push((async () => {
                const outFile = join(reportDir, 'deps.json');
                const r = await runProcess({
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
                    status: r.outcome === 'completed' ? 'ok' : 'failed',
                });
            })());
        }
        else {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        if (phpcsBin) {
            tasks.push((async () => {
                const outFile = join(reportDir, 'phpcs.json');
                const r = await runProcess({
                    command: 'phpcs',
                    args: [
                        `--standard=${standard}`,
                        '--report=json',
                        `--report-file=${outFile}`,
                        '--extensions=php',
                        ctx.projectPath,
                    ],
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                const raw = readJsonSafe(outFile);
                if (raw)
                    parser_inputs.push({ parser: phpcsParser, input: raw });
                const ok = r.outcome === 'completed' || r.exitCode === 1 || r.exitCode === 2;
                tools_run.push({
                    name: 'phpcs-wpcs',
                    status: ok ? 'ok' : 'failed',
                    reason: ok ? undefined : `phpcs exit ${r.exitCode}`,
                });
            })());
        }
        else {
            tools_run.push({ name: 'phpcs-wpcs', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('phpcs');
        }
        await Promise.all(tasks);
        const extras = { wordpress_layout_detected: looksWp };
        if (warnings.length > 0)
            extras['warnings_extra'] = warnings;
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
            extras,
        };
    },
}));
//# sourceMappingURL=scanWordpress.js.map