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
import { gitleaksParser } from '../runners/scannerParsers/gitleaks.js';
import { phpcsParser } from '../runners/scannerParsers/phpcs.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import {
  AllowDirty,
  AutoFix,
  Force,
  ProjectPath,
  SeverityMin,
} from '../schemas.js';
import type { ToolRun } from '../types.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

const WP_STANDARDS = ['WordPress', 'WordPress-Core', 'WordPress-Extra', 'WordPress-VIP-Go'] as const;

registerToolModule(
  makeScanTool({
    name: 'scan_wordpress',
    title: 'WordPress code scan (Semgrep + Trivy + gitleaks + PHPCS-WPCS)',
    description:
      'Aggregated source-side scan for a WordPress plugin / theme / site project: Semgrep PHP + ' +
      'WP rule pack, Trivy fs for composer.lock CVEs, gitleaks for secrets, PHPCS WordPress ' +
      'standard. Each scanner that is missing is skipped with reason. Use wp_audit / wp_vuln_check ' +
      'for live-install scenarios.',
    scan_type: 'wordpress' as never,
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
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'wordpress');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];
      const inp = input as { standard?: typeof WP_STANDARDS[number]; auto_fix?: boolean };
      const standard = inp.standard ?? 'WordPress';

      const looksWp =
        existsSync(join(ctx.projectPath, 'wp-config.php')) ||
        existsSync(join(ctx.projectPath, 'wp-config-sample.php')) ||
        existsSync(join(ctx.projectPath, 'style.css')) || // theme root
        existsSync(join(ctx.projectPath, 'readme.txt')); // plugin/theme readme
      const warnings: string[] = [];
      if (!looksWp) {
        warnings.push(
          'not_a_wordpress_project: no wp-config.php / style.css / readme.txt at the root — running generic PHP scans anyway.',
        );
      }

      // --- Semgrep (PHP + WordPress rule pack) ----------------------------
      const semgrepBin = await scannerAvailable('semgrep');
      if (semgrepBin) {
        const outFile = join(reportDir, 'sast.json');
        const args = [
          '--config=p/php',
          '--config=p/wordpress',
          '--json',
          '--quiet',
          '--output',
          outFile,
        ];
        if (inp.auto_fix === true) args.push('--autofix');
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
        if (raw) parser_inputs.push({ parser: semgrepParser, input: raw });
        const ok = r.outcome === 'completed' || r.exitCode === 1;
        tools_run.push({ name: 'semgrep-wp', status: ok ? 'ok' : 'failed' });
      } else {
        tools_run.push({ name: 'semgrep-wp', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('semgrep');
      }

      // --- gitleaks --------------------------------------------------------
      const gitleaksBin = await scannerAvailable('gitleaks');
      if (gitleaksBin) {
        const outFile = join(reportDir, 'secrets.json');
        const r = await runProcess({
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
        if (raw) parser_inputs.push({ parser: gitleaksParser, input: raw });
        const ok = r.outcome === 'completed' || r.exitCode === 1;
        tools_run.push({ name: 'gitleaks', status: ok ? 'ok' : 'failed' });
      } else {
        tools_run.push({ name: 'gitleaks', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('gitleaks');
      }

      // --- Trivy fs (composer.lock CVEs) ----------------------------------
      const trivyBin = await scannerAvailable('trivy');
      if (trivyBin) {
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
        if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
        tools_run.push({
          name: 'trivy',
          status: r.outcome === 'completed' ? 'ok' : 'failed',
        });
      } else {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
      }

      // --- PHPCS + WPCS ---------------------------------------------------
      const phpcsBin = await scannerAvailable('phpcs');
      if (phpcsBin) {
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
        if (raw) parser_inputs.push({ parser: phpcsParser, input: raw });
        // phpcs exits 1 when issues are found — that is OK.
        const ok = r.outcome === 'completed' || r.exitCode === 1 || r.exitCode === 2;
        tools_run.push({
          name: 'phpcs-wpcs',
          status: ok ? 'ok' : 'failed',
          reason: ok ? undefined : `phpcs exit ${r.exitCode}`,
        } as ToolRun);
      } else {
        tools_run.push({ name: 'phpcs-wpcs', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('phpcs');
      }

      const extras: Record<string, unknown> = { wordpress_layout_detected: looksWp };
      if (warnings.length > 0) extras['warnings_extra'] = warnings;

      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
        extras,
      };
    },
  }),
);
