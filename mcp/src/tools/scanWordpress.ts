/**
 * `scan_wordpress` — WordPress code scan.
 *
 * Source-side scan (no live WP install required). Aggregates:
 *   - Semgrep with `p/php` (and `p/wordpress` if available locally)
 *   - Trivy fs for dependency CVEs and licences, judged like scan_deps: a
 *     manifest Trivy read nothing for (a composer.json with no lock) is a
 *     named gap (`runners/trivyRun.ts#judgeTrivyFs`)
 *   - gitleaks for secrets
 *   - PHPCS with `WordPress` standard (when phpcs + WPCS installed)
 *
 * For live-install audits, use `wp_audit`. For WPScan vuln-DB lookup,
 * use `wp_vuln_check`.
 */

import { presentInProject } from '../platform/projectFs.js';
import { join } from 'node:path';
import { z } from 'zod';
import { historyState } from '../runners/git.js';
import { runGitleaksScan } from '../runners/gitleaksScan.js';
import { phpcsParser } from '../runners/scannerParsers/phpcs.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { runSemgrep } from '../runners/semgrepRun.js';
import { applySemgrepCoverageGaps, markMissing, semgrepCoverageGaps } from '../runners/semgrepCoverageGaps.js';
import { judgeTrivyFs, runTrivy, type TrivyFsJudgement } from '../runners/trivyRun.js';
import { trivySkipArgs } from '../platform/guardianIgnore.js';
import { hasFileWithExtension } from '../runners/projectFiles.js';
import { checkSemgrepReport, describePartialParse } from '../runners/semgrepReport.js';
import { withSemgrepEngineNote } from '../runners/semgrepConfigs.js';
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
      'WP rule pack, Trivy fs for dependency CVEs (a manifest it cannot read, e.g. composer.json with no ' +
      'composer.lock, is a named gap), gitleaks for secrets, PHPCS WordPress standard. Each scanner that ' +
      'is missing is skipped with reason. Use wp_audit / wp_vuln_check ' +
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
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'wordpress');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];
      const inp = input as { standard?: typeof WP_STANDARDS[number]; auto_fix?: boolean };
      const standard = inp.standard ?? 'WordPress';

      const looksWp =
        presentInProject(ctx.projectPath, 'wp-config.php') ||
        presentInProject(ctx.projectPath, 'wp-config-sample.php') ||
        presentInProject(ctx.projectPath, 'style.css') || // theme root
        presentInProject(ctx.projectPath, 'readme.txt'); // plugin/theme readme
      const warnings: string[] = [];
      if (!looksWp) {
        warnings.push(
          'not_a_wordpress_project: no wp-config.php / style.css / readme.txt at the root — running generic PHP scans anyway.',
        );
      }

      // The 4 scanners are independent: separate report files, separate
      // CLIs. Run in parallel — wall-clock drops from sum to max.
      const [semgrepBin, trivyBin, phpcsBin] = await Promise.all([
        scannerAvailable('semgrep'),
        scannerAvailable('trivy'),
        scannerAvailable('phpcs'),
      ]);

      const tasks: Array<Promise<void>> = [];
      let manifestGaps: TrivyFsJudgement['gaps'] = [];

      if (semgrepBin) {
        tasks.push(
          (async () => {
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
            // UTF-8 mode (runners/semgrepRun.ts, review M3).
            const r = await runSemgrep({
              args,
              cwd: ctx.projectPath,
              env: ctx.scriptEnv,
              signal: ctx.signal,
              onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw) parser_inputs.push({ parser: semgrepParser, input: raw });
            recordSemgrepWp({ raw, run: r, projectPath: ctx.projectPath, tools_run, missing_tools });
            // The shared gaps: files over Semgrep's size limit, initialised
            // submodules (runners/semgrepCoverageGaps.ts).
            const at = tools_run.findIndex((t) => t.name === 'semgrep-wp');
            const entry = tools_run[at];
            if (entry !== undefined) {
              const applied = applySemgrepCoverageGaps(entry, await semgrepCoverageGaps(ctx.projectPath), {
                scannedNothing: entry.status === 'skipped',
              });
              tools_run[at] = applied.toolRun;
              if (applied.missing) markMissing(missing_tools, 'semgrep-wp');
            }
          })(),
        );
      } else {
        tools_run.push({ name: 'semgrep-wp', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('semgrep');
      }

      // Secrets: history AND uncommitted files (or the whole directory when
      // this is not a git repository — the common case for a WordPress site
      // copied off a server). See runners/gitleaksScan.ts.
      tasks.push(
        (async () => {
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
          } catch (e) {
            tools_run.push({
              name: 'gitleaks',
              status: 'failed',
              reason: `secret scan failed: ${e instanceof Error ? e.message : String(e)}`,
            });
          }
        })(),
      );

      if (trivyBin) {
        tasks.push(
          (async () => {
            const outFile = join(reportDir, 'deps.json');
            // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
            const r = await runTrivy({
              args: ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', outFile, '--quiet', ...trivySkipArgs(ctx.exclusions)],
              target: ctx.projectPath,
              workDir: reportDir,
              ignoreFrom: ctx.projectPath,
              env: ctx.scriptEnv,
              signal: ctx.signal,
              onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
            // The same judgement as scan_deps (review I2): a composer.json
            // with no composer.lock is a named gap, never `ok`, full.
            const judged = judgeTrivyFs({ projectPath: ctx.projectPath, raw, run: r, exclusions: ctx.exclusions });
            tools_run.push(judged.toolRun);
            missing_tools.push(...judged.missing);
            manifestGaps = judged.gaps;
          })(),
        );
      } else {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
      }

      if (phpcsBin) {
        tasks.push(
          (async () => {
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
            const ok = r.outcome === 'completed' || r.exitCode === 1 || r.exitCode === 2;
            tools_run.push({
              name: 'phpcs-wpcs',
              status: ok ? 'ok' : 'failed',
              reason: ok ? undefined : `phpcs exit ${r.exitCode}`,
            } as ToolRun);
          })(),
        );
      } else {
        tools_run.push({ name: 'phpcs-wpcs', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('phpcs');
      }

      await Promise.all(tasks);

      const extras: Record<string, unknown> = { wordpress_layout_detected: looksWp };
      if (manifestGaps.length > 0) extras['manifest_coverage_gaps'] = manifestGaps;
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

/**
 * The `semgrep-wp` entry, judged by the shared Semgrep judge
 * (`runners/semgrepReport.ts`) — never by the exit code alone, which read a
 * partly parsed file and a run that scanned no file as `ok`, coverage full
 * (follow-up X, fix round 1). The gap is named `semgrep-wp`, the same name as
 * the run, so a partial run reads "ran, with a narrower gap"
 * (`history/runNames.ts` maps it to Semgrep's findings); only a Semgrep that
 * is not installed is listed as `semgrep`.
 *
 *   - partial → `ok`, the files named in `partially_parsed`, and missing;
 *   - scanned nothing → `skipped`: not applicable when the project holds no
 *     `.php` file (nothing for p/php or p/wordpress to read), a gap when it
 *     does;
 *   - anything fatal → `failed`, the errors as its reason (the findings the
 *     report holds were already kept).
 */
function recordSemgrepWp(args: {
  raw: string | null;
  run: ProcessRunResult;
  projectPath: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}): void {
  const { raw, run, projectPath, tools_run, missing_tools } = args;
  const check = checkSemgrepReport({ raw, exitCode: run.exitCode, outcome: run.outcome, targets: 1, projectPath });
  // What the engine cannot report (taint fixpoint timeouts), on a run that scanned.
  if (check.verdict === 'ok') {
    tools_run.push(withSemgrepEngineNote({ name: 'semgrep-wp', status: 'ok' }, raw));
    return;
  }
  if (check.verdict === 'partial' && check.partial !== undefined) {
    tools_run.push(
      withSemgrepEngineNote(
        {
          name: 'semgrep-wp',
          status: 'ok',
          reason: describePartialParse(check.partial, 'findings in the unparsed spans may be missing'),
          partially_parsed: check.partial,
        },
        raw,
      ),
    );
    missing_tools.push('semgrep-wp');
    return;
  }
  if (check.verdict === 'scanned_nothing') {
    if (!hasFileWithExtension(projectPath, ['.php'])) {
      tools_run.push({
        name: 'semgrep-wp',
        status: 'skipped',
        reason: 'not applicable: no .php file here for p/php or p/wordpress to read',
      });
      return;
    }
    tools_run.push({
      name: 'semgrep-wp',
      status: 'skipped',
      reason: 'semgrep scanned 0 files although .php files exist — excluded (.semgrepignore) or the rules loaded nothing',
    });
    missing_tools.push('semgrep-wp');
    return;
  }
  const stderr = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
  tools_run.push({ name: 'semgrep-wp', status: 'failed', reason: check.reason ?? stderr ?? 'semgrep failed' });
}
