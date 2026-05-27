/**
 * `scan_sast` — Semgrep-only static analysis (plus Bandit when Python is
 * present).
 *
 * Invokes Semgrep directly (no shell script), writing the JSON report to
 * `.guardian/reports/sast-<short-scan-id>/sast.json`. Bandit, if installed
 * and Python sources are detected, is run in the same pass.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
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

registerToolModule(
  makeScanTool({
    name: 'scan_sast',
    title: 'SAST scan (Semgrep)',
    description:
      'Static analysis with Semgrep against the project (config=auto). ' +
      'Also runs Bandit when Python files are present and the CLI is installed. ' +
      'Output JSON is written to .guardian/reports/sast-<scan>/ and parsed into Findings.',
    scan_type: 'sast',
    category: 'security',
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      auto_fix: AutoFix,
      allow_dirty: AllowDirty,
      force: Force,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'sast');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];
      const autoFix = input.auto_fix === true;

      // --- Semgrep -----------------------------------------------------
      const semgrepBin = await scannerAvailable('semgrep');
      if (semgrepBin) {
        const outFile = join(reportDir, 'sast.json');
        const args = ['--config=auto', '--json', '--quiet', '--output', outFile];
        if (autoFix) args.push('--autofix');
        args.push(ctx.projectPath);

        const result = await runProcess({
          command: 'semgrep',
          args,
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw) {
          parser_inputs.push({ parser: semgrepParser, input: raw });
        }
        // exit 0 = no findings; exit 1 = findings present; both are OK.
        const ok = result.outcome === 'completed' || result.exitCode === 1;
        tools_run.push({ name: 'semgrep', status: ok ? 'ok' : 'failed' });
        if (!ok && result.stderr) {
          // Surface the first stderr line for diagnostics.
          const reason = result.stderr.split(/\r?\n/)[0] ?? 'unknown';
          tools_run[tools_run.length - 1]!.reason = reason;
        }
      } else {
        tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('semgrep');
      }

      // --- Bandit ------------------------------------------------------
      // Only attempt Bandit when the project obviously has Python sources.
      const looksPython =
        existsSync(join(ctx.projectPath, 'pyproject.toml')) ||
        existsSync(join(ctx.projectPath, 'requirements.txt')) ||
        existsSync(join(ctx.projectPath, 'setup.py'));
      if (looksPython) {
        const banditBin = await scannerAvailable('bandit');
        if (banditBin) {
          const outFile = join(reportDir, 'bandit.json');
          const result = await runProcess({
            command: 'bandit',
            args: ['-r', ctx.projectPath, '-f', 'json', '-o', outFile, '-q'],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
          });
          const raw = readJsonSafe(outFile);
          if (raw) parser_inputs.push({ parser: banditParser, input: raw });
          // Bandit returns 1 when issues are found; treat as ok.
          const ok = result.outcome === 'completed' || result.exitCode === 1;
          tools_run.push({ name: 'bandit', status: ok ? 'ok' : 'failed' });
        } else {
          tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('bandit');
        }
      }

      const anyOk = tools_run.some((t) => t.status === 'ok');
      const outcome = anyOk ? 'completed' : missing_tools.length > 0 ? 'completed' : 'failed';

      return {
        outcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
      };
    },
  }),
);
