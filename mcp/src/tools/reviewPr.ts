/**
 * `review_pr` — diff-scoped review scan.
 *
 * Resolves `base_ref` (input, or `git symbolic-ref refs/remotes/origin/HEAD`,
 * else `main`) and `head_ref` (input, or `HEAD`), computes the changed
 * files, then invokes `scripts/scan/review-scan.sh` with that file list.
 * The script runs Semgrep + gitleaks (staged) + Trivy fs (when manifests
 * changed) scoped to the diff.
 *
 * If the diff is empty we short-circuit before spawning the script — the
 * factory still finalises the scan as `completed` with zero findings, which
 * is the right answer.
 */

import { execa } from 'execa';
import { join } from 'node:path';
import { z } from 'zod';
import { gitleaksParser } from '../runners/scannerParsers/gitleaks.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runShellScript } from '../runners/shellRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { ToolRun } from '../types.js';
import { registerToolModule } from './index.js';
import { findNewestDir, readJsonSafe } from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

const SCRIPT_REL_PATH = ['scan', 'review-scan.sh'];

registerToolModule(
  makeScanTool({
    name: 'review_pr',
    title: 'Pre-PR diff review',
    description:
      'Run security + secret + dep checks scoped to the diff between base_ref and head_ref. ' +
      'When base_ref is omitted, defaults to the remote main branch (git symbolic-ref refs/remotes/origin/HEAD, ' +
      'then `main`). head_ref defaults to HEAD.',
    scan_type: 'review_pr',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
      project_path: ProjectPath,
      base_ref: z
        .string()
        .optional()
        .describe('Base ref for the diff. Defaults to origin/HEAD then main.'),
      head_ref: z.string().optional().describe('Head ref. Defaults to HEAD.'),
      severity_min: SeverityMin,
      force: Force,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const startedAt = Date.now() - 1000;
      const scriptPath = join(ctx.plugin.scriptsDir, ...SCRIPT_REL_PATH);

      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      const inp = input as { base_ref?: string; head_ref?: string };
      const baseRef = await resolveBaseRef(inp.base_ref, ctx.projectPath);
      const headRef = inp.head_ref ?? 'HEAD';

      const files = await diffFiles(baseRef, headRef, ctx.projectPath);
      if (files.length === 0) {
        return {
          outcome: 'completed',
          tools_run: [{ name: 'review', status: 'ok', reason: 'no files changed' }],
          missing_tools,
          parser_inputs,
          report_paths: [],
        };
      }

      // The review-scan.sh script expects a single argument: space-joined
      // file paths. Filenames with spaces are not supported by the script —
      // documented limitation.
      const shellResult = await runShellScript({
        shell: ctx.plugin.shell!,
        scriptPath,
        args: [files.join(' ')],
        cwd: ctx.projectPath,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        onLog: ctx.onLog,
      });

      const reportsRoot = join(ctx.projectPath, '.guardian', 'reports');
      const reportDir = findNewestDir(reportsRoot, 'review-', startedAt);

      if (reportDir) {
        const sastRaw = readJsonSafe(join(reportDir, 'sast.json'));
        if (sastRaw) {
          parser_inputs.push({ parser: semgrepParser, input: sastRaw });
          tools_run.push({ name: 'semgrep', status: 'ok' });
        } else {
          tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('semgrep');
        }

        const secretsRaw = readJsonSafe(join(reportDir, 'secrets.json'));
        if (secretsRaw) {
          parser_inputs.push({ parser: gitleaksParser, input: secretsRaw });
          tools_run.push({ name: 'gitleaks', status: 'ok' });
        } else {
          tools_run.push({ name: 'gitleaks', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('gitleaks');
        }

        const depsRaw = readJsonSafe(join(reportDir, 'deps.json'));
        if (depsRaw) {
          parser_inputs.push({ parser: trivyParser, input: depsRaw });
          tools_run.push({ name: 'trivy', status: 'ok' });
        }
        // Trivy is conditional in the review script (only when manifests
        // changed); don't surface a missing tool when its report is absent.
      }

      return {
        outcome: shellResult.outcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: reportDir ? [reportDir] : [],
      };
    },
  }),
);

async function resolveBaseRef(input: string | undefined, cwd: string): Promise<string> {
  if (input && input.length > 0) return input;
  try {
    const r = await execa('git', ['-C', cwd, 'symbolic-ref', 'refs/remotes/origin/HEAD'], {
      reject: false,
      timeout: 5_000,
    });
    if (r.exitCode === 0) {
      const out = r.stdout.trim();
      // "refs/remotes/origin/main" → "origin/main"
      return out.replace(/^refs\/remotes\//, '');
    }
  } catch {
    /* ignore */
  }
  return 'main';
}

async function diffFiles(base: string, head: string, cwd: string): Promise<string[]> {
  try {
    const r = await execa('git', ['-C', cwd, 'diff', '--name-only', `${base}...${head}`], {
      reject: false,
      timeout: 30_000,
    });
    if (r.exitCode !== 0) return [];
    return r.stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  } catch {
    return [];
  }
}
