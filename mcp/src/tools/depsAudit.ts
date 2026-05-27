/**
 * `deps_audit` — dependency audit (Trivy + bot detection + optional
 * stack-specific auditors).
 *
 * Builds on `scan_deps` (same Trivy invocation) and adds:
 *   - `bot_configured` flag — whether the project already has renovate.json
 *     or .github/dependabot.yml in place;
 *   - opportunistic capture of `npm audit --json` / `pip-audit -f json`
 *     output when the corresponding package manager is present. The output
 *     files are persisted under .guardian/reports/depsaudit-<scan>/ as
 *     evidence; this version does not parse them into Findings (the Trivy
 *     parser already covers the CVE detection across all stacks). Adding
 *     native parsers later does not require touching this tool — drop new
 *     ScannerParsers into runners/scannerParsers/ and reference them here.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
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

interface BotConfigured {
  renovate: boolean;
  dependabot: boolean;
}

function detectBots(projectPath: string): BotConfigured {
  return {
    renovate:
      existsSync(join(projectPath, 'renovate.json')) ||
      existsSync(join(projectPath, '.renovaterc')) ||
      existsSync(join(projectPath, '.renovaterc.json')),
    dependabot: existsSync(join(projectPath, '.github', 'dependabot.yml')),
  };
}

registerToolModule(
  makeScanTool({
    name: 'deps_audit',
    title: 'Dependency audit (Trivy + native auditors + bot detection)',
    description:
      'Run Trivy fs (vuln+license) plus stack-specific auditors (npm audit, pip-audit) when ' +
      'applicable. Returns Findings, indexed CVEs, and a `bot_configured` flag indicating whether ' +
      'Renovate or Dependabot is set up in this repo.',
    scan_type: 'deps',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      force: Force,
    },
    invoke: async (_input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'depsaudit');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      // --- Trivy fs (canonical CVE source for all stacks) ---------------
      const trivyBin = await scannerAvailable('trivy');
      if (trivyBin) {
        const outFile = join(reportDir, 'deps.json');
        const result = await runProcess({
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
          status: result.outcome === 'completed' ? 'ok' : 'failed',
        });
      } else {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
      }

      // --- Native auditors (best-effort, no parsing in v1) --------------
      if (existsSync(join(ctx.projectPath, 'package.json'))) {
        await tryNativeAudit({
          command: 'npm',
          args: ['audit', '--json', '--audit-level=info'],
          outFile: join(reportDir, 'npm-audit.json'),
          ctx,
          tools_run,
        });
      }
      if (
        existsSync(join(ctx.projectPath, 'pyproject.toml')) ||
        existsSync(join(ctx.projectPath, 'requirements.txt'))
      ) {
        await tryNativeAudit({
          command: 'pip-audit',
          args: ['-f', 'json', '-o', join(reportDir, 'pip-audit.json')],
          outFile: join(reportDir, 'pip-audit.json'),
          ctx,
          tools_run,
        });
      }

      const bot_configured = detectBots(ctx.projectPath);

      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
        extras: { bot_configured },
      };
    },
  }),
);

interface NativeAuditOptions {
  command: string;
  args: string[];
  outFile: string;
  ctx: Parameters<NonNullable<Parameters<typeof makeScanTool>[0]['invoke']>>[1];
  tools_run: ToolRun[];
}

async function tryNativeAudit(opts: NativeAuditOptions): Promise<void> {
  const bin = await scannerAvailable(opts.command);
  if (!bin) {
    opts.tools_run.push({
      name: opts.command,
      status: 'skipped',
      reason: 'not_installed',
    });
    return;
  }
  const isNpmStdout = opts.command === 'npm';
  const result = await runProcess({
    command: opts.command,
    args: opts.args,
    cwd: opts.ctx.projectPath,
    env: opts.ctx.scriptEnv,
    signal: opts.ctx.signal,
    onLog: opts.ctx.onLog,
  });
  // npm audit writes to stdout; redirect ourselves.
  if (isNpmStdout && result.stdout.length > 0) {
    try {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(opts.outFile, result.stdout, 'utf8');
    } catch {
      /* swallow */
    }
  }
  // npm audit returns non-zero when vulnerabilities are present — that is
  // information, not failure.
  const ok =
    result.outcome === 'completed' ||
    (opts.command === 'npm' && typeof result.exitCode === 'number') ||
    result.exitCode === 1;
  opts.tools_run.push({
    name: opts.command,
    status: ok ? 'ok' : 'failed',
    reason: ok ? 'captured (no MCP parser yet)' : undefined,
  } as ToolRun);
}
