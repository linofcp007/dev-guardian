/**
 * `scan_secrets` — secret-leak detection via gitleaks.
 *
 * History AND the files no commit has seen yet — see
 * `runners/gitleaksScan.ts` for what is scanned in a repository with
 * commits, one without, and a directory that is not a repository, and for
 * why `gitleaks detect` on its own reported all three clean.
 *
 * Always runs with `--redact` so the actual secret bytes never reach the
 * MCP wire. The parser strips Match/Secret fields too, but `--redact`
 * is a belt-and-braces guarantee.
 *
 * `log_opts` narrows the HISTORY pass (`/guardian-incident leak`: "since
 * when?"). It is restricted to `--all`, `<ref>..<ref>` and `--since=<date>`
 * and every ref is resolved to its commit id before gitleaks sees it — the
 * resolved form is also what the cache key holds, so a moved branch is a new
 * scan rather than a stale hit.
 */

import { z } from 'zod';
import { resolveProjectPath, InvalidProjectPathError } from '../platform/projectPath.js';
import { repoState } from '../runners/git.js';
import { LogOptsError, resolveLogOpts, runGitleaksScan } from '../runners/gitleaksScan.js';
import { Force, ProjectPath } from '../schemas.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir } from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

type ScanSecretsInput = ScanToolBaseInput & { log_opts?: string };

const scanSecrets = makeScanTool<ScanSecretsInput>({
  name: 'scan_secrets',
  title: 'Secret scan (gitleaks)',
  description:
    'Detect secrets / API keys / tokens with gitleaks: in git history AND in files not committed yet ' +
    '(modified, staged, untracked-not-ignored), or the whole directory when the project is not a git ' +
    'repository (skipping node_modules, vendor, .git and build output). Each finding says where it was ' +
    'found: history (with the commit), working_tree or directory. A history pass that scanned 0 commits ' +
    'is reported as failed, never as clean. Always runs with --redact so the raw secret never reaches ' +
    'MCP output.',
  scan_type: 'secrets',
  category: 'security',
  supportsAutoFix: false,
  inputSchema: {
    project_path: ProjectPath,
    log_opts: z
      .string()
      .max(400)
      .optional()
      .describe(
        'Narrow the history pass. Only --all, <ref>..<ref> (or ...) and --since=<date> are accepted, ' +
          'space-separated; every ref must resolve to a commit. Example: "--since=2026-01-01" or ' +
          '"v1.2.0..HEAD". The uncommitted-files pass always runs.',
      ),
    force: Force,
  },
  invoke: async (input, ctx): Promise<ScannerInvocation> => {
    const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'secrets');
    // Validated by the handler below; re-checked so no other caller of
    // `invoke` can pass an unvalidated string to `git log`.
    const logOpts =
      input.log_opts !== undefined ? await resolveLogOpts(ctx.projectPath, input.log_opts) : undefined;
    const scan = await runGitleaksScan({
      projectPath: ctx.projectPath,
      reportDir,
      scope: logOpts !== undefined ? { kind: 'project', logOpts } : { kind: 'project' },
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
    return {
      outcome: scan.cancelled ? 'cancelled' : 'completed',
      tools_run: scan.tools_run,
      missing_tools: scan.missing_tools,
      parser_inputs: scan.parser_inputs,
      report_paths: [reportDir],
    };
  },
});

const tool: ToolModule = {
  ...scanSecrets,
  handler: async (input, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const raw = (input as { log_opts?: unknown }).log_opts;
    if (typeof raw !== 'string' || raw.trim().length === 0) {
      const { log_opts: _drop, ...rest } = input;
      return scanSecrets.handler(rest, plugin, callMeta);
    }
    let projectPath: string;
    try {
      projectPath = resolveProjectPath((input as { project_path?: string }).project_path).path;
    } catch (e) {
      // The pipeline reports an invalid project_path itself.
      if (e instanceof InvalidProjectPathError) return scanSecrets.handler(input, plugin, callMeta);
      throw e;
    }
    const state = await repoState(projectPath);
    if (state.kind !== 'has_commits') {
      return {
        ok: false,
        error: {
          code: 'not_a_git_repo',
          message: 'log_opts narrows git history, and this project has no git history to narrow.',
        },
      };
    }
    let resolved: string | undefined;
    try {
      resolved = await resolveLogOpts(projectPath, raw);
    } catch (e) {
      if (!(e instanceof LogOptsError)) throw e;
      return {
        ok: false,
        error: { code: e.kind === 'unresolved_ref' ? 'target_not_found' : 'unsupported_target', message: e.message },
      };
    }
    return scanSecrets.handler({ ...input, log_opts: resolved }, plugin, callMeta);
  },
};

registerToolModule(tool);
