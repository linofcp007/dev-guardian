/**
 * `scan_secrets` — secret-leak detection via gitleaks.
 *
 * History AND the files no commit has seen yet — see
 * `runners/gitleaksScan.ts` for what is scanned in a repository with
 * commits, one without, and a directory that is not a repository, and for
 * why `gitleaks detect` on its own reported all three clean.
 *
 * Runs with `--redact` so the actual secret bytes never reach the MCP wire.
 * The parser strips Match/Secret fields too, but `--redact` is a
 * belt-and-braces guarantee.
 *
 * `verify_live` (off by default) is the one exception, and the value still
 * never reaches the wire, the database or a report: gitleaks writes its
 * unredacted report into a private temporary directory, the values of the
 * rules `secrets/verify/providers.ts` can check are held in memory, each
 * DISTINCT value is sent once to its own provider's read-only identity
 * endpoint (a fixed host per rule — never one taken from the repository),
 * and every finding comes back `live` (raised to critical, with where to
 * revoke it), `revoked` or `unknown`. See `secrets/verify/index.ts`.
 * Findings `.guardianignore` or the scope drop are never sent.
 *
 * `log_opts` narrows the HISTORY pass (`/guardian-incident leak`: "since
 * when?"). It is restricted to `--all`, `<ref>..<ref>` and `--since=<date>`
 * and every ref is resolved to its commit id before gitleaks sees it — the
 * resolved form is also what the cache key holds, so a moved branch is a new
 * scan rather than a stale hit.
 *
 * `scope` (`platform/scope.ts`) is the general form of the same question —
 * `/guardian-prepush`, `-branch`, `-since`, `-diff`: the history pass reads
 * the commits `scope.diff.base` / `scope.since` name, and the files pass
 * reads exactly the files `scope.paths` or an uncommitted/staged diff names.
 * `log_opts` and `scope` together are refused: two answers to one question.
 */

import { z } from 'zod';
import { isProjectPath } from '../platform/guardianIgnore.js';
import { resolveProjectPath, InvalidProjectPathError } from '../platform/projectPath.js';
import { ScanScopeInput } from '../platform/scope.js';
import { historyState, repoState } from '../runners/git.js';
import { LogOptsError, resolveLogOpts, runGitleaksScan, type SecretScanScope } from '../runners/gitleaksScan.js';
import { Force, ProjectPath } from '../schemas.js';
import { discardCaptured, isVerifiableRule, OFFLINE_REASON, verifyGitleaksFindings } from '../secrets/verify/index.js';
import type { Finding, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir } from './scanHelpers.js';
import {
  makeScanTool,
  type InvokeContext,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

type ScanSecretsInput = ScanToolBaseInput & { log_opts?: string; verify_live?: boolean };

/** `GUARDIAN_OFFLINE=1`: verify_live sends nothing (and captures nothing). */
function networkDisabled(): boolean {
  return process.env['GUARDIAN_OFFLINE'] === '1';
}

/**
 * Whether the scan will keep this finding — the factory's own `.guardianignore`
 * and scope filters, applied here first so a finding they drop is never sent.
 */
function keptByScan(ctx: InvokeContext): (f: Finding) => boolean {
  return (f) => {
    const p = f.file_path;
    if (p === undefined || p === '') return true;
    if (ctx.exclusions !== null && isProjectPath(ctx.projectPath, p) && ctx.exclusions.ignores(p)) return false;
    return ctx.scope === null || ctx.scope.member(p);
  };
}

const scanSecrets = makeScanTool<ScanSecretsInput>({
  name: 'scan_secrets',
  title: 'Secret scan (gitleaks)',
  description:
    'Detect secrets / API keys / tokens with gitleaks: in git history AND in files not committed yet ' +
    '(modified, staged, untracked-not-ignored), or the whole directory when the project is not a git ' +
    'repository (skipping node_modules, vendor, .git and build output). Each finding says where it was ' +
    'found: history (with the commit), working_tree or directory. A history pass that scanned 0 commits ' +
    'is reported as failed, never as clean. The raw secret never reaches MCP output, the database or ' +
    'reports. Pass scope to scan only some files or commits: paths and uncommitted/staged diffs are ' +
    'scanned as files, diff.base and since as exactly those commits. .guardianignore paths are ' +
    'filtered out. verify_live (off by default) asks whether each GitHub, GitLab, Slack, Stripe, ' +
    "OpenAI, Anthropic, npm or SendGrid secret still works: it sends each secret to its own provider's " +
    'read-only API and nowhere else (5 s timeout, at most 50 per scan), and marks the finding live ' +
    '(raised to critical, with where to revoke it), revoked or unknown.',
  scan_type: 'secrets',
  // History is read beyond the working tree: HEAD and every ref join the key.
  // A verifying scan run offline (every verdict `unknown`) must not be served
  // to a verifying call that could reach the providers, nor the reverse.
  cacheState: async (input, { projectPath }) => ({
    ...(await historyState(projectPath)),
    ...(input.verify_live === true ? { verify_network: networkDisabled() ? 'off' : 'on' } : {}),
  }),
  category: 'security',
  supportsAutoFix: false,
  supportsScope: true,
  inputSchema: {
    project_path: ProjectPath,
    log_opts: z
      .string()
      .max(400)
      .optional()
      .describe(
        'Narrow the history pass. Only --all, <ref>..<ref> (or ...) and --since=<date> are accepted, ' +
          'space-separated; every ref must resolve to a commit. Example: "--since=2026-01-01" or ' +
          '"v1.2.0..HEAD". The uncommitted-files pass always runs. Not with scope.',
      ),
    force: Force,
    scope: ScanScopeInput,
    verify_live: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Off by default. Sends each supported secret to its own provider's read-only identity API — and " +
          'nowhere else — to learn whether it is live, revoked or unknown. GUARDIAN_OFFLINE=1 sends nothing.',
      ),
  },
  invoke: async (input, ctx): Promise<ScannerInvocation> => {
    const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'secrets');
    // Validated by the handler below; re-checked so no other caller of
    // `invoke` can pass an unvalidated string to `git log`.
    const logOpts =
      input.log_opts !== undefined ? await resolveLogOpts(ctx.projectPath, input.log_opts) : undefined;
    let scope: SecretScanScope = logOpts !== undefined ? { kind: 'project', logOpts } : { kind: 'project' };
    if (ctx.scope !== null) {
      const h = ctx.scope.history;
      // A `--since=` built by the scope still goes through the same
      // validation as a caller's log_opts before gitleaks hands it to git.
      const history =
        h === null ? null : 'base' in h ? h : { logOpts: (await resolveLogOpts(ctx.projectPath, h.logOpts)) ?? h.logOpts };
      scope = { kind: 'scoped', history, files: ctx.scope.contentFiles };
    }
    const verify = input.verify_live === true;
    // Offline, nothing is captured: a raw value that cannot be sent is not read.
    const offline = verify && networkDisabled();
    const scan = await runGitleaksScan({
      projectPath: ctx.projectPath,
      reportDir,
      scope,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
      ...(verify && !offline ? { captureSecrets: isVerifiableRule } : {}),
    });
    const invocation: ScannerInvocation = {
      outcome: scan.cancelled ? 'cancelled' : 'completed',
      tools_run: scan.tools_run,
      missing_tools: scan.missing_tools,
      parser_inputs: scan.parser_inputs,
      report_paths: [reportDir],
    };
    if (!verify) return invocation;
    if (scan.cancelled) {
      // A cancelled scan sends nothing, and lets go of what it captured.
      discardCaptured(scan.captured);
      return invocation;
    }
    ctx.onLog?.('verify_live: asking each secret\'s own provider whether it is live');
    const verified = await verifyGitleaksFindings({
      parser_inputs: scan.parser_inputs,
      secrets: scan.captured ?? null,
      unavailable: offline ? OFFLINE_REASON : (scan.capture_error ?? null),
      projectPath: ctx.projectPath,
      keep: keptByScan(ctx),
      options: { signal: ctx.signal, offline },
    });
    return {
      ...invocation,
      parser_inputs: verified.parser_inputs,
      warnings: verified.warnings,
      extras: { secret_verification: verified.summary },
    };
  },
});

const tool: ToolModule = {
  ...scanSecrets,
  handler: async (input, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const raw = (input as { log_opts?: unknown }).log_opts;
    const scope = (input as { scope?: unknown }).scope;
    if (scope !== undefined && scope !== null && typeof raw === 'string' && raw.trim().length > 0) {
      return {
        ok: false,
        error: {
          code: 'unsupported_target',
          message:
            'log_opts and scope both narrow what is scanned — pass one: scope.since or scope.diff.base ' +
            'for commits, scope.paths or scope.diff for files.',
        },
      };
    }
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
