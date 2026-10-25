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
 * scan rather than a stale hit. A log_opts that narrows the walk (a range, a
 * `--since=`) records the run as scoped (`meta.scope.kind: 'log_opts'`), so
 * it never answers for the secrets outside its window.
 *
 * `scope` (`platform/scope.ts`) is the general form of the same question —
 * `/guardian-prepush`, `-branch`, `-since`, `-diff`: the history pass reads
 * the commits `scope.diff.base` / `scope.since` name, and the files pass
 * reads exactly the files `scope.paths` or an uncommitted/staged diff names.
 * `log_opts` and `scope` together are refused: two answers to one question.
 */

import { z } from 'zod';
import { projectPathTest } from '../platform/guardianIgnore.js';
import { resolveProjectPath, InvalidProjectPathError } from '../platform/projectPath.js';
import { ScanScopeInput } from '../platform/scope.js';
import { historyState, repoState } from '../runners/git.js';
import { LogOptsError, resolveLogOpts, runGitleaksScan, type SecretScanScope } from '../runners/gitleaksScan.js';
import { Force, ProjectPath } from '../schemas.js';
import { discardCaptured, isVerifiableRule, OFFLINE_REASON, verifyGitleaksFindings } from '../secrets/verify/index.js';
import type { Finding, ToolResult } from '../types.js';
import { defineTool, registerToolModule } from './index.js';
import { ensureReportDir } from './scanHelpers.js';
import {
  makeScanTool,
  type InvokeContext,
  type ScannerInvocation,
} from './scanToolFactory.js';

/** `GUARDIAN_OFFLINE=1`: verify_live sends nothing (and captures nothing). */
function networkDisabled(): boolean {
  return process.env['GUARDIAN_OFFLINE'] === '1';
}

/**
 * Whether the scan will keep this finding — the factory's own `.guardianignore`
 * and scope filters, applied here first so a finding they drop is never sent.
 */
function keptByScan(ctx: InvokeContext): (f: Finding) => boolean {
  const inProject = projectPathTest(ctx.projectPath);
  return (f) => {
    const p = f.file_path;
    if (p === undefined || p === '') return true;
    if (ctx.exclusions !== null && ctx.exclusions.ignores(p) && inProject(p)) return false;
    return ctx.scope === null || ctx.scope.member(p);
  };
}

const inputSchema = {
  project_path: ProjectPath,
  log_opts: z
    .string()
    .max(400)
    .optional()
    .describe(
      'Narrow the history pass: --all, <ref>..<ref> or --since=<date>. Not with scope.',
    ),
  force: Force,
  scope: ScanScopeInput,
  verify_live: z
    .boolean()
    .optional()
    .default(false)
    .describe(
      "Ask each secret's own provider whether it is live: sends the secrets out, so ask the user first.",
    ),
};

const scanSecrets = makeScanTool({
  name: 'scan_secrets',
  title: 'Secret scan (gitleaks)',
  description:
    'gitleaks over git history and uncommitted files (the whole directory outside git); each finding says ' +
    'where: history (with the commit), working_tree or directory. A history pass over 0 commits is ' +
    'failed, never clean. The secret never reaches the response, the database or a report. .gitleaks.toml ' +
    'and .gitleaksignore are honoured (`tools_run[].honoured_config`). verify_live asks each provider ' +
    '(GitHub, Slack, Stripe, OpenAI, …) whether its secret is live: ask the user first.',
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
  inputSchema,
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
    // A log_opts that narrows the history (anything but `--all`, which is the
    // whole walk) is a scoped run, recorded as `scope.since` is: its silence
    // about the commits outside its window is not evidence. Recorded as a
    // whole-project scan it became the secrets slot's source at coverage
    // full, and every secret found before the window left the open set.
    const narrowed = logOpts !== undefined && ctx.scope === null && logOpts.split(' ').some((t) => t !== '--all');
    const scoped: Pick<ScannerInvocation, 'extras' | 'warnings'> = narrowed
      ? {
          extras: { scope: { kind: 'log_opts', log_opts: logOpts } },
          warnings: [
            `log_opts "${logOpts}" narrowed the history pass: the secrets an earlier full scan found outside it stay ` +
              'open, and this run is never a baseline.',
          ],
        }
      : {};
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
      // The CI gate's --rules-ref: the ref's .guardianignore decides the submodule gap too.
      ...(ctx.configRoot !== ctx.projectPath ? { guardianIgnoreFrom: ctx.configRoot } : {}),
    });
    const invocation: ScannerInvocation = {
      outcome: scan.cancelled ? 'cancelled' : 'completed',
      tools_run: scan.tools_run,
      missing_tools: scan.missing_tools,
      parser_inputs: scan.parser_inputs,
      report_paths: [reportDir],
      ...scoped,
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
      warnings: [...(scoped.warnings ?? []), ...verified.warnings],
      extras: { ...scoped.extras, secret_verification: verified.summary },
    };
  },
});

const tool = defineTool({
  ...scanSecrets,
  inputSchema,
  handler: async (inp, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const raw = inp.log_opts;
    const scope = inp.scope;
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
      const { log_opts: _drop, ...rest } = inp;
      return scanSecrets.handler(rest, plugin, callMeta);
    }
    let projectPath: string;
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      // The pipeline reports an invalid project_path itself.
      if (e instanceof InvalidProjectPathError) return scanSecrets.handler(inp, plugin, callMeta);
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
    return scanSecrets.handler({ ...inp, log_opts: resolved }, plugin, callMeta);
  },
});

registerToolModule(tool);
