/**
 * `create_fix_pr` — orchestrates Tasks 1–6 into the tool that applies fixes
 * the scanners themselves already produced, proves them, and opens a pull
 * request (design doc `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`).
 *
 * Flow: resolve the project path → refuse if not a git repository → read the
 * project's open findings → ask `deps_update_plan` for upgrade steps (when
 * `sources` includes `'deps'`) → `buildGroups` → `selectGroups` → for every
 * SELECTED group: create an isolated worktree, apply the group's fix,
 * re-scan inside the worktree, judge the scan and test differentials, and —
 * only when the fix verifies AND `apply` is true — open a pull request.
 *
 * **`apply` defaults to `false`, and that is the whole safety story** (design
 * §6). Everything expensive and everything verifiable still runs — the
 * worktree is created, the fix is applied, both differentials execute. What
 * sits behind the flag is only what leaves the machine: commit, push, and
 * `gh pr create`. That gate is enforced in exactly one place below (the
 * `if (!apply)` short-circuit before `openPr` is ever called) and nowhere
 * else, so it cannot be bypassed by a path that forgets to check it.
 *
 * **The worktree is removed on every path, including every failure path.**
 * Each selected group gets its own worktree (branched fresh from committed
 * HEAD) and its own `try { … } finally { await worktree.remove(); }` — a
 * failure in one group's worktree creation, fix application, re-scan, or PR
 * step never leaves that group's worktree registered, and never prevents the
 * remaining selected groups from being attempted.
 *
 * **A failed verification is `ok: true` with a verdict, not a `DomainError`.**
 * The only precondition that fails the WHOLE call is not being inside a git
 * repository at all — nothing downstream is meaningful without one, and nothing
 * has been created yet at that point. Every other failure this design
 * enumerates (design §7 items 2–8: no `gh`, worktree creation failed, the fix
 * command failed, the scan differential failed, the fix broke the tests, push
 * failed, `gh pr create` failed) happens PER GROUP, inside a per-group
 * worktree that is always cleaned up, and is reported as that group's own
 * result rather than aborting sibling groups that may have already succeeded
 * or may yet succeed. `gh` missing is not special-cased here at all: `openPr`
 * (Task 6) already refuses cleanly when it cannot determine PR existence —
 * exactly what happens when `gh` is not on PATH — and that refusal surfaces
 * as this group's own `pr.status === 'refused'`.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { applyGroup } from '../fixpr/apply.js';
import { buildGroups, selectGroups } from '../fixpr/candidates.js';
import { branchName, openPr, type PrOutcome } from '../fixpr/pr.js';
import { deriveTestCommand, TEST_MANIFESTS } from '../fixpr/testCommand.js';
import type { FixGroup, FixSource, ScanVerdict, TestVerdict, UpgradeStep } from '../fixpr/types.js';
import { judgeScan, judgeTests, mayOpenPr } from '../fixpr/verify.js';
import { createWorktree } from '../fixpr/worktree.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath, SeverityMin } from '../schemas.js';
import type { DomainError, Finding, Severity, ToolResult } from '../types.js';
import { isGitRepo } from './gitState.js';
import { registerToolModule, TOOLS, type ToolModule } from './index.js';

const DEFAULT_SOURCES: readonly FixSource[] = ['deps', 'semgrep'];
const DEFAULT_SEVERITY_MIN: Severity = 'high';
const DEFAULT_MAX_PRS = 3;

/** The per-group outcome. `scan`/`tests`/`pr` are null exactly when that
 *  stage never ran — a failure upstream, or (for `pr`) a verification that
 *  did not pass, or `apply: false`. `note` is always populated: a one-line,
 *  human-readable account of what happened, never left to be inferred from
 *  which fields are null. */
interface GroupResult {
  key: string;
  source: FixSource;
  severity: Severity;
  /** Deterministic — see `pr.ts#branchName`. Computable even when nothing
   *  downstream ran, so a repeat call with `apply: true` can be told in
   *  advance what branch it would use. */
  branch: string;
  findings: Finding[];
  commands: string[];
  scan: ScanVerdict | null;
  tests: TestVerdict | null;
  pr: PrOutcome | null;
  note: string;
}

const tool: ToolModule = {
  name: 'create_fix_pr',
  title: 'Apply scanner-produced fixes and open a pull request',
  description:
    'Apply fixes the scanners themselves already produced — deps_update_plan pinned upgrade ' +
    'commands and Semgrep --autofix — inside an isolated git worktree, prove them with a scan ' +
    'differential and a (lazy) test differential, and open one pull request per ecosystem or ' +
    'scanner. apply defaults to false: candidates, the worktree, the fix, and both differentials ' +
    'always run; only commit/push/gh pr create sit behind apply=true.',
  inputSchema: {
    project_path: ProjectPath,
    severity_min: SeverityMin,
    sources: z
      .array(z.enum(['deps', 'semgrep']))
      .optional()
      .describe("Which fix sources to consider. Default: both ('deps' and 'semgrep')."),
    max_prs: z
      .number()
      .int()
      .min(1)
      .max(10)
      .optional()
      .describe(
        'Maximum number of groups (pull requests) to act on in one run, highest severity ' +
          'first. Groups beyond the cap are reported in `deferred`, never dropped silently. Default: 3.',
      ),
    apply: z
      .boolean()
      .optional()
      .describe(
        'When true, commit, push and open a pull request for every group that verifies. ' +
          'Default: false — a dry run that still computes candidates, applies the fix in a ' +
          'worktree, and runs both differentials, but never leaves the machine.',
      ),
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    severity_min?: Severity;
    sources?: FixSource[];
    max_prs?: number;
    apply?: boolean;
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  if (!(await isGitRepo(projectPath))) {
    return failDomain('not_a_git_repo', `'${projectPath}' is not inside a git working tree.`);
  }

  const severityMin = inp.severity_min ?? DEFAULT_SEVERITY_MIN;
  // `??`, not `||`: an explicit empty array is a deliberate "consider
  // nothing" and must not be silently reinterpreted as "use the default".
  const sources = inp.sources ?? DEFAULT_SOURCES;
  const maxPrs = inp.max_prs ?? DEFAULT_MAX_PRS;
  const apply = inp.apply === true;

  const allFindings = ctx.storage.findings.listOpenForProject(projectPath);
  const upgradeSteps = sources.includes('deps') ? await fetchUpgradeSteps(projectPath, ctx) : [];

  const groups = buildGroups({ findings: allFindings, upgradeSteps, sources, severityMin });
  const { selected, deferred, deferred_reason } = selectGroups(groups, maxPrs);

  const results: GroupResult[] = [];
  for (const group of selected) {
    try {
      results.push(await processGroup({ group, allFindings, projectPath, apply, ctx }));
    } catch (e) {
      // Every ANTICIPATED failure mode (worktree creation, apply, re-scan,
      // push, gh pr create) is reported by processGroup as a normal return,
      // not a throw — see its own `finally`. This catch exists only for a
      // genuinely unexpected exception, and its purpose is narrow: that
      // group's own worktree is already gone (processGroup's `finally` ran
      // before this exception reached here, whatever raised it), and a bug
      // isolated to one group must not also cost the report on every OTHER
      // selected group, some of which may already have succeeded or may
      // yet succeed.
      results.push({
        key: group.key,
        source: group.source,
        severity: group.severity,
        branch: branchName(group.source, group.key, group.hash),
        findings: findingsForGroup(allFindings, group),
        commands: [],
        scan: null,
        tests: null,
        pr: null,
        note: `internal_error: unexpected failure while processing this group — ${errorMessage(e)}`,
      });
    }
  }

  return {
    ok: true,
    applied: apply,
    project_path: projectPath,
    severity_min: severityMin,
    sources,
    groups: results,
    deferred,
    deferred_reason,
  };
}

/**
 * `deps_update_plan`'s handler, called the way `audit_executive` calls its
 * own sub-tools (`TOOLS.find` + `.handler(input, ctx)`). Its result shape is
 * read defensively — `plan` may be absent or malformed only if that tool's
 * own contract ever changes — rather than assumed, matching how
 * `auditExecutive.ts` treats every sub-tool's JSON result as untyped input.
 * A missing tool or a failed plan degrades to "no deps candidates" rather
 * than failing this whole call: the deps side of the run simply finds
 * nothing to group, which `buildGroups` already reports honestly (no group
 * silently invents a fix).
 */
async function fetchUpgradeSteps(projectPath: string, ctx: PluginContext): Promise<UpgradeStep[]> {
  const depsPlanTool = TOOLS.find((t) => t.name === 'deps_update_plan');
  if (depsPlanTool === undefined) return [];
  const result = await depsPlanTool.handler({ project_path: projectPath }, ctx);
  if (!result.ok) return [];
  const r = result as unknown as { plan?: unknown };
  return Array.isArray(r.plan) ? (r.plan as UpgradeStep[]) : [];
}

async function processGroup(opts: {
  group: FixGroup;
  allFindings: readonly Finding[];
  projectPath: string;
  apply: boolean;
  ctx: PluginContext;
}): Promise<GroupResult> {
  const { group, allFindings, projectPath, apply, ctx } = opts;
  const branch = branchName(group.source, group.key, group.hash);
  const targets = group.candidates.flatMap((c) => c.fingerprints);
  const findings = findingsForGroup(allFindings, group);
  const base = { key: group.key, source: group.source, severity: group.severity, branch, findings };

  const created = await createWorktree({ projectPath, branch });
  if (!created.ok) {
    return {
      ...base,
      commands: [],
      scan: null,
      tests: null,
      pr: null,
      note: `worktree_failed: could not create an isolated worktree for branch '${branch}': ${created.reason}`,
    };
  }
  const { worktree } = created;

  try {
    // The test command must be known BEFORE applyGroup runs — it decides
    // lockfileOnly, which applyGroup needs as an input — so manifests are
    // read from the worktree (the fix has not been applied yet, but the
    // worktree already reflects the exact committed content that will be
    // tested, which projectPath's own possibly-dirty working tree might not).
    const derivedTest = deriveTestCommand(readManifests(worktree.path));

    const applied = await applyGroup({
      group,
      worktreePath: worktree.path,
      lockfileOnly: derivedTest === null,
    });
    if (!applied.applied) {
      return {
        ...base,
        commands: applied.commands,
        scan: null,
        tests: null,
        pr: null,
        note: `apply_failed: the fix could not be applied — ${describeApplyFailure(applied.failure)}`,
      };
    }

    const rescan = await rescanAfterFix(group, worktree.path, ctx);
    if (!rescan.ok) {
      return {
        ...base,
        commands: applied.commands,
        scan: null,
        tests: null,
        pr: null,
        note: `verification_failed: could not verify the fix — ${rescan.reason}`,
      };
    }

    const beforeScanId = ctx.storage.scans.getLatestForProject(projectPath)?.scan_id ?? 'unknown';
    const scanVerdict = judgeScan(
      targets,
      { scan_id: beforeScanId, findings: allFindings },
      { scan_id: rescan.scanId, findings: rescan.findings },
    );
    const testVerdict = await judgeTests({
      derived: derivedTest,
      worktreePath: worktree.path,
      projectPath,
    });

    if (!mayOpenPr(scanVerdict, testVerdict)) {
      const why = !scanVerdict.passed
        ? `the scan differential did not pass (${scanVerdict.still_present.length} target(s) still ` +
          `present, ${scanVerdict.new_findings.length} new finding(s))`
        : 'the fix broke the test suite';
      return {
        ...base,
        commands: applied.commands,
        scan: scanVerdict,
        tests: testVerdict,
        pr: null,
        note: `not_verified: ${why} — no pull request opened`,
      };
    }

    if (!apply) {
      return {
        ...base,
        commands: applied.commands,
        scan: scanVerdict,
        tests: testVerdict,
        pr: null,
        note: 'verified: dry run (apply=false) — re-run with apply=true to open a pull request',
      };
    }

    const title = buildPrTitle(group, targets.length);
    const body = buildPrBody({ group, findings, commands: applied.commands, scan: scanVerdict, tests: testVerdict });
    const pr = await openPr({ projectPath, worktreePath: worktree.path, branch, title, body });
    const note =
      pr.status === 'created'
        ? `pull request opened: ${pr.url ?? '(gh reported no URL)'}`
        : `pull request not opened (${pr.status}): ${pr.detail ?? 'no further detail'}`;
    return { ...base, commands: applied.commands, scan: scanVerdict, tests: testVerdict, pr, note };
  } finally {
    // Per group, on every path above — success, every early return, and any
    // throw. `await`ed so the worktree is actually gone (or reported unable
    // to be) before this group's turn ends, matching worktree.ts's own
    // "teardown verified by observing the world" discipline rather than
    // trusting a fire-and-forget call.
    await worktree.remove();
  }
}

function readManifests(worktreePath: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const name of TEST_MANIFESTS) {
    const path = join(worktreePath, name);
    if (!existsSync(path)) continue;
    try {
      files[name] = readFileSync(path, 'utf8');
    } catch {
      // Unreadable is treated as absent — deriveTestCommand cannot use
      // content it cannot read, and this is not a failure worth aborting
      // the group over: the other manifests are still tried.
    }
  }
  return files;
}

function describeApplyFailure(failure: { command: string; outcome: string; exit_code: number | null; stderr_head: string } | null): string {
  if (failure === null) return 'unknown failure';
  const exit = failure.exit_code !== null ? ` (exit ${failure.exit_code})` : '';
  return `'${failure.command}' ${failure.outcome}${exit}: ${failure.stderr_head}`;
}

/**
 * Re-runs the group's originating scanner inside the already-fixed worktree
 * (design §4.1) via the same MCP tool that would have produced this group's
 * findings in the first place: `scan_sast` for `semgrep`, `deps_audit` for
 * `deps` (Trivy + npm audit — the two `DEP_SCANNER_TOOLS` entries
 * `candidates.ts` actually pairs against; `wpscan` is out of reach here the
 * same way it is for `deps_update_plan` itself).
 *
 * A missing primary scanner is treated as a verification failure, not as "0
 * findings": `scan_sast`/`deps_audit` both report `ok: true` with an EMPTY
 * finding set when their primary scanner could not run at all (consistent
 * with every other scan tool in this repo — a coverage gap, not a clean
 * bill of health). Trusting that empty set at face value here would read
 * "the scanner didn't run" as "nothing is wrong any more" — exactly the
 * false positive the scan differential exists to prevent, in a new costume.
 */
async function rescanAfterFix(
  group: FixGroup,
  worktreePath: string,
  ctx: PluginContext,
): Promise<{ ok: true; scanId: string; findings: Finding[] } | { ok: false; reason: string }> {
  const toolName = group.source === 'semgrep' ? 'scan_sast' : 'deps_audit';
  const primaryScanner = group.source === 'semgrep' ? 'semgrep' : 'trivy';

  const subTool = TOOLS.find((t) => t.name === toolName);
  if (subTool === undefined) {
    return { ok: false, reason: `the '${toolName}' tool is not registered` };
  }

  const result = await subTool.handler({ project_path: worktreePath }, ctx);
  if (!result.ok) {
    return { ok: false, reason: `${toolName} failed: ${result.error.message}` };
  }

  const r = result as unknown as { scan_id?: unknown; missing_tools?: unknown };
  if (typeof r.scan_id !== 'string') {
    return { ok: false, reason: `${toolName} returned no scan_id` };
  }
  const missingTools = Array.isArray(r.missing_tools) ? r.missing_tools : [];
  if (missingTools.includes(primaryScanner)) {
    return {
      ok: false,
      reason: `${primaryScanner} did not run inside the worktree (reported as missing) — cannot verify`,
    };
  }

  return { ok: true, scanId: r.scan_id, findings: ctx.storage.findings.listByScan(r.scan_id) };
}

function buildPrTitle(group: FixGroup, findingCount: number): string {
  const noun = group.source === 'deps' ? `${group.key} dependency` : 'Semgrep';
  const plural = findingCount === 1 ? '' : 's';
  return `dev-guardian: automated ${noun} fix (${findingCount} finding${plural})`;
}

/**
 * States exactly what design §6 requires: the findings covered, the exact
 * commands run, the scan differential, and the test verdict — including,
 * VERBATIM when the outcome is `not_run`, "behaviour was not verified: this
 * project declares no test command".
 */
function buildPrBody(opts: {
  group: FixGroup;
  findings: Finding[];
  commands: string[];
  scan: ScanVerdict;
  tests: TestVerdict;
}): string {
  const { group, findings, commands, scan, tests } = opts;
  const lines: string[] = [];

  lines.push(
    `Automated fix opened by dev-guardian's \`create_fix_pr\` for the **${group.key}** ` +
      `(${group.source}) group.`,
  );

  lines.push('', '## Findings covered');
  for (const f of findings) {
    const loc = f.file_path ? ` (\`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`)` : '';
    lines.push(`- \`${f.fingerprint.slice(0, 12)}\` [${f.severity}] ${f.title}${loc}`);
  }

  lines.push('', '## Commands run');
  for (const c of commands) lines.push(`- \`${c}\``);

  lines.push(
    '',
    '## Scan differential',
    `- Resolved: ${scan.resolved.length}`,
    `- Still present: ${scan.still_present.length}`,
    `- New findings introduced: ${scan.new_findings.length}`,
  );
  for (const nf of scan.new_findings) {
    lines.push(`  - \`${nf.fingerprint.slice(0, 12)}\` [${nf.severity}] ${nf.title}`);
  }

  lines.push('', '## Test verdict');
  switch (tests.outcome) {
    case 'not_run':
      lines.push('behaviour was not verified: this project declares no test command');
      break;
    case 'passed':
      lines.push(`Passed: \`${tests.command ?? ''}\` (${tests.origin ?? 'unknown origin'}).`);
      break;
    case 'already_failing':
      lines.push(
        `The test suite was already failing on the base commit BEFORE this change ` +
          `(not caused by this fix): \`${tests.command ?? ''}\` (${tests.origin ?? 'unknown origin'}).`,
      );
      if (tests.output_head) lines.push('', '```', tests.output_head, '```');
      break;
    case 'broken_by_fix':
      // Never actually reaches here — mayOpenPr refuses a PR whenever
      // outcome === 'broken_by_fix'. Handled anyway so every TestOutcome has
      // an explicit branch rather than a silently-missing one.
      lines.push('the fix broke the test suite; this pull request should not exist.');
      break;
  }

  lines.push(
    '',
    "_Generated by dev-guardian's `create_fix_pr`. This tool verifies that the target findings " +
      'resolved, that no new finding appeared, and that the test suite still passes — it does not ' +
      'review the change itself. Verify before merging._',
  );

  return lines.join('\n');
}

/** The Finding objects a group's candidates target — by fingerprint set
 *  membership, not array order, so a fingerprint's origin candidate never
 *  matters to which findings end up attached to the group's own report. */
function findingsForGroup(allFindings: readonly Finding[], group: FixGroup): Finding[] {
  const targetSet = new Set(group.candidates.flatMap((c) => c.fingerprints));
  return allFindings.filter((f) => targetSet.has(f.fingerprint));
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function failDomain(code: DomainError['code'], message: string): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
