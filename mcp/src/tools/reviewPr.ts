/**
 * `review_pr` — the scans of a pull request, scoped to what it changes.
 *
 *   - Semgrep over every file the PR adds, copies, modifies or renames
 *     (`git diff -z --diff-filter=ACMR base...head`), with the same rule
 *     sources as `scan_sast`. The files are read from the working tree when
 *     head is what is checked out; otherwise from head's own tree, checked
 *     out for the scan with `git worktree add --detach` and removed after —
 *     the working tree would hold other versions of the files, and none of
 *     the files only head has. A changed file missing from that tree is a
 *     coverage gap;
 *   - gitleaks over exactly the PR's commits (`--log-opts=<base>..<head>`),
 *     so a secret added in one commit and removed in the next is still found,
 *     plus the uncommitted files when head is what is checked out;
 *   - Bandit over the changed `.py` files;
 *   - Trivy over the project when a dependency manifest or lockfile changed.
 *
 * It used to hand a space-joined file list to `scripts/scan/review-scan.sh`,
 * which lost every one of: deleted files (one aborted the whole Semgrep run),
 * paths with spaces (split), non-ASCII paths (git-quoted), long lists (xargs
 * batches overwriting one report), files named `-x` (read as options), and the
 * branch's commits (`gitleaks protect --staged` reads the index). See
 * `runners/git.ts`, `runners/argBatches.ts` and `runners/fileBatchScan.ts`.
 *
 * Refs are resolved before anything runs: an unresolvable `base_ref` (a typo,
 * a `master` repository asked about `main`) is `target_not_found`, never "no
 * files changed". The resolved commit ids are what the scan is keyed and
 * cached by, so a moved branch is a new review, not a stale hit.
 */

import {
  PROJECT_LANGUAGES_META_KEY,
  resolveProjectLanguagesAsync,
  type ProjectLanguages,
} from '../frameworks/projectLanguages.js';
import { lstatSync } from 'node:fs';
import { basename, join } from 'node:path';
import { z } from 'zod';
import { GUARDIAN_IGNORE_FILE } from '../platform/guardianIgnore.js';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { banditOnFiles, semgrepOnFiles } from '../runners/fileBatchScan.js';
import {
  changedFiles,
  git,
  gitlinksAmong,
  materialiseCommit,
  repoState,
  resolveCommit,
  showPrefix,
  type MaterialisedTree,
} from '../runners/git.js';
import { applySemgrepCoverageGaps, markMissing, semgrepCoverageGaps } from '../runners/semgrepCoverageGaps.js';
import { runGitleaksScan } from '../runners/gitleaksScan.js';
import { PROJECT_TRIVYIGNORE, runTrivy as spawnTrivy, withHonoured } from '../runners/trivyRun.js';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { semgrepParserFor } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { planSemgrepConfigs, semgrepEngineNote } from '../runners/semgrepConfigs.js';
import { semgrepEngineOf } from '../runners/semgrepReport.js';
import { mayHoldTaintRules, pluginPackCheckIds } from '../runners/semgrepRuleIds.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { DomainError, ToolResult, ToolRun } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';
import {
  makeScanTool,
  type InvokeContext,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

type ReviewPrInput = ScanToolBaseInput & {
  base_ref?: string;
  head_ref?: string;
  local_only?: boolean;
};

/** A change to one of these means the dependency set may have changed. */
const MANIFEST_RE =
  /^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|composer\.(json|lock)|Gemfile(\.lock)?|Cargo\.(toml|lock)|go\.(mod|sum)|.*\.csproj|packages\.lock\.json|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile)$/;

const reviewPr = makeScanTool<ReviewPrInput>({
  name: 'review_pr',
  title: 'Pre-PR diff review',
  description:
    'Scan what a pull request changes: Semgrep (same rules as scan_sast) over every added/modified/' +
    'renamed file between base_ref and head_ref, gitleaks over exactly those commits (plus uncommitted ' +
    'files when head is checked out), Bandit over changed .py files, and Trivy when a dependency ' +
    'manifest changed. Files are read at head: from the working tree when head is checked out, else ' +
    'from a temporary checkout of head. base_ref defaults to ' +
    'origin/HEAD, then main, then master; head_ref to HEAD. An unresolvable ref is an error, never ' +
    '"no files changed". Pass local_only=true to skip the Semgrep registry (no telemetry).',
  scan_type: 'review_pr',
  category: 'security',
  supportsAutoFix: false,
  rulePacks: (input, { projectPath, plugin }) =>
    planSemgrepConfigs(projectPath, plugin, input.local_only === true).rulePacks,
  inputSchema: {
    project_path: ProjectPath,
    base_ref: z
      .string()
      .optional()
      .describe('Base ref for the diff. Defaults to origin/HEAD, then main, then master.'),
    head_ref: z.string().optional().describe('Head ref. Defaults to HEAD.'),
    local_only: z
      .boolean()
      .optional()
      .describe(
        "Semgrep runs only the project's own rules and registered custom rules, with --metrics=off. " +
          'Default: false.',
      ),
    severity_min: SeverityMin,
    force: Force,
  },
  invoke: async (input, ctx): Promise<ScannerInvocation> => {
    // The handler below resolved both refs to commit ids; re-resolved here so
    // no other caller of `invoke` can pass an unchecked ref to git.
    const base = await resolveCommit(ctx.projectPath, input.base_ref ?? '');
    const head = await resolveCommit(ctx.projectPath, input.head_ref ?? 'HEAD');
    if (base === null || head === null) throw new Error('review_pr: base_ref/head_ref do not name commits');

    const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'review');
    const out: Collected = { tools_run: [], missing_tools: [], parser_inputs: [], cancelled: false };
    const changed = await changedFiles(ctx.projectPath, base, head);

    // Which files ARE the head: the working tree only when head is what is
    // checked out. Otherwise the head's own tree, checked out for this scan —
    // the working tree would hold another version of every file, and no copy
    // at all of the files only the head has.
    const headIsCheckedOut = (await resolveCommit(ctx.projectPath, 'HEAD')) === head;
    let tree: MaterialisedTree | null = null;
    let cleanupNote: string | null = null;
    let projectLanguages: ProjectLanguages | null = null;
    try {
      let scanRoot = ctx.projectPath;
      let unavailable: string | null = null;
      if (!headIsCheckedOut && changed.length > 0) {
        try {
          tree = await materialiseCommit(ctx.projectPath, head);
          scanRoot = join(tree.root, await showPrefix(ctx.projectPath));
        } catch (e) {
          unavailable = `could not check out head ${head.slice(0, 12)}: ${e instanceof Error ? e.message : String(e)}`;
        }
      }
      const where = headIsCheckedOut ? 'the working tree' : `head ${head.slice(0, 12)}`;
      // The languages of the tree this review reads — the head's own when it
      // is not checked out — listed before that tree is removed below. A
      // head that is not checked out and changes no file was never
      // materialised: the working tree is not the head, so nothing is
      // recorded rather than the wrong tree's languages.
      projectLanguages =
        unavailable !== null
          ? { languages: null, source: `could not be determined (${unavailable})` }
          : !headIsCheckedOut && tree === null
            ? { languages: null, source: `not recorded: head ${head.slice(0, 12)} was not checked out (no file changed)` }
            : await resolveProjectLanguagesAsync(ctx.plugin.storage.stack, ctx.projectPath, { walkRoot: scanRoot });

      if (unavailable !== null) {
        // gitleaks reads commits, not files, and still runs below.
        out.tools_run.push({ name: 'semgrep', status: 'failed', reason: unavailable });
        if (changed.some(isPython)) out.tools_run.push({ name: 'bandit', status: 'failed', reason: unavailable });
        if (changed.some(isManifest)) out.tools_run.push({ name: 'trivy', status: 'failed', reason: unavailable });
      } else {
        const present = changed.filter((f) => isFileOnDisk(join(scanRoot, f)));
        const submodules = await gitlinksAmong(ctx.projectPath, head, changed);
        await runSemgrep(ctx, input, out, { scanRoot, reportDir, changed, present, where, submodules });
        if (!out.cancelled) await runBandit(ctx, out, { scanRoot, reportDir, files: present.filter(isPython) });
        if (!out.cancelled && changed.some(isManifest)) await runTrivy(ctx, out, { scanRoot, reportDir });
      }

      // gitleaks over the PR's commits — and, when head is what is checked
      // out, over the files no commit holds yet (`protect --staged` used to
      // look at the index; this looks at everything uncommitted).
      if (!out.cancelled) {
        const secrets = await runGitleaksScan({
          projectPath: ctx.projectPath,
          reportDir,
          scope: { kind: 'range', base, head, workingTree: headIsCheckedOut },
          env: ctx.scriptEnv,
          signal: ctx.signal,
          ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
        });
        out.tools_run.push(...secrets.tools_run);
        out.missing_tools.push(...secrets.missing_tools);
        out.parser_inputs.push(...secrets.parser_inputs);
        out.cancelled ||= secrets.cancelled;
      }
    } finally {
      if (tree) cleanupNote = await tree.remove();
    }

    // A pull request that edits .guardianignore changes what every scan of
    // the project leaves out — this review's included. Say so, every time.
    const warnings = changed.includes(GUARDIAN_IGNORE_FILE)
      ? [
          `This diff changes ${GUARDIAN_IGNORE_FILE}, which decides what every dev-guardian scan of this ` +
            "project leaves out (this review applied the working tree's copy). Review that change before " +
            'trusting a quiet result: a pattern added there hides findings, it does not fix them.',
        ]
      : [];
    // The same for Trivy's suppression file, which this review honoured from the tree it read.
    if (changed.includes(PROJECT_TRIVYIGNORE)) {
      warnings.push(
        `This diff changes ${PROJECT_TRIVYIGNORE}, which Trivy honours: every vulnerability id listed there is ` +
          "not reported (this review applied the reviewed tree's copy). Review that change before trusting a " +
          'quiet dependency result: an entry added there hides a finding, it does not fix it.',
      );
    }

    return {
      outcome: out.cancelled ? 'cancelled' : 'completed',
      tools_run: out.tools_run,
      missing_tools: [...new Set(out.missing_tools)],
      parser_inputs: out.parser_inputs,
      report_paths: [reportDir],
      ...(warnings.length > 0 ? { warnings } : {}),
      extras: {
        base_sha: base,
        head_sha: head,
        scanned_tree: headIsCheckedOut ? 'working_tree' : 'head_checkout',
        changed_files: changed.length,
        // Whether the Semgrep registry ran — OWASP coverage
        // (`frameworks/coverage.ts`) claims registry categories only when
        // the row says `false`, as scan_sast's rows always have.
        local_only: input.local_only === true,
        ...(projectLanguages !== null ? { [PROJECT_LANGUAGES_META_KEY]: projectLanguages } : {}),
        ...(cleanupNote !== null ? { cleanup_warning: cleanupNote } : {}),
      },
    };
  },
});

interface Collected {
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: ScannerInvocation['parser_inputs'];
  cancelled: boolean;
}

const isPython = (f: string): boolean => f.toLowerCase().endsWith('.py');
const isManifest = (f: string): boolean => MANIFEST_RE.test(basename(f));

/**
 * Semgrep over the changed files present in `scanRoot`. A changed file that
 * is not there (deleted in the working tree since, a submodule) was not
 * scanned: that is a gap in coverage, never a note on a full run.
 */
async function runSemgrep(
  ctx: InvokeContext,
  input: ReviewPrInput,
  out: Collected,
  args: {
    scanRoot: string;
    reportDir: string;
    changed: readonly string[];
    present: readonly string[];
    where: string;
    /** The submodules the diff bumped (`git.ts#gitlinksAmong`): their new commits are read by nothing here. */
    submodules: readonly string[];
  },
): Promise<void> {
  // The shared Semgrep coverage gaps (runners/semgrepCoverageGaps.ts): the
  // changed files over the size limit, the submodules the diff bumped — on
  // the entry just pushed, for a Semgrep that ran or was meant to.
  const withGaps = async (scannedNothing: boolean): Promise<void> => {
    const at = out.tools_run.length - 1;
    const entry = out.tools_run[at];
    if (entry === undefined || entry.name !== 'semgrep') return;
    const gaps = await semgrepCoverageGaps(args.scanRoot, { files: args.present, submodules: args.submodules });
    const applied = applySemgrepCoverageGaps(entry, gaps, { scannedNothing });
    out.tools_run[at] = applied.toolRun;
    if (applied.missing) markMissing(out.missing_tools, 'semgrep');
  };
  const missing = args.changed.length - args.present.length;
  const gap = missing > 0 ? `${missing} changed file(s) not in ${args.where} were not scanned` : null;
  if (args.changed.length === 0) {
    out.tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'no changed file between base and head' });
    return;
  }
  if (args.present.length === 0) {
    out.tools_run.push({ name: 'semgrep', status: 'skipped', reason: gap ?? 'nothing to scan' });
    out.missing_tools.push('semgrep');
    await withGaps(false);
    return;
  }
  if (!(await scannerAvailable('semgrep'))) {
    out.tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
    out.missing_tools.push('semgrep');
    return;
  }
  const plan = planSemgrepConfigs(ctx.projectPath, ctx.plugin, input.local_only === true);
  if (plan.nothingToRun) {
    out.tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason: 'local_only=true but this project has no local Semgrep rules — nothing to run',
    });
    out.missing_tools.push('semgrep');
    return;
  }
  const run = await semgrepOnFiles({
    configArgs: plan.args,
    files: args.present,
    cwd: args.scanRoot,
    reportDir: args.reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
    rules: {
      configs: plan.rulePacks,
      ctx: { projectPath: ctx.projectPath, cwd: args.scanRoot },
      loadedFrom: plan.ruleConfigs,
      // The plugin's pack's own fixpoint timeouts are its gap, not the review's.
      packCheckIds: pluginPackCheckIds(plan.pluginPacks, { cwd: args.scanRoot }),
      nonPackTaintRules: mayHoldTaintRules(plan.ruleConfigs),
    },
  });
  // Run from `scanRoot` (a temporary tree for a ref), Semgrep names the
  // project's rules by their absolute path; stored canonical, as scan_sast's.
  const parser = semgrepParserFor(plan.rulePacks, { projectPath: ctx.projectPath, cwd: args.scanRoot });
  for (const raw of run.reports) out.parser_inputs.push({ parser, input: raw });
  // What the engine cannot do — report taint fixpoint timeouts, resolve the
  // LLM pack's node: imports — said once, as scan_sast says it.
  const engineNote = semgrepEngineNote(semgrepEngineOf(run.reports[0] ?? null), { llmPack: plan.pluginPacks.length > 0 });
  out.tools_run.push(
    withNotes(run.toolRun, [...plan.notes, ...(gap !== null ? [gap] : []), ...(engineNote !== null ? [engineNote] : [])]),
  );
  // Scanned nothing at all, not every changed file, or some only partly
  // parsed or rules that did not load (`ok` + missing, runners/semgrepReport.ts):
  // a gap, not a clean result.
  // The plugin's LLM pack missing from disk (runners/semgrepConfigs.ts) is a gap too.
  const partial = run.toolRun.status === 'ok' && (run.partial.length > 0 || run.failedRules.length > 0 || plan.packMissing);
  if (run.nothingScanned || gap !== null || partial) out.missing_tools.push('semgrep');
  await withGaps(run.nothingScanned);
  out.cancelled ||= run.cancelled;
}

/** Bandit over the changed `.py` files present in `scanRoot`. */
async function runBandit(
  ctx: InvokeContext,
  out: Collected,
  args: { scanRoot: string; reportDir: string; files: readonly string[] },
): Promise<void> {
  if (args.files.length === 0) return;
  if (!(await scannerAvailable('bandit'))) {
    out.tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
    out.missing_tools.push('bandit');
    return;
  }
  const run = await banditOnFiles({
    files: args.files,
    cwd: args.scanRoot,
    reportDir: args.reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  for (const raw of run.reports) out.parser_inputs.push({ parser: banditParser, input: raw });
  out.tools_run.push(run.toolRun);
  out.cancelled ||= run.cancelled;
}

/** Trivy over the head's dependency manifests, when one of them changed. */
async function runTrivy(ctx: InvokeContext, out: Collected, args: { scanRoot: string; reportDir: string }): Promise<void> {
  if (!(await scannerAvailable('trivy'))) {
    out.tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
    out.missing_tools.push('trivy');
    return;
  }
  const outFile = join(args.reportDir, 'deps.json');
  // Never in the tree under review, never its trivy.yaml: a pull request
  // could otherwise add one that silences its own dependency
  // (runners/trivyRun.ts). Its .trivyignore is honoured and named — and a
  // diff that edits it is called out beside .guardianignore.
  const run = await spawnTrivy({
    args: ['fs', '--scanners', 'vuln', '--format', 'json', '--output', outFile, '--quiet'],
    target: args.scanRoot,
    workDir: args.reportDir,
    ignoreFrom: args.scanRoot,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  const raw = readJsonSafe(outFile);
  if (run.outcome === 'cancelled') out.cancelled = true;
  if (run.outcome === 'completed' && raw !== null) {
    out.parser_inputs.push({ parser: trivyParser, input: raw });
    out.tools_run.push(withHonoured({ name: 'trivy', status: 'ok', reason: 'a dependency manifest changed' }, run.honoured));
  } else {
    out.tools_run.push(
      withHonoured(
        {
          name: 'trivy',
          status: 'failed',
          reason: raw === null ? `no report (${run.outcome}, exit ${String(run.exitCode)})` : run.outcome,
        },
        run.honoured,
      ),
    );
  }
}

function isFileOnDisk(path: string): boolean {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

function withNotes(run: ToolRun, notes: readonly string[]): ToolRun {
  if (notes.length === 0) return run;
  return { ...run, reason: [run.reason, ...notes].filter((s) => s !== undefined).join('; ') };
}

/** origin/HEAD, then main, master, origin/main, origin/master — the first that names a commit. */
async function defaultBaseRef(cwd: string): Promise<string | null> {
  const originHead = await git(cwd, ['symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD']);
  const candidates: string[] = [];
  if (originHead.exitCode === 0) candidates.push(originHead.stdout.trim().replace(/^refs\/remotes\//, ''));
  candidates.push('main', 'master', 'origin/main', 'origin/master');
  for (const ref of candidates) {
    if (ref.length > 0 && (await resolveCommit(cwd, ref)) !== null) return ref;
  }
  return null;
}

function refused(code: DomainError['code'], message: string): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}

const tool: ToolModule = {
  ...reviewPr,
  handler: async (input, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const inp = input as { project_path?: string; base_ref?: unknown; head_ref?: unknown };
    let projectPath: string;
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      // The pipeline reports an invalid project_path itself.
      if (e instanceof InvalidProjectPathError) return reviewPr.handler(input, plugin, callMeta);
      throw e;
    }

    const state = await repoState(projectPath);
    if (state.kind === 'not_git') {
      return refused('not_a_git_repo', `${projectPath} is not inside a git repository — there is no diff to review.`);
    }
    if (state.kind === 'error') return refused('not_a_git_repo', `git could not read ${projectPath}: ${state.message}`);
    if (state.kind === 'no_commits') {
      return refused('target_not_found', 'The repository has no commits yet — there is no base or head to diff.');
    }

    const headLabel = typeof inp.head_ref === 'string' && inp.head_ref.length > 0 ? inp.head_ref : 'HEAD';
    let baseLabel: string;
    if (typeof inp.base_ref === 'string' && inp.base_ref.length > 0) {
      baseLabel = inp.base_ref;
    } else {
      const found = await defaultBaseRef(projectPath);
      if (found === null) {
        return refused(
          'target_not_found',
          'No base ref given and none found (no origin/HEAD, main, master, origin/main or origin/master). ' +
            'Pass base_ref.',
        );
      }
      baseLabel = found;
    }
    const baseSha = await resolveCommit(projectPath, baseLabel);
    if (baseSha === null) return refused('target_not_found', `base_ref "${baseLabel}" does not name a commit.`);
    const headSha = await resolveCommit(projectPath, headLabel);
    if (headSha === null) return refused('target_not_found', `head_ref "${headLabel}" does not name a commit.`);

    const result = await reviewPr.handler({ ...input, base_ref: baseSha, head_ref: headSha }, plugin, callMeta);
    return result.ok ? { ...result, base_ref: baseLabel, head_ref: headLabel } : result;
  },
};

registerToolModule(tool);
