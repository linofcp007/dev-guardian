/**
 * `branchName` / `prExists` / `openPr` — the part of `create_fix_pr` that
 * leaves the machine (design doc
 * `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md` §5 and §7).
 * Everything before this module runs entirely inside a disposable worktree;
 * this module is the first (and only) place in that flow that talks to the
 * user's own GitHub remote — a branch push and a `gh pr create`.
 *
 * **Two known defects in `../tools/createGithubIssues.ts` are not repeated
 * here** (design §5), and both are binding requirements, not aspirations:
 *
 *   1. `issueExistsByFingerprint` returns `false` on ANY non-completed `gh`
 *      outcome, so a network error reads as "does not exist" and creates a
 *      duplicate. Here, `prExists` returns `{ known: false, reason }` on any
 *      failure to determine existence — a failed `gh` call, unparsable
 *      output, an unexpected shape — and `openPr` REFUSES on that, rather
 *      than guessing. Not knowing is never treated as knowing there is
 *      nothing.
 *   2. `create_github_issues` searches with `gh issue list`, which defaults
 *      to OPEN issues only, so a closed issue for the same finding is
 *      silently re-filed. Here the search is `--state all`, covering open,
 *      closed and merged pull requests alike.
 *
 * **Order of operations is the safety property.** `openPr` resolves
 * `prExists` FIRST, unconditionally, and returns immediately on `refused` or
 * `exists` — before a commit or a push has happened. Nothing here pushes
 * speculatively and rolls back; the existence check gates every write that
 * follows it.
 *
 * **`prExists` has a SECOND caller besides `openPr` (final review,
 * 2026-08-16-create-fix-pr, finding I1).** `branchName` is deterministic
 * (§5, below) so that a repeat run for the same findings lands on the same
 * branch — but `created`, `push_failed` and `create_failed` all deliberately
 * keep that branch (`createFixPr.ts`'s own `KEEPS_BRANCH`), which means the
 * NEXT run's `git worktree add -b <branch>` collides before `openPr` is ever
 * reached at all. Left alone, that makes `prExists` — the entire mechanism
 * this section exists to describe — unreachable for the one case it was
 * built for: recognising a pull request this tool itself already opened.
 * `createFixPr.ts` now calls `prExists` directly when `createWorktree`
 * reports a branch collision, and maps a genuine hit to `existsOutcome`
 * below — the exact same outcome `openPr`'s own check would have produced
 * had it been reachable. A collision `prExists` cannot resolve (no `gh`, a
 * transient failure, or a branch kept by `push_failed`/`create_failed` with
 * no PR to find) falls back to reporting the worktree failure honestly,
 * unchanged from before this fix.
 *
 * **Of the eight failure paths in design §7, one leaves remote state**: `gh
 * pr create` failing after a successful push. That is the one case where a
 * `detail` that just says "creating the PR failed" is not good enough — the
 * user is left with a branch on their own remote and nothing explaining it.
 * `create_failed`'s `detail` always names the pushed branch, so the report
 * alone is enough to open the pull request by hand. `push_failed` names the
 * branch too, for a smaller version of the same reason: the branch still
 * exists locally (in the worktree, and — because `git worktree remove` never
 * deletes the branch it was checked out on — in the main repository's own
 * refs even after the worktree is gone) even though the push itself never
 * landed.
 *
 * **`cwd` is the isolation boundary, not incidental plumbing** (the same
 * point `apply.ts` and `verify.ts` make about their own subprocess calls):
 * `git add` / `git commit` / `git push` run with `cwd: worktreePath` — that
 * is where the applied fix and the working directory actually are. `gh pr
 * list` and `gh pr create` run with `cwd: projectPath` — `gh` resolves which
 * GitHub repository (and which of the user's own local auth applies) from
 * the git remote of its working directory, and `projectPath` is the checkout
 * the user actually set that up in; the brief fixes `gh pr create`'s `cwd`
 * explicitly, and `prExists` has no `worktreePath` to give `gh pr list` even
 * if it wanted to.
 *
 * Transport is the local `gh` CLI only — no tokens, no REST, no Octokit, the
 * same as `create_github_issues`. This repository has never handled a GitHub
 * credential and does not begin here.
 *
 * **`.guardian/**` never becomes part of the commit (task-7-review.md C1).**
 * `createFixPr.ts` re-runs the group's originating scanner INSIDE the
 * worktree to verify the fix, and that scanner writes its own JSON report to
 * `<worktree>/.guardian/reports/**` (`ensureReportDir`,
 * `../tools/scanHelpers.ts`). `git add -A` would stage that report file
 * alongside — or, when the fix itself changed nothing real, INSTEAD OF —
 * whatever the fix actually touched, and `git commit` would then happily
 * commit it: a tree that contains dev-guardian's own scan output is never
 * empty, even when the fix was a no-op. Measured: a commit titled "automated
 * Semgrep fix" whose entire diff was `sast.json`. Both `git add` and the
 * real-change check below use the pathspec `-- ':!.guardian'`, so neither
 * ever sees that directory.
 *
 * **An empty diff is an explicit outcome (`no_changes`), not inferred from
 * `git commit` refusing an empty tree.** Checked directly — `git status
 * --porcelain -- ':!.guardian'` on the worktree — after the existence check
 * and before `git add`, so a fix that genuinely changed nothing never
 * reaches `git commit`, `git push` or `gh pr create` at all. Relying on
 * `git commit`'s own refusal instead would still work (it does refuse an
 * empty tree), but its message — "nothing to commit, working tree clean" —
 * sits several lines past `describeFailure`'s own "first non-blank line"
 * convention (`On branch <name>`), so the caller sees the wrong line and the
 * outcome is bucketed under `push_failed`, indistinguishable from a real
 * failure.
 */

import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import type { FixSource } from './types.js';

/** Excludes dev-guardian's own scan-report artifacts from both staging and
 *  the "did anything real change" check — see the module comment (C1). */
const EXCLUDE_GUARDIAN_DIR = ':!.guardian';

export interface PrOutcome {
  status: 'created' | 'exists' | 'refused' | 'no_changes' | 'push_failed' | 'create_failed';
  url: string | null;
  /** Always set when status !== 'created'. Names the pushed branch when one exists. */
  detail: string | null;
}

const BRANCH_PREFIX = 'dev-guardian/fix-';

/**
 * Deterministic and namespaced (design §5): the same set of findings always
 * produces the same branch, so a repeat run is recognisable as one instead
 * of silently piling up duplicates. The first parameter is accepted — not
 * just `key` — so a caller can pass a `FixGroup`'s three relevant fields
 * (`group.source, group.key, group.hash`) directly, but it never appears in
 * the formatted string: `key` already IS the ecosystem-or-scanner identifier
 * ('npm', 'pip', … for deps; 'semgrep' for semgrep — see `FixGroup.key`'s own
 * doc comment in `types.ts`), so folding it in again would only repeat the
 * same word `key` already carries. (Named `_source`, not `source`: unused on
 * purpose, and `noUnusedParameters` is on.)
 */
export function branchName(_source: FixSource, key: string, hash: string): string {
  return `${BRANCH_PREFIX}${key}-${hash}`;
}

/**
 * The `PrOutcome` for a branch that already has a pull request — shared
 * between `openPr`'s own existence check below and `createFixPr.ts`'s
 * handling of a worktree that could not be created because the branch
 * already exists locally (final review, 2026-08-16-create-fix-pr, finding
 * I1): both learn the same fact ("this branch already has a PR") through the
 * same `prExists` call and must report it identically, so this is the one
 * place that formats it.
 */
export function existsOutcome(branch: string): PrOutcome {
  return {
    status: 'exists',
    url: null,
    detail: `A pull request already exists for branch '${branch}'; nothing to do.`,
  };
}

/**
 * `known: false` whenever the search could not be trusted — a failed `gh`
 * call, output that did not parse as JSON, or JSON that was not the array
 * `gh pr list --json number` promises. `openPr` treats every one of those
 * the same way: refuse, never assume absence.
 */
export async function prExists(opts: {
  projectPath: string;
  branch: string;
  run?: typeof runProcess;
}): Promise<{ known: true; exists: boolean } | { known: false; reason: string }> {
  const run = opts.run ?? runProcess;
  const { projectPath, branch } = opts;

  const result = await run({
    command: 'gh',
    // `--state all`: the defect this must not repeat (module comment, point
    // 2) is a search that defaults to open-only and re-files something that
    // already exists in another state.
    args: ['pr', 'list', '--head', branch, '--state', 'all', '--json', 'number', '--limit', '5'],
    cwd: projectPath,
  });

  if (hasFailed(result)) {
    return { known: false, reason: describeFailure(result, 'gh pr list') };
  }

  let rows: unknown;
  try {
    rows = JSON.parse(result.stdout || '[]');
  } catch (e) {
    return {
      known: false,
      reason: `'gh pr list' printed output that could not be parsed as JSON: ${errorMessage(e)}`,
    };
  }
  if (!Array.isArray(rows)) {
    return { known: false, reason: "'gh pr list' returned JSON that was not an array" };
  }
  return { known: true, exists: rows.length > 0 };
}

/**
 * Branch, commit, push, and open the pull request — in that order, stopping
 * at the first thing that does not succeed. See the module comment for why
 * the existence check runs first and unconditionally, and for the `cwd`
 * chosen at each step.
 */
export async function openPr(opts: {
  projectPath: string;
  worktreePath: string;
  branch: string;
  title: string;
  body: string;
  run?: typeof runProcess;
}): Promise<PrOutcome> {
  const run = opts.run ?? runProcess;
  const { projectPath, worktreePath, branch, title, body } = opts;

  // Gated FIRST, before this function does anything else — see the module
  // comment on order of operations. Nothing below this point runs unless the
  // check came back both known and negative.
  const check = await prExists({ projectPath, branch, run });
  if (!check.known) {
    return {
      status: 'refused',
      url: null,
      detail:
        `Could not determine whether a pull request already exists for branch ` +
        `'${branch}': ${check.reason}. Refusing to push, to avoid risking a duplicate.`,
    };
  }
  if (check.exists) {
    return existsOutcome(branch);
  }

  // Explicit empty-diff check — see the module comment (C1). Excludes
  // .guardian the same way the `git add` below does, so the re-scan's own
  // report is never what makes an otherwise-unchanged tree look non-empty.
  // `git status --porcelain` needs no `--quiet`/exit-code interpretation:
  // empty stdout IS "nothing staged, nothing unstaged, nothing untracked".
  const status = await run({
    command: 'git',
    args: ['status', '--porcelain', '--', EXCLUDE_GUARDIAN_DIR],
    cwd: worktreePath,
  });
  if (hasFailed(status)) {
    return {
      status: 'push_failed',
      url: null,
      detail:
        `Could not determine whether branch '${branch}' has real changes to commit: ` +
        `${describeFailure(status, 'git status')}`,
    };
  }
  if (status.stdout.trim().length === 0) {
    return {
      status: 'no_changes',
      url: null,
      detail:
        `The fix produced no changes to commit on branch '${branch}' (dev-guardian's own scan ` +
        `report is excluded from this check, so it cannot mask a no-op fix). No pull request was opened.`,
    };
  }

  const add = await run({
    command: 'git',
    args: ['add', '-A', '--', EXCLUDE_GUARDIAN_DIR],
    cwd: worktreePath,
  });
  if (hasFailed(add)) {
    return {
      status: 'push_failed',
      url: null,
      detail: `Could not stage the fix on branch '${branch}': ${describeFailure(add, 'git add')}`,
    };
  }

  const commit = await run({ command: 'git', args: ['commit', '-m', title], cwd: worktreePath });
  if (hasFailed(commit)) {
    return {
      status: 'push_failed',
      url: null,
      detail: `Could not commit the fix on branch '${branch}': ${describeFailure(commit, 'git commit')}`,
    };
  }

  const push = await run({ command: 'git', args: ['push', '-u', 'origin', branch], cwd: worktreePath });
  if (hasFailed(push)) {
    return {
      status: 'push_failed',
      url: null,
      detail:
        `Push to origin failed for branch '${branch}': ${describeFailure(push, 'git push')}. ` +
        `The commit exists locally on that branch; it was not pushed.`,
    };
  }

  // cwd: projectPath, per the brief — see the module comment.
  const create = await run({
    command: 'gh',
    args: ['pr', 'create', '--head', branch, '--title', title, '--body', body],
    cwd: projectPath,
  });
  if (hasFailed(create)) {
    return {
      status: 'create_failed',
      url: null,
      detail:
        `Branch '${branch}' was pushed to origin, but 'gh pr create' failed: ` +
        `${describeFailure(create, 'gh pr create')}. Open the pull request by hand from that branch.`,
    };
  }

  return { status: 'created', url: firstUrlLine(create.stdout), detail: null };
}

/**
 * Deletes the local branch `createWorktree` made (task-7-review.md C2).
 * `git worktree remove` deliberately never deletes the branch a worktree was
 * checked out on — confirmed by this module's own `push_failed`/
 * `create_failed` messages, which rely on exactly that so a user can find
 * the branch by hand — so once a group's outcome is one where nothing keeps
 * that branch meaningful (verification never reached `openPr`; `openPr`
 * itself refused, found a PR already `exists`ing, or found `no_changes` to
 * commit), the branch is still sitting in the project's own refs after the
 * worktree is gone. Left alone, design §6's "a dry run leaves nothing behind
 * at all — not a branch" is violated on every dry run, AND a later call for
 * the exact same group collides on that stray branch name in `createWorktree`
 * itself, before `prExists`'s own `--state all` idempotency check is ever
 * reached — design §5's whole idempotency mechanism, made unreachable.
 *
 * Callers decide WHEN this is safe to call (never after `created`,
 * `push_failed` or `create_failed` — see `createFixPr.ts`'s own `keepBranch`
 * logic); this function only performs the deletion, unconditionally, once
 * asked. `-D` (force), not `-d`: every case this is called for has made no
 * commit beyond HEAD on that branch (verification/apply never got as far as
 * `openPr`'s own `git add`/`commit`, or `openPr` returned before making one),
 * so there is nothing `-d`'s "is this merged" safety check could ever
 * usefully refuse, and a refusal here would just leave the exact stray branch
 * this function exists to remove.
 */
export async function deleteLocalBranch(opts: {
  projectPath: string;
  branch: string;
  run?: typeof runProcess;
}): Promise<{ deleted: boolean; warning: string | null }> {
  const run = opts.run ?? runProcess;
  const result = await run({
    command: 'git',
    args: ['branch', '-D', opts.branch],
    cwd: opts.projectPath,
  });
  if (hasFailed(result)) {
    return {
      deleted: false,
      warning: `could not delete local branch '${opts.branch}': ${describeFailure(result, 'git branch -D')}`,
    };
  }
  return { deleted: true, warning: null };
}

// --------------------------------------------------------------- internal

/**
 * Neither check subsumes the other — the same discipline `verify.ts`'s own
 * `hasFailed` applies to the test differential. A real `runProcess` result
 * never has `outcome === 'completed'` alongside a non-zero `exitCode` (the
 * runner itself downgrades that case to `'failed'`), but a fake supplied by
 * a test is not obliged to preserve that invariant, and neither is some
 * future runner. Checking both is what keeps this correct either way.
 */
function hasFailed(result: { outcome: string; exitCode: number | null }): boolean {
  return result.outcome !== 'completed' || result.exitCode !== 0;
}

/**
 * `git push` (like `git worktree add` — see `worktree.ts`'s own
 * `describeFailure`) routinely writes progress lines to stderr AHEAD of the
 * real reason for a failure: a rejected push commonly reads
 * "Enumerating objects…" then "! [rejected]" / "fatal: …" on separate lines.
 * `fatal:`/`error:`-prefixed lines are preferred when present; otherwise
 * this falls back to the first non-blank line of stderr, then stdout, then a
 * summary synthesised from `outcome`/`exitCode` for the case where neither
 * stream has anything at all (a process killed by `output_too_large` or
 * `timed_out` before writing).
 */
function describeFailure(result: ProcessRunResult, label: string): string {
  return (
    preferredErrorLine(result.stderr) ??
    firstNonEmptyLine(result.stderr) ??
    firstNonEmptyLine(result.stdout) ??
    `${label}: ${result.outcome}${result.exitCode !== null ? ` (exit ${result.exitCode})` : ''}`
  );
}

function preferredErrorLine(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('fatal:') || trimmed.startsWith('error:')) return trimmed;
  }
  return null;
}

function firstNonEmptyLine(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

/**
 * `gh pr create`'s own success output is the created PR's URL. Taking the
 * FIRST matching line, not the last: `gh` does not document this as stable
 * either way, and "first" is the more conservative reading if a future `gh`
 * version ever adds output ahead of the URL rather than after it.
 */
function firstUrlLine(stdout: string): string | null {
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('https://')) return trimmed;
  }
  return null;
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
