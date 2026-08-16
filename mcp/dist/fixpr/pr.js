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
 */
import { runProcess } from '../runners/processRunner.js';
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
export function branchName(_source, key, hash) {
    return `${BRANCH_PREFIX}${key}-${hash}`;
}
/**
 * `known: false` whenever the search could not be trusted — a failed `gh`
 * call, output that did not parse as JSON, or JSON that was not the array
 * `gh pr list --json number` promises. `openPr` treats every one of those
 * the same way: refuse, never assume absence.
 */
export async function prExists(opts) {
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
    let rows;
    try {
        rows = JSON.parse(result.stdout || '[]');
    }
    catch (e) {
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
export async function openPr(opts) {
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
            detail: `Could not determine whether a pull request already exists for branch ` +
                `'${branch}': ${check.reason}. Refusing to push, to avoid risking a duplicate.`,
        };
    }
    if (check.exists) {
        return {
            status: 'exists',
            url: null,
            detail: `A pull request already exists for branch '${branch}'; nothing to do.`,
        };
    }
    const add = await run({ command: 'git', args: ['add', '-A'], cwd: worktreePath });
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
            detail: `Push to origin failed for branch '${branch}': ${describeFailure(push, 'git push')}. ` +
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
            detail: `Branch '${branch}' was pushed to origin, but 'gh pr create' failed: ` +
                `${describeFailure(create, 'gh pr create')}. Open the pull request by hand from that branch.`,
        };
    }
    return { status: 'created', url: firstUrlLine(create.stdout), detail: null };
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
function hasFailed(result) {
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
function describeFailure(result, label) {
    return (preferredErrorLine(result.stderr) ??
        firstNonEmptyLine(result.stderr) ??
        firstNonEmptyLine(result.stdout) ??
        `${label}: ${result.outcome}${result.exitCode !== null ? ` (exit ${result.exitCode})` : ''}`);
}
function preferredErrorLine(text) {
    for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.startsWith('fatal:') || trimmed.startsWith('error:'))
            return trimmed;
    }
    return null;
}
function firstNonEmptyLine(text) {
    for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.length > 0)
            return trimmed;
    }
    return null;
}
/**
 * `gh pr create`'s own success output is the created PR's URL. Taking the
 * FIRST matching line, not the last: `gh` does not document this as stable
 * either way, and "first" is the more conservative reading if a future `gh`
 * version ever adds output ahead of the URL rather than after it.
 */
function firstUrlLine(stdout) {
    for (const line of stdout.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.startsWith('https://'))
            return trimmed;
    }
    return null;
}
function errorMessage(e) {
    return e instanceof Error ? e.message : String(e);
}
//# sourceMappingURL=pr.js.map