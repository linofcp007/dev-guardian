/**
 * The handful of git questions the scan pipelines ask, answered without a
 * shell and without git's path quoting.
 *
 * Every listing uses `-z`: NUL-separated, never quoted. Without it git prints
 * a non-ASCII path as `"h\303\251llo.py"` (core.quotePath) and a path with a
 * space is one line that a `tr ' ' '\n'` in a script splits into two — both
 * reproduced against `review-scan.sh`. Every listing that can be scoped also
 * uses `--relative`, so paths are relative to the PROJECT (which may be a
 * subdirectory of the repository), never to the repository root.
 *
 * Refs are resolved with `rev-parse --verify --end-of-options <ref>^{commit}`
 * before anything uses them: a ref that does not resolve is an error the
 * caller reports, never an empty diff — `review_pr` against a repository whose
 * default branch is `master` used to diff against a `main` that did not
 * exist, get nothing back, and report "no files changed", `ok`. And
 * `--end-of-options` means a ref spelt like an option (`--output=x`) is only
 * ever a ref.
 *
 * Runs `git` through execa directly, like `tools/gitState.ts`: these are quick
 * local queries, not scanner runs, and must not share the scan runner's
 * limits (or its test doubles).
 */
import { execa } from 'execa';
const GIT_TIMEOUT_MS = 60_000;
/** `git -C cwd …args`, never throwing; a missing git reads as exit 127. */
export async function git(cwd, args) {
    try {
        const r = await execa('git', ['-C', cwd, ...args], {
            reject: false,
            timeout: GIT_TIMEOUT_MS,
            encoding: 'utf8',
            stripFinalNewline: false,
        });
        // No exit code: git could not be started (not on PATH) or was killed.
        if (r.exitCode === undefined)
            return { exitCode: 127, stdout: '', stderr: 'git could not be run' };
        return {
            exitCode: r.exitCode,
            stdout: typeof r.stdout === 'string' ? r.stdout : '',
            stderr: typeof r.stderr === 'string' ? r.stderr : '',
        };
    }
    catch (e) {
        return { exitCode: 127, stdout: '', stderr: e instanceof Error ? e.message : String(e) };
    }
}
/** Split `-z` output into its entries. */
export function splitNul(text) {
    return text.split('\0').filter((s) => s.length > 0);
}
export async function repoState(cwd) {
    const top = await git(cwd, ['rev-parse', '--show-toplevel']);
    if (top.exitCode !== 0) {
        if (/not a git repository/i.test(top.stderr) || top.exitCode === 127)
            return { kind: 'not_git' };
        return { kind: 'error', message: firstLine(top.stderr) || `git exited ${top.exitCode}` };
    }
    const toplevel = top.stdout.trim();
    const head = await git(cwd, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
    return head.exitCode === 0 ? { kind: 'has_commits', toplevel } : { kind: 'no_commits', toplevel };
}
/** The full commit id `ref` names, or null when it names no commit. */
export async function resolveCommit(cwd, ref) {
    const r = await git(cwd, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`]);
    if (r.exitCode !== 0)
        return null;
    const sha = r.stdout.trim();
    return /^[0-9a-f]{40,64}$/.test(sha) ? sha : null;
}
/**
 * Files added, copied, modified or renamed between the merge base of `base`
 * and `head`, and `head` (`base...head`), relative to `cwd`. Deleted files are
 * excluded (`--diff-filter=ACMR`): a deleted path handed to Semgrep is an
 * "Invalid scanning root" that aborts the whole run. Throws with git's own
 * message when the diff cannot be computed (unrelated histories, …).
 */
export async function changedFiles(cwd, base, head) {
    const r = await git(cwd, [
        'diff',
        '-z',
        '--name-only',
        '--relative',
        '--diff-filter=ACMR',
        '--no-renames',
        `${base}...${head}`,
        '--',
    ]);
    if (r.exitCode !== 0) {
        throw new Error(`git diff ${base}...${head} failed: ${firstLine(r.stderr) || `exit ${r.exitCode}`}`);
    }
    return splitNul(r.stdout);
}
/** How many commits `range` (e.g. `a..b`) selects; throws when git cannot say. */
export async function countCommits(cwd, range) {
    const r = await git(cwd, ['rev-list', '--count', range, '--']);
    const n = Number(r.stdout.trim());
    if (r.exitCode !== 0 || !Number.isInteger(n)) {
        throw new Error(`git rev-list --count ${range} failed: ${firstLine(r.stderr) || `exit ${r.exitCode}`}`);
    }
    return n;
}
/**
 * Every file under `cwd` that is in the working tree but in no commit:
 * tracked files that differ from HEAD (staged or not), and untracked files
 * that are not ignored. For a repository with no commits, everything in the
 * index plus every untracked, non-ignored file. Deleted files are left out —
 * there is nothing on disk to read. `excludeDirs` drops UNTRACKED files under
 * those directory names (an un-ignored `node_modules/`), never tracked ones.
 */
export async function uncommittedFiles(cwd, hasCommits, excludeDirs) {
    const excludes = excludeDirs.map((d) => `--exclude=${d}/`);
    const untracked = await git(cwd, ['ls-files', '-z', '--others', '--exclude-standard', ...excludes]);
    if (untracked.exitCode !== 0) {
        throw new Error(`git ls-files failed: ${firstLine(untracked.stderr) || `exit ${untracked.exitCode}`}`);
    }
    const tracked = hasCommits
        ? await git(cwd, ['diff', '-z', '--name-only', '--relative', '--diff-filter=d', '--no-renames', 'HEAD', '--'])
        : await git(cwd, ['ls-files', '-z', '--cached']);
    if (tracked.exitCode !== 0) {
        throw new Error(`git failed listing changed files: ${firstLine(tracked.stderr) || `exit ${tracked.exitCode}`}`);
    }
    return [...new Set([...splitNul(tracked.stdout), ...splitNul(untracked.stdout)])];
}
function firstLine(text) {
    return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}
//# sourceMappingURL=git.js.map