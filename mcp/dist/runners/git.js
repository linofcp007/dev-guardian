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
 * Runs `git` directly through `platform/gitSafety.ts#execGit`, like
 * `tools/gitState.ts`: these are quick local queries, not scanner runs, and
 * must not share the scan runner's limits (or its test doubles). That helper
 * is also what keeps the scanned repository's own git configuration from
 * running anything (`core.fsmonitor`, hooks, filter and textconv drivers).
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { execGit } from '../platform/gitSafety.js';
const GIT_TIMEOUT_MS = 60_000;
/** A checkout writes the whole tree: a large repository needs longer than a query. */
const CHECKOUT_TIMEOUT_MS = 10 * 60_000;
/**
 * `git -C cwd …args`, never throwing; a missing git reads as exit 127. A
 * repository whose git configuration could not be read safely is not run at
 * all: exit 126, with the reason in stderr.
 */
export async function git(cwd, args, timeoutMs = GIT_TIMEOUT_MS) {
    const r = await execGit(cwd, args, { timeoutMs });
    const notApplied = r.notApplied.length > 0 ? { notApplied: r.notApplied } : {};
    if (r.failure?.code === 'refused')
        return { exitCode: 126, stdout: '', stderr: r.stderr, ...notApplied };
    // No exit code: git could not be started (not on PATH) or was killed.
    if (r.status === null)
        return { exitCode: 127, stdout: '', stderr: r.failure?.message ?? 'git could not be run', ...notApplied };
    return { exitCode: r.status, stdout: r.stdout, stderr: r.stderr, ...notApplied };
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
/**
 * The shallow boundary of a shallow clone — the commits whose parents were
 * never fetched (`git rev-parse --git-path shallow` lists them) — or null
 * when the repository is not shallow. A shallow repository whose boundary
 * file cannot be read answers `['(unknown)']`: shallow, boundary unnamed.
 */
export async function shallowBoundary(cwd) {
    const shallow = await git(cwd, ['rev-parse', '--is-shallow-repository']);
    if (shallow.exitCode !== 0 || shallow.stdout.trim() !== 'true')
        return null;
    const where = await git(cwd, ['rev-parse', '--git-path', 'shallow']);
    const rel = where.stdout.trim();
    if (where.exitCode !== 0 || rel === '')
        return ['(unknown)'];
    try {
        const shas = readFileSync(isAbsolute(rel) ? rel : join(cwd, rel), 'utf8')
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => /^[0-9a-f]{40,64}$/.test(l));
        return shas.length > 0 ? shas : ['(unknown)'];
    }
    catch {
        return ['(unknown)'];
    }
}
/**
 * The submodules under `cwd` that are initialised and hold content — the
 * index's gitlinks (mode 160000, one per `.gitmodules` entry that was
 * added) whose checkout directory is not empty (an uninitialised submodule
 * is an empty directory) — as `/`-separated paths relative to `cwd`,
 * sorted. Their files are in no listing a scanner of the superproject uses
 * (review M2). Empty outside a repository.
 *
 * Read from `git ls-files --stage` (~30 ms) rather than `git submodule
 * status`, which spawns a shell and took ~770 ms per call on Windows
 * (git 2.52) — on every secrets and SAST scan.
 */
export async function initialisedSubmodules(cwd) {
    const r = await git(cwd, ['ls-files', '-z', '--stage', '--', '.']);
    if (r.exitCode !== 0)
        return [];
    const out = new Set();
    for (const entry of splitNul(r.stdout)) {
        // `<mode> <object> <stage>\t<path>`.
        const tab = entry.indexOf('\t');
        if (tab < 0 || !entry.startsWith('160000 '))
            continue;
        const path = entry.slice(tab + 1);
        try {
            if (readdirSync(join(cwd, path)).some((name) => name !== '.git'))
                out.add(path.split('\\').join('/'));
        }
        catch {
            // Not there on disk: nothing a scan could have read.
        }
    }
    return [...out].sort();
}
/**
 * The submodules (gitlinks, mode 160000) among `paths` in the tree of `rev`,
 * relative to `cwd` — what a review's diff bumped: those commits' files are
 * in no range of the superproject, whether or not anything is checked out.
 * Empty when git cannot answer.
 */
export async function gitlinksAmong(cwd, rev, paths) {
    if (paths.length === 0)
        return [];
    const r = await git(cwd, ['ls-tree', '-r', '-z', rev, '--', '.']);
    if (r.exitCode !== 0)
        return [];
    const wanted = new Set(paths.map((p) => p.split('\\').join('/')));
    const out = [];
    for (const entry of splitNul(r.stdout)) {
        // `<mode> <type> <object>\t<path>`.
        const tab = entry.indexOf('\t');
        if (tab < 0 || !entry.startsWith('160000 '))
            continue;
        const path = entry.slice(tab + 1);
        if (wanted.has(path))
            out.push(path);
    }
    return out.sort();
}
/** `submodule contents not scanned: a, b` — the first few, then "and N more". */
export function describeSubmodules(paths) {
    const shown = paths.slice(0, 5).join(', ');
    return `submodule contents not scanned: ${shown}${paths.length > 5 ? ` and ${paths.length - 5} more` : ''}`;
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
    // `--ignore-submodules=dirty`: not into a submodule's work tree (a moved
    // submodule commit is still listed — as a directory, which no caller reads).
    const tracked = hasCommits
        ? await git(cwd, ['diff', '-z', '--name-only', '--relative', '--diff-filter=d', '--no-renames', '--ignore-submodules=dirty', 'HEAD', '--'])
        : await git(cwd, ['ls-files', '-z', '--cached']);
    if (tracked.exitCode !== 0) {
        throw new Error(`git failed listing changed files: ${firstLine(tracked.stderr) || `exit ${tracked.exitCode}`}`);
    }
    return [...new Set([...splitNul(tracked.stdout), ...splitNul(untracked.stdout)])];
}
/**
 * What a history scan reads that the working tree does not show: HEAD, and
 * every ref (`gitleaks detect` reads `git log --all`). A fetch or a merge
 * with an empty net diff moves these without changing a single file, so a
 * cache keyed on the tree alone would serve the old history's answer. Empty
 * for a directory without commits.
 */
export async function historyState(cwd) {
    const head = await resolveCommit(cwd, 'HEAD');
    if (head === null)
        return {};
    const refs = await git(cwd, ['for-each-ref', '--format=%(objectname) %(refname)']);
    if (refs.exitCode !== 0)
        throw new Error(`git for-each-ref failed: ${firstLine(refs.stderr)}`);
    return { head, refs: createHash('sha256').update(refs.stdout).digest('hex') };
}
/** The project's path inside its repository, `/`-separated with a trailing `/` ('' at the root). */
export async function showPrefix(cwd) {
    const r = await git(cwd, ['rev-parse', '--show-prefix']);
    if (r.exitCode !== 0)
        throw new Error(`git rev-parse --show-prefix failed: ${firstLine(r.stderr)}`);
    return r.stdout.trim();
}
/**
 * Check out commit `sha` into a new temporary directory with `git worktree
 * add --detach`, so its files can be scanned without touching the user's
 * working tree. No hook runs (a `post-checkout` hook is the repository's
 * code, and scanning must not run it), nor any filter driver the
 * repository's own configuration names (`platform/gitSafety.ts`).
 *
 * In two steps — `worktree add --no-checkout`, then `reset --hard` INSIDE
 * the new worktree — which is what `worktree add` does itself, in a child
 * git started there. The split is for that child's configuration: an
 * `includeIf "gitdir:…"` can match the new worktree's git directory and not
 * the project's, so the configuration is read, and neutralised, where the
 * checkout actually runs. The caller must call `remove()` — in a `finally`.
 */
export async function materialiseCommit(cwd, sha) {
    const holder = mkdtempSync(join(tmpdir(), 'guardian-review-'));
    const root = join(holder, 'head');
    const noHooks = join(holder, 'no-hooks');
    const add = await git(cwd, ['-c', `core.hooksPath=${noHooks}`, 'worktree', 'add', '--detach', '--no-checkout', '--quiet', root, sha], CHECKOUT_TIMEOUT_MS);
    // `--no-recurse-submodules`, as `worktree add`'s own reset passes: with the
    // user's `submodule.recurse=true` (or the repository's), a reset in a
    // `--no-checkout` worktree goes into submodules whose git directories it
    // was never given, and dies (review of W2E-git, measured).
    const r = add.exitCode === 0 ? await git(root, ['reset', '--hard', '--quiet', '--no-recurse-submodules'], CHECKOUT_TIMEOUT_MS) : add;
    const notApplied = [...new Set([...(add.notApplied ?? []), ...(r === add ? [] : (r.notApplied ?? []))])].sort();
    const remove = async () => {
        const problems = [];
        const rm = await git(cwd, ['worktree', 'remove', '--force', root]);
        if (rm.exitCode !== 0 && existsSync(root))
            problems.push(firstLine(rm.stderr) || `git worktree remove exited ${rm.exitCode}`);
        try {
            rmSync(holder, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
        catch (e) {
            problems.push(e instanceof Error ? e.message : String(e));
        }
        await git(cwd, ['worktree', 'prune']);
        return problems.length > 0 ? `temporary checkout ${root} not fully removed: ${problems.join('; ')}` : null;
    };
    if (r.exitCode !== 0) {
        await remove();
        const step = r === add ? 'git worktree add' : 'git reset --hard (the checkout)';
        throw new Error(`${step} ${sha.slice(0, 12)} failed: ${firstLine(r.stderr) || `exit ${r.exitCode}`}`);
    }
    return { root, remove, notApplied };
}
function firstLine(text) {
    return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}
//# sourceMappingURL=git.js.map