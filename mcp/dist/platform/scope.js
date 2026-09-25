/**
 * Scoped scans — a scan of part of a project: named files, a diff, or the
 * changes since a commit or a date.
 *
 * Seven commands (`guardian-diff`, `-prepush`, `-branch`, `-since`,
 * `-incoming`, `-file`, plus `-postinstall` / `-leak`) ask for a file-, diff-
 * or commit-scoped scan, and the scan tools used to accept only a directory:
 * a file path was `not_a_directory`, and a diff was not expressible at all, so
 * every one of those commands ran a whole-project scan and called it scoped.
 *
 * `resolveScope` turns the `scope` input into:
 *
 *   - `files` — the regular files, on disk, that the scanners are handed as
 *     explicit targets (sorted, project-relative, POSIX). Deleted files are
 *     never in it: a deleted target makes Semgrep abort the whole run.
 *   - `member(path)` — which result paths belong to the scope. Wider than
 *     `files` for a commit range: a file one commit of the range touched and
 *     a later one deleted is in no target list, but a secret gitleaks finds
 *     in that commit is exactly what `scope.diff.base` asked about.
 *   - `history` — the commits a history scanner (gitleaks) reads: a resolved
 *     `base..head` range, or `--since=<date>`; null for a working-tree scope.
 *   - `contentFiles` — the files a content pass reads from the working tree:
 *     every file for `paths` and uncommitted/staged diffs; only the untracked
 *     additions for a commit range, whose committed content `history` covers.
 *
 * Refs go through `rev-parse --verify --end-of-options` (`runners/git.ts`):
 * one that names no commit is `target_not_found`, never an empty diff, and a
 * ref spelt like an option is only ever a ref. Every listing is `-z` (no path
 * quoting) and `--relative` (paths relative to the PROJECT, which may be a
 * subdirectory of its repository).
 *
 * A scoped scan is persisted with `meta.scope` (see `history/scanRoles.ts`
 * `isScopedScan`): it never answers for the project's open findings, never
 * becomes a baseline, and never supersedes an unscoped scan in a comparison —
 * its silence about the files outside its scope is not evidence about them.
 */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { z } from 'zod';
import { changedFiles, git, repoState, resolveCommit, splitNul } from '../runners/git.js';
import { listProjectFiles, PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { globToRegExp, hasGlobMagic } from './glob.js';
export const ScanScopeInput = z
    .object({
    paths: z
        .array(z.string().min(1).max(4096))
        .min(1)
        .max(1000)
        .optional()
        .describe('Files, directories or globs relative to (and inside) project_path. Directories are ' +
        'expanded to their files. With diff/since, narrows that change set to these paths.'),
    diff: z
        .object({
        base: z
            .string()
            .min(1)
            .max(256)
            .optional()
            .describe('Scan the files changed between the merge base of this ref and head (committed work).'),
        head: z.string().min(1).max(256).optional().describe('Must be the checked-out commit. Default HEAD.'),
        staged: z
            .boolean()
            .optional()
            .describe('Only the files staged in the index (read from the working tree, like every scope).'),
        include_untracked: z
            .boolean()
            .optional()
            .describe('Also untracked, non-ignored files. Default: true without base/staged, else false.'),
    })
        .strict()
        .optional()
        .describe('A git change set. {} = every uncommitted change (staged, unstaged, untracked).'),
    since: z
        .string()
        .min(1)
        .max(256)
        .optional()
        .describe('A commit/tag, or a date (YYYY-MM-DD, "2 weeks ago", "yesterday"): what changed since.'),
})
    .strict()
    .optional()
    .describe('Scan part of the project instead of all of it. Findings are restricted to the scope; the scan ' +
    'is recorded as scoped (meta.scope), never becomes a baseline and never replaces a whole-project ' +
    "scan in the project's open findings.");
export class ScopeError extends Error {
    code;
    constructor(message, code) {
        super(message);
        this.code = code;
        this.name = 'ScopeError';
    }
}
/**
 * What to call instead, when `project_path` names a FILE: its repository's
 * root (the nearest ancestor holding `.git`) or, outside git, its directory —
 * with the file as `scope.paths`.
 */
export function suggestScopeForFile(filePath) {
    const file = resolve(filePath);
    let root = dirname(file);
    for (let dir = root;; dir = dirname(dir)) {
        if (existsSync(join(dir, '.git'))) {
            root = dir;
            break;
        }
        if (dirname(dir) === dir)
            break;
    }
    return { project_path: root, scope: { paths: [normaliseRelPath(relative(root, file))] } };
}
/** A result path in the form the scope's sets use. */
export function normaliseRelPath(p) {
    return p.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/{2,}/g, '/').replace(/\/+$/, '');
}
export async function resolveScope(projectPath, scope, opts) {
    const { paths, diff, since } = scope;
    if (paths === undefined && diff === undefined && since === undefined) {
        throw new ScopeError('scope must name paths, diff or since (omit scope to scan the whole project)', 'unsupported_target');
    }
    if (diff !== undefined && since !== undefined) {
        throw new ScopeError('scope.diff and scope.since each name a change set — pass one of them', 'unsupported_target');
    }
    const pathPart = paths !== undefined ? resolvePaths(projectPath, paths) : null;
    let kind = 'paths';
    let files;
    let touched = null;
    let history = null;
    let contentFiles;
    const meta = {};
    if (diff !== undefined || since !== undefined) {
        const change = diff !== undefined ? await resolveDiff(projectPath, diff) : await resolveSince(projectPath, since ?? '');
        kind = diff !== undefined ? 'diff' : 'since';
        const inPaths = (p) => pathPart === null || pathPart.member(p);
        files = change.files.filter(inPaths);
        contentFiles = change.contentFiles.filter(inPaths);
        touched = new Set([...change.touched, ...change.files].filter(inPaths));
        history = change.history;
        Object.assign(meta, change.meta);
    }
    else if (pathPart !== null) {
        files = pathPart.files;
        contentFiles = files;
    }
    else {
        // Unreachable: the guard at the top requires one of the three.
        throw new ScopeError('scope must name paths, diff or since', 'unsupported_target');
    }
    const ignored = (p) => opts.exclusions?.ignores(p) === true;
    const before = files.length;
    files = files.filter((p) => !ignored(p));
    contentFiles = contentFiles.filter((p) => !ignored(p));
    const excludedByIgnore = before - files.length;
    const fileSet = new Set(files);
    const touchedSet = touched;
    const member = (relPath) => {
        const p = normaliseRelPath(relPath);
        if (fileSet.has(p))
            return true;
        if (touchedSet !== null)
            return touchedSet.has(p);
        return pathPart !== null && pathPart.member(p);
    };
    const describedMeta = {
        kind,
        ...(paths !== undefined ? { paths: [...paths] } : {}),
        ...meta,
        files: files.length,
        ...(excludedByIgnore > 0 ? { files_excluded_by_guardianignore: excludedByIgnore } : {}),
    };
    const cacheState = {
        scope: createHash('sha256')
            .update(JSON.stringify({ files, touched: touched === null ? null : [...touched].sort(), history }))
            .digest('hex'),
    };
    return { kind, files, member, history, contentFiles, meta: describedMeta, cacheState, excludedByIgnore };
}
/**
 * `paths` entries → files. A literal file or directory is taken as named (a
 * directory expanded with the project walk, which skips `PROJECT_WALK_EXCLUDE`
 * below it); an entry that names nothing on disk but holds glob syntax is
 * matched against every project file and each of its directories. Anything
 * not found is refused, all of them in one error.
 */
function resolvePaths(projectPath, entries) {
    const root = realOrSelf(projectPath);
    const files = new Set();
    const dirs = [];
    const globs = [];
    const missing = [];
    let allFiles = null;
    for (const entry of entries) {
        const rel = toProjectRelative(projectPath, entry);
        if (rel === null) {
            throw new ScopeError(`scope.paths entry "${entry}" is outside the project ${projectPath}`, 'unsupported_target');
        }
        const abs = rel === '' ? projectPath : join(projectPath, ...rel.split('/'));
        const kind = entryKind(abs, root);
        if (kind === 'escapes') {
            throw new ScopeError(`scope.paths entry "${entry}" resolves outside the project`, 'unsupported_target');
        }
        if (kind === 'file') {
            files.add(rel);
        }
        else if (kind === 'dir') {
            dirs.push(rel);
            for (const f of listProjectFiles(abs))
                files.add(rel === '' ? f : `${rel}/${f}`);
        }
        else if (kind === 'other') {
            throw new ScopeError(`scope.paths entry "${entry}" is not a regular file or directory (a symbolic link is not followed)`, 'unsupported_target');
        }
        else if (hasGlobMagic(rel)) {
            // Not `expandGlob`: it stops after 50 000 entries without saying so,
            // and a truncated scope would read as a complete one.
            allFiles ??= listProjectFiles(projectPath);
            const re = globToRegExp(rel);
            globs.push(re);
            let matched = 0;
            for (const f of allFiles) {
                if (matchesSelfOrAncestor(re, f)) {
                    files.add(f);
                    matched += 1;
                }
            }
            if (matched === 0)
                missing.push(entry);
        }
        else {
            missing.push(entry);
        }
    }
    if (missing.length > 0) {
        throw new ScopeError(`scope.paths: ${missing.map((m) => `"${m}"`).join(', ')} matched nothing in ${projectPath}`, 'target_not_found');
    }
    return {
        files: [...files].sort(),
        member: (p) => files.has(p) ||
            dirs.some((d) => d === '' || p.startsWith(`${d}/`)) ||
            globs.some((re) => matchesSelfOrAncestor(re, p)),
    };
}
/** Does `re` match `path` or one of its parent directories? */
function matchesSelfOrAncestor(re, path) {
    if (re.test(path))
        return true;
    const segments = path.split('/');
    for (let i = 1; i < segments.length; i++) {
        if (re.test(segments.slice(0, i).join('/')))
            return true;
    }
    return false;
}
/** `rel` climbs out of its base (`..` or `../…`), or is absolute (another drive). */
function escapes(rel) {
    return isAbsolute(rel) || rel.split(/[\\/]/)[0] === '..';
}
/** `entry` relative to the project (POSIX), or null when it is outside it. */
function toProjectRelative(projectPath, entry) {
    const abs = isAbsolute(entry) ? resolve(entry) : resolve(projectPath, entry.replace(/\\/g, '/'));
    const rel = relative(resolve(projectPath), abs);
    if (escapes(rel))
        return null;
    return normaliseRelPath(rel);
}
function realOrSelf(p) {
    try {
        return realpathSync.native(p);
    }
    catch {
        return resolve(p);
    }
}
/** What is at `abs` — a symbolic link counts only when it stays inside the project. */
function entryKind(abs, root) {
    let st;
    try {
        st = lstatSync(abs);
    }
    catch {
        return 'missing';
    }
    if (st.isSymbolicLink()) {
        return escapes(relative(root, realOrSelf(abs))) ? 'escapes' : 'other';
    }
    if (st.isFile())
        return 'file';
    if (st.isDirectory())
        return 'dir';
    return 'other';
}
async function requireRepo(projectPath, what) {
    const state = await repoState(projectPath);
    if (state.kind === 'not_git')
        throw new ScopeError(`${what} needs a git repository, and ${projectPath} is not in one`, 'not_a_git_repo');
    if (state.kind === 'error')
        throw new ScopeError(`git could not read ${projectPath}: ${state.message}`, 'not_a_git_repo');
    return state.kind === 'has_commits';
}
async function listZ(cwd, args) {
    const r = await git(cwd, args);
    if (r.exitCode !== 0) {
        const line = r.stderr.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? `exit ${r.exitCode}`;
        throw new ScopeError(`git ${args[0] ?? ''} failed: ${line}`, 'not_a_git_repo');
    }
    return splitNul(r.stdout).map(normaliseRelPath);
}
async function untracked(cwd) {
    return listZ(cwd, [
        'ls-files',
        '-z',
        '--others',
        '--exclude-standard',
        ...[...PROJECT_WALK_EXCLUDE].map((d) => `--exclude=${d}/`),
    ]);
}
function onDisk(projectPath, rels) {
    const out = new Set();
    for (const rel of rels) {
        try {
            if (lstatSync(join(projectPath, ...rel.split('/'))).isFile())
                out.add(rel);
        }
        catch {
            /* deleted, or never there: nothing to read */
        }
    }
    return [...out].sort();
}
async function resolveDiff(projectPath, diff) {
    if (diff.staged === true && diff.base !== undefined) {
        throw new ScopeError('scope.diff.staged reads the index and scope.diff.base reads commits — pass one of them', 'unsupported_target');
    }
    if (diff.head !== undefined && diff.base === undefined) {
        throw new ScopeError('scope.diff.head needs scope.diff.base', 'unsupported_target');
    }
    const hasCommits = await requireRepo(projectPath, 'scope.diff');
    if (diff.base !== undefined) {
        if (!hasCommits)
            throw new ScopeError('scope.diff.base: the repository has no commits yet', 'target_not_found');
        const baseSha = await resolveCommit(projectPath, diff.base);
        if (baseSha === null)
            throw new ScopeError(`scope.diff.base "${diff.base}" does not name a commit`, 'target_not_found');
        const headLabel = diff.head ?? 'HEAD';
        const headSha = await resolveCommit(projectPath, headLabel);
        if (headSha === null)
            throw new ScopeError(`scope.diff.head "${headLabel}" does not name a commit`, 'target_not_found');
        const checkedOut = await resolveCommit(projectPath, 'HEAD');
        if (headSha !== checkedOut) {
            throw new ScopeError(`scope.diff.head "${headLabel}" is not the checked-out commit — a scoped scan reads files from ` +
                'the working tree. Check it out first, or use review_pr, which checks out another head.', 'unsupported_target');
        }
        const committed = onDisk(projectPath, await changedFilesOrThrow(projectPath, baseSha, headSha));
        const touched = await listZ(projectPath, [
            'log',
            '-z',
            '--name-only',
            '--format=',
            '--relative',
            '--no-renames',
            `${baseSha}..${headSha}`,
            '--',
        ]);
        const extra = diff.include_untracked === true ? onDisk(projectPath, await untracked(projectPath)) : [];
        return {
            files: [...new Set([...committed, ...extra])].sort(),
            touched,
            contentFiles: extra,
            history: { base: baseSha, head: headSha },
            meta: {
                diff: {
                    base: diff.base,
                    head: headLabel,
                    base_sha: baseSha,
                    head_sha: headSha,
                    include_untracked: diff.include_untracked === true,
                },
            },
        };
    }
    const includeUntracked = diff.include_untracked ?? diff.staged !== true;
    let tracked;
    if (diff.staged === true) {
        tracked = hasCommits
            ? await listZ(projectPath, ['diff', '-z', '--name-only', '--relative', '--cached', '--diff-filter=ACMR', '--no-renames', 'HEAD', '--'])
            : await listZ(projectPath, ['ls-files', '-z', '--cached']);
    }
    else {
        tracked = hasCommits
            ? await listZ(projectPath, ['diff', '-z', '--name-only', '--relative', '--diff-filter=d', '--no-renames', 'HEAD', '--'])
            : await listZ(projectPath, ['ls-files', '-z', '--cached']);
    }
    const extra = includeUntracked ? await untracked(projectPath) : [];
    const files = onDisk(projectPath, [...tracked, ...extra]);
    return {
        files,
        touched: [],
        contentFiles: files,
        history: null,
        meta: { diff: { staged: diff.staged === true, include_untracked: includeUntracked } },
    };
}
async function changedFilesOrThrow(projectPath, base, head) {
    try {
        return (await changedFiles(projectPath, base, head)).map(normaliseRelPath);
    }
    catch (e) {
        throw new ScopeError(e instanceof Error ? e.message : String(e), 'target_not_found');
    }
}
/** `YYYY-MM-DD`, optionally with `THH:MM[:SS]`. */
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})(?:T\d{2}:\d{2}(?::\d{2})?)?$/;
/** `2 weeks ago`, `3.days.ago`, `1 month ago`. */
const RELATIVE_DATE = /^(\d{1,4})[ .](second|minute|hour|day|week|month|year)s?[ .]ago$/i;
/**
 * The `--since=` value for `since` when it is a date, or null. Only forms git
 * parses exactly: git's approxidate accepts anything and answers garbage with
 * garbage — `--since=banana` selected no commit and `--since=2999-01-01`
 * selected EVERY commit (measured, git 2.x), either of which would read as a
 * scoped result.
 */
export function sinceDate(since) {
    const s = since.trim();
    if (s.toLowerCase() === 'yesterday')
        return 'yesterday';
    const rel = RELATIVE_DATE.exec(s);
    if (rel !== null)
        return `${rel[1] ?? ''}.${(rel[2] ?? '').toLowerCase()}s.ago`;
    if (ISO_DATE.test(s) && Number.isFinite(Date.parse(s)))
        return s;
    return null;
}
async function resolveSince(projectPath, since) {
    const hasCommits = await requireRepo(projectPath, 'scope.since');
    if (!hasCommits)
        throw new ScopeError('scope.since: the repository has no commits yet', 'target_not_found');
    const headSha = await resolveCommit(projectPath, 'HEAD');
    if (headSha === null)
        throw new ScopeError('scope.since: HEAD names no commit', 'target_not_found');
    const sinceSha = await resolveCommit(projectPath, since);
    if (sinceSha !== null) {
        const touched = await listZ(projectPath, ['log', '-z', '--name-only', '--format=', '--relative', '--no-renames', `${sinceSha}..${headSha}`, '--']);
        return {
            files: onDisk(projectPath, await changedFilesOrThrow(projectPath, sinceSha, headSha)),
            touched,
            contentFiles: [],
            history: { base: sinceSha, head: headSha },
            meta: { since, since_sha: sinceSha, head_sha: headSha },
        };
    }
    const date = sinceDate(since);
    if (date === null) {
        throw new ScopeError(`scope.since "${since}" is neither a commit nor a date (YYYY-MM-DD, "2 weeks ago", "yesterday")`, 'target_not_found');
    }
    if (ISO_DATE.test(date) && Date.parse(date) > Date.now()) {
        throw new ScopeError(`scope.since "${since}" is in the future`, 'unsupported_target');
    }
    const touched = await listZ(projectPath, ['log', '-z', '--name-only', '--format=', '--relative', '--no-renames', `--since=${date}`, headSha, '--']);
    return {
        files: onDisk(projectPath, touched),
        touched,
        contentFiles: [],
        history: { logOpts: `--since=${date}` },
        meta: { since, since_date: date, head_sha: headSha },
    };
}
//# sourceMappingURL=scope.js.map