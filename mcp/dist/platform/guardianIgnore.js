/**
 * `.guardianignore` — paths a project declares are not its own code to scan.
 *
 * Self-scanning dev-guardian reported its own deliberately vulnerable test
 * fixtures (`mcp/test/fixtures/**`) as critical and high findings: every rule
 * pack ships a `hits/` tree whose whole purpose is to be flagged. A project
 * says so once, in `.guardianignore` at its root, in gitignore syntax, and
 * every scanner honours it.
 *
 * ---- Two layers, and which one is the guarantee ---------------------------
 *
 *   1. **The result filter** (`ignores`) — every finding of every scan tool
 *      built on the scan factory passes through it before anything is
 *      stored. This is the guarantee: it implements the syntax exactly (it is
 *      tested against `git check-ignore` itself), and it covers scanners that
 *      have no exclusion flag at all (gitleaks, jscpd, ruff, …).
 *   2. **Native flags** — Semgrep `--exclude`, Trivy `--skip-dirs` /
 *      `--skip-files`, Bandit `-x` — so the scanner never reads an excluded
 *      tree in the first place. They are derived from the project's file list
 *      (`excludedDirs` / `excludedFiles`: the top-most excluded paths, exact),
 *      never by translating patterns, because each scanner reads a pattern
 *      differently. Measured on Semgrep 1.176.1: `--exclude` is read as
 *      gitignore (`docs` at any depth, `/docs` anchored) — and anchored at
 *      the GIT ROOT, not at the scan target: with the project at `repo/sub`,
 *      `--exclude=/fixtures` excluded nothing and `--exclude=/sub/lib` (meant
 *      for `<project>/sub/lib`) excluded the kept `<project>/lib` instead. So
 *      the anchor is the project's `git rev-parse --show-prefix` (the target
 *      itself outside git), and no Semgrep flag at all when that cannot be
 *      known. Trivy anchors `--skip-dirs` / `--skip-files` at its target (a
 *      single segment too). Bandit's `-x` is a SUBSTRING test on the path as
 *      it walks it (plus `fnmatch`), so only an absolute native path works — a
 *      relative `data/fx` excluded nothing on Windows. A path holding glob
 *      syntax (`pages/[id].test.js`) is a pattern to all three — `--exclude`
 *      of that name excluded `pages/i.py` and kept itself — so it is never
 *      passed. A native flag that could exclude MORE than the file says under
 *      some reading is not passed either: the filter still applies, so a
 *      withheld flag costs only speed, never a silent gap.
 *
 * Exclusion is never silent: the factory reports how many files the ignore
 * file excludes and how many findings it dropped on every scan of a project
 * that has one.
 *
 * Only the file at the project root is read; `.guardianignore` files in
 * subdirectories are not (gitignore's per-directory files are not supported).
 */
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { git, splitNul } from '../runners/git.js';
import { listProjectFiles, PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { describeReadRefusal, readProjectText, readProjectTextOrUndefined } from './projectFs.js';
/** The largest `.guardianignore` read; a real one is a few KB. */
const MAX_GUARDIAN_IGNORE_BYTES = 1024 * 1024;
export const GUARDIAN_IGNORE_FILE = '.guardianignore';
/** Bandit's own default `-x` list — replaced, not extended, by passing `-x`. */
const BANDIT_DEFAULT_EXCLUDES = ['.svn', 'CVS', '.bzr', '.hg', '.git', '__pycache__', '.tox', '.eggs', '*.egg'];
/** Glob syntax to Semgrep's gitignore reader and Trivy's doublestar (tested on POSIX paths). */
const GLOB_SYNTAX = /[*?[\]{}\\]/;
/** Glob syntax to Bandit's `fnmatch` (tested on native absolute paths, backslashes and all). */
const FNMATCH_SYNTAX = /[*?[\]]/;
/** Most native exclusion entries passed to one scanner; the rest are filtered from results only. */
const MAX_NATIVE_ENTRIES = 200;
/** Most characters of native exclusion arguments (the command line is shared with targets). */
const MAX_NATIVE_CHARS = 8_000;
/** Parse gitignore-syntax text into a matcher. */
export function compileIgnore(text) {
    const rules = [];
    for (const rawLine of text.split(/\r?\n/)) {
        const rule = parseLine(rawLine);
        if (rule !== null)
            rules.push(rule);
    }
    /** The last rule matching this exact path decides; no rule means kept. */
    const decide = (path, isDir) => {
        let ignored = false;
        for (const rule of rules) {
            if (rule.dirOnly && !isDir)
                continue;
            if (rule.regex.test(path))
                ignored = !rule.negated;
        }
        return ignored;
    };
    return {
        patterns: rules.length,
        ignores(relPath, isDir = false) {
            const path = normalise(relPath);
            if (path === null || path === '')
                return false;
            const segments = path.split('/');
            // A file inside an excluded directory cannot be re-included (git).
            for (let i = 1; i < segments.length; i++) {
                if (decide(segments.slice(0, i).join('/'), true))
                    return true;
            }
            return decide(path, isDir);
        },
    };
}
/**
 * A project-relative path in POSIX form without a leading `./`, or null when
 * it is not relative to the project at all (absolute, or climbing out).
 */
function normalise(relPath) {
    let p = relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
    if (p.startsWith('/') || /^[A-Za-z]:\//.test(p))
        return null;
    p = p.replace(/\/{2,}/g, '/');
    if (p === '..' || p.startsWith('../'))
        return null;
    return p;
}
function parseLine(rawLine) {
    // Trailing spaces are ignored unless escaped with a backslash.
    let line = rawLine.replace(/(?<!\\)[ \t]+$/, '');
    if (line.length === 0 || line.startsWith('#'))
        return null;
    let negated = false;
    if (line.startsWith('!')) {
        negated = true;
        line = line.slice(1);
    }
    else if (line.startsWith('\\!') || line.startsWith('\\#')) {
        line = line.slice(1);
    }
    let dirOnly = false;
    if (line.endsWith('/') && !line.endsWith('\\/')) {
        dirOnly = true;
        line = line.replace(/\/+$/, '');
    }
    if (line.length === 0)
        return null;
    // A slash at the start or in the middle anchors the pattern at the root;
    // otherwise it matches at any depth.
    const anchored = line.includes('/');
    if (line.startsWith('/'))
        line = line.slice(1);
    if (line.length === 0)
        return null;
    const body = globBody(line);
    const regex = new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}$`);
    return { negated, dirOnly, regex };
}
/** gitignore glob → regex source (unanchored), per gitignore(5). */
function globBody(pattern) {
    let re = '';
    let i = 0;
    while (i < pattern.length) {
        const c = pattern.charAt(i);
        if (c === '*') {
            if (pattern.charAt(i + 1) === '*') {
                const atStart = i === 0 || pattern.charAt(i - 1) === '/';
                const atEnd = i + 2 === pattern.length;
                const beforeSlash = pattern.charAt(i + 2) === '/';
                if (atStart && beforeSlash) {
                    // `**/` — zero or more leading directories.
                    re += '(?:.*/)?';
                    i += 3;
                    continue;
                }
                if (atStart && atEnd) {
                    // `/**` at the end (or a lone `**`): everything inside.
                    re += '.*';
                    i += 2;
                    continue;
                }
                // Any other run of asterisks is an ordinary `*`.
                while (pattern.charAt(i) === '*')
                    i += 1;
                re += '[^/]*';
                continue;
            }
            re += '[^/]*';
            i += 1;
        }
        else if (c === '?') {
            re += '[^/]';
            i += 1;
        }
        else if (c === '[') {
            const close = findClassEnd(pattern, i);
            if (close === -1) {
                re += '\\[';
                i += 1;
                continue;
            }
            let cls = pattern.slice(i + 1, close);
            let negate = false;
            if (cls.startsWith('!') || cls.startsWith('^')) {
                negate = true;
                cls = cls.slice(1);
            }
            cls = cls.replace(/\\(.)/g, '$1').replace(/[\\\]^]/g, '\\$&');
            re += `[${negate ? '^' : ''}${cls}]`;
            i = close + 1;
        }
        else if (c === '\\' && i + 1 < pattern.length) {
            re += escapeRegExp(pattern.charAt(i + 1));
            i += 2;
        }
        else {
            re += escapeRegExp(c);
            i += 1;
        }
    }
    return re;
}
/** Index of the `]` closing the class opened at `start`, or -1. A `]` first in the class is literal. */
function findClassEnd(pattern, start) {
    let j = start + 1;
    if (pattern.charAt(j) === '!' || pattern.charAt(j) === '^')
        j += 1;
    if (pattern.charAt(j) === ']')
        j += 1;
    for (; j < pattern.length; j++) {
        if (pattern.charAt(j) === '\\') {
            j += 1;
            continue;
        }
        if (pattern.charAt(j) === ']')
            return j;
    }
    return -1;
}
function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
/**
 * The project's `.guardianignore`, compiled and applied to the project's
 * files. Null when there is no such file; an error object when it exists and
 * cannot be read — the caller must say so, never proceed as if nothing were
 * excluded without a word.
 *
 * The files are git's own listing in a work tree (tracked, plus untracked
 * files `.gitignore` does not exclude — what Semgrep and the tree hash read,
 * and never a crawl of a gitignored `data/` of a million files), else a walk
 * of the directory. Either way `PROJECT_WALK_EXCLUDE` (`node_modules`,
 * `.git`, `.guardian`, build output, …) is left out: no scan of the
 * project's own files reads those.
 *
 * `configRoot` is where the file itself is read — the project, unless the CI
 * gate took it from `--rules-ref` (`ci/refConfig.ts`): the ref's copy is then
 * applied to the project's files, and the project's own is never read.
 */
export async function loadProjectExclusions(projectPath, configRoot = projectPath) {
    const file = join(configRoot, GUARDIAN_IGNORE_FILE);
    // The repository's file (or the CI gate's --rules-ref copy): bounded,
    // regular files only, never through a link out of its root
    // (`platform/projectFs.ts`). One that is there and refused is an error the
    // caller reports, never "nothing excluded".
    const read = readProjectText(configRoot, GUARDIAN_IGNORE_FILE, MAX_GUARDIAN_IGNORE_BYTES);
    if (read.status === 'absent')
        return null;
    if (read.status === 'refused')
        return { file, error: `not read: ${describeReadRefusal(read.reason)}` };
    const text = read.text;
    const matcher = compileIgnore(text);
    const listed = await gitListFiles(projectPath);
    let semgrepAnchor;
    if (listed !== null) {
        const prefix = await git(projectPath, ['rev-parse', '--show-prefix']);
        semgrepAnchor = prefix.exitCode === 0 ? prefix.stdout.trim() : null;
    }
    else {
        // git could not list the project: outside any work tree Semgrep anchors
        // at the target; inside one (git failing for another reason) the anchor
        // is unknown.
        semgrepAnchor = insideGitWorkTree(projectPath) ? null : '';
    }
    return {
        file,
        hash: createHash('sha256').update(text).digest('hex'),
        patterns: matcher.patterns,
        ignores: (relPath, isDir) => matcher.ignores(relPath, isDir),
        ...classify(listed ?? listProjectFiles(projectPath), matcher),
        semgrepAnchor,
    };
}
/** A name no file has, to ask whether EVERYTHING inside a directory is excluded (`libs/core/**`). */
const PROBE_CHILD = '.guardian-probe-7f3a';
/**
 * The submodules (project-relative directories) the project's
 * `.guardianignore` leaves in (round 4, item 6). One it excludes — by name
 * (`libs/core`), by a directory above it (`libs/`), or all of its contents
 * (`libs/core/**`) — is not the project's to scan, so its unscanned
 * contents are no gap; one it excludes only part of (`libs/core/*.js`) still
 * is. A `.guardianignore` that cannot be read excludes nothing here: the gap
 * stays named. `configRoot` is where it is read — the CI gate's `--rules-ref`
 * copy (`ci/refConfig.ts`) instead of the project, like `loadProjectExclusions`.
 */
export function submodulesNotIgnored(projectPath, submodules, configRoot = projectPath) {
    if (submodules.length === 0)
        return [];
    const text = readProjectTextOrUndefined(configRoot, GUARDIAN_IGNORE_FILE, MAX_GUARDIAN_IGNORE_BYTES);
    if (text === undefined)
        return [...submodules];
    const matcher = compileIgnore(text);
    return submodules.filter((sub) => !matcher.ignores(sub, true) && !matcher.ignores(`${sub}/${PROBE_CHILD}`, false));
}
/**
 * Is a finding's `file_path` a path IN the project — the file itself, or a
 * directory it would sit in (a secret in a file a later commit deleted)? A
 * container image target (`alpine:3.18 (alpine 3.18.4)`) or Trivy's `Node.js`
 * pseudo-target can match a pattern (`alpine*`, `*.js`) and is no project
 * file: the result filter leaves those alone. A deleted top-level file has no
 * directory left to place it by and is kept too — the direction that never
 * hides a finding.
 */
export function isProjectPath(projectPath, relPath) {
    return projectPathTest(projectPath)(relPath);
}
/**
 * {@link isProjectPath} for many paths of one project, asking the disk about
 * each DIRECTORY once: a scan's result filter used to `existsSync` every
 * finding (20 000 findings: 2-4 s on Windows). A path below the top level is
 * in the project exactly when one of its directories exists — the file itself
 * cannot exist without its directory — so only a top-level path (or one with
 * a `.`/`..` segment, where the lexical parent is not the real one) is looked
 * up by its own name. Answers are memoised for the returned function's
 * lifetime: make one per scan.
 */
export function projectPathTest(projectPath) {
    const exists = new Map();
    const onDisk = (segments) => {
        const key = segments.join('/');
        let v = exists.get(key);
        if (v === undefined) {
            v = existsSync(join(projectPath, ...segments));
            exists.set(key, v);
        }
        return v;
    };
    return (relPath) => {
        const p = relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
        if (p === '' || p.startsWith('/') || /^[A-Za-z]:/.test(p) || p === '..' || p.startsWith('../'))
            return false;
        const segments = p.split('/');
        if (segments.length === 1 || segments.some((s) => s === '.' || s === '..')) {
            if (onDisk(segments))
                return true;
        }
        for (let i = segments.length - 1; i >= 1; i--) {
            if (onDisk(segments.slice(0, i)))
                return true;
        }
        return false;
    };
}
/** A `.git` (directory or worktree file) in the project or one of its ancestors. */
function insideGitWorkTree(projectPath) {
    for (let dir = resolve(projectPath);; dir = dirname(dir)) {
        if (existsSync(join(dir, '.git')))
            return true;
        if (dirname(dir) === dir)
            return false;
    }
}
/** `git ls-files` of the work tree at `root`, relative to it; null outside git. */
async function gitListFiles(root) {
    const r = await git(root, [
        'ls-files',
        '-z',
        '--cached',
        '--others',
        '--exclude-standard',
        ...[...PROJECT_WALK_EXCLUDE].map((d) => `--exclude=${d}/`),
    ]);
    if (r.exitCode !== 0)
        return null;
    const files = new Set();
    for (const entry of splitNul(r.stdout)) {
        // Tracked files under an excluded directory name are listed by git; no
        // walk of the project would see them.
        if (entry.split('/').some((segment) => PROJECT_WALK_EXCLUDE.has(segment)))
            continue;
        files.add(entry);
    }
    return [...files];
}
/**
 * Each file is excluded by its top-most excluded directory, or by its own
 * pattern, or kept. Directory verdicts are memoised: a tree of thousands of
 * files under one excluded directory costs one match per directory.
 */
function classify(files, matcher) {
    const dirVerdict = new Map();
    const dirIgnored = (dir) => {
        let v = dirVerdict.get(dir);
        if (v === undefined) {
            v = matcher.ignores(dir, true);
            dirVerdict.set(dir, v);
        }
        return v;
    };
    const excludedDirs = new Set();
    const excludedFiles = [];
    const keptFiles = [];
    let excludedFileCount = 0;
    for (const f of files) {
        const segments = f.split('/');
        let top = null;
        for (let i = 1; i < segments.length; i++) {
            const dir = segments.slice(0, i).join('/');
            if (dirIgnored(dir)) {
                top = dir;
                break;
            }
        }
        if (top !== null) {
            excludedDirs.add(top);
            excludedFileCount += 1;
        }
        else if (matcher.ignores(f, false)) {
            excludedFiles.push(f);
            excludedFileCount += 1;
        }
        else {
            keptFiles.push(f);
        }
    }
    return {
        excludedDirs: [...excludedDirs].sort(),
        excludedFiles: excludedFiles.sort(),
        excludedFileCount,
        keptFiles: keptFiles.sort(),
    };
}
function nativeEntries(ex) {
    return [
        ...ex.excludedDirs.map((rel) => ({ rel, dir: true })),
        ...ex.excludedFiles.map((rel) => ({ rel, dir: false })),
    ];
}
/**
 * Would an UNANCHORED reading of `entry` (a scanner treating `a/b` as "a/b at
 * any depth") also exclude a file the ignore file keeps?
 */
function widensOntoKept(entry, kept) {
    const needle = `/${entry.rel}`;
    return kept.some((k) => {
        const hay = `/${k}`;
        return entry.dir ? hay.includes(`${needle}/`) : hay.endsWith(needle);
    });
}
/** Keep entries until the count or character budget is spent. */
function withinBudget(items, cost) {
    const out = [];
    let used = 0;
    for (const item of items) {
        if (out.length >= MAX_NATIVE_ENTRIES)
            break;
        const c = cost(item);
        if (used + c > MAX_NATIVE_CHARS)
            break;
        out.push(item);
        used += c;
    }
    return out;
}
/**
 * `--exclude=/<anchor><path>` per top-most excluded path. The leading slash
 * anchors it at the GIT ROOT, where Semgrep 1.176.1 anchors it (measured —
 * see the module comment), hence `semgrepAnchor`; unknown anchor, no flags.
 * An entry holding glob syntax, or one an unanchored reading would widen onto
 * a kept file, is left to the result filter.
 */
export function semgrepExcludeArgs(ex) {
    if (ex === null || ex.semgrepAnchor === null)
        return [];
    const anchor = ex.semgrepAnchor;
    const patterns = nativeEntries(ex)
        .filter((e) => !widensOntoKept(e, ex.keptFiles))
        .map((e) => `/${anchor}${e.rel}`)
        // Glob syntax, or a trailing space gitignore would trim: not this path.
        .filter((p) => !GLOB_SYNTAX.test(p) && !/\s$/.test(p));
    return withinBudget(patterns.map((p) => `--exclude=${p}`), (a) => a.length + 3);
}
/**
 * `--skip-dirs <dir>` / `--skip-files <file>`, project-relative: Trivy
 * matches them against the path relative to the scan target, anchored
 * (measured — `data/fx` skips `data/fx`, not `x/data/fx`; `data` skips only
 * the top-level one). They are doublestar patterns: a path with glob syntax
 * is left to the result filter.
 */
export function trivySkipArgs(ex) {
    if (ex === null)
        return [];
    const args = [];
    const plain = nativeEntries(ex).filter((e) => !GLOB_SYNTAX.test(e.rel));
    for (const e of withinBudget(plain, (entry) => entry.rel.length + 16)) {
        args.push(e.dir ? '--skip-dirs' : '--skip-files', e.rel);
    }
    return args;
}
/**
 * `-x <list>`: Bandit's defaults plus the absolute path of every top-most
 * excluded path (a directory with a trailing separator, so `data/fx` does not
 * also match `data/fx2`). Bandit tests each as a substring of the path it
 * walks, so an entry that is a prefix of a kept file's path, or holds a comma
 * (the list separator), is left to the result filter. Empty when nothing is
 * excluded — Bandit's own defaults then stay in force.
 */
export function banditExcludeArgs(ex, projectPath) {
    if (ex === null)
        return [];
    const keptAbs = ex.keptFiles.map((k) => join(projectPath, ...k.split('/')));
    const entries = nativeEntries(ex)
        .filter((e) => !e.rel.includes(','))
        .map((e) => {
        const abs = join(projectPath, ...e.rel.split('/'));
        return e.dir ? `${abs}${sep}` : abs;
    })
        .filter((abs) => !FNMATCH_SYNTAX.test(abs) && !keptAbs.some((k) => k.includes(abs)));
    const chosen = withinBudget(entries, (a) => a.length + 1);
    if (chosen.length === 0)
        return [];
    return ['-x', [...BANDIT_DEFAULT_EXCLUDES, ...chosen].join(',')];
}
//# sourceMappingURL=guardianIgnore.js.map