/**
 * Secret scanning with gitleaks — the one implementation `scan_secrets`,
 * `scan_wordpress` and `review_pr` share.
 *
 * `gitleaks detect` reads COMMITS and nothing else. Every tool used to run it
 * alone, and each of these was reproduced reporting a clean, `ok` scan:
 *
 *   - a repository with history and an uncommitted `.env` — the file most
 *     likely to hold a live secret is the one no commit has seen yet;
 *   - a directory that is not a git repository — "0 commits scanned";
 *   - a repository with no commits yet — likewise.
 *
 * So what gets scanned depends on what the project is:
 *
 *   | project                   | history pass (`gitleaks`)  | files pass                          |
 *   | ------------------------- | -------------------------- | ----------------------------------- |
 *   | git, with commits         | every commit (or log_opts) | uncommitted + untracked-not-ignored |
 *   | git, no commits yet       | skipped — nothing to read  | index + untracked-not-ignored       |
 *   | not a git repository      | —                          | the whole directory                 |
 *   | a commit range (review)   | exactly that range         | —                                   |
 *
 * The files pass copies the files to a temporary directory, keeping their
 * relative paths, and runs `gitleaks detect --no-git -s .` there, so the
 * paths gitleaks reports ARE project-relative, and the fingerprints in the
 * project's `.gitleaksignore` (`<file>:<rule>:<line>`) match. The temporary
 * directory is always removed. Directories no scan of the project's own files
 * should read (`node_modules`, `vendor`, `.git`, build output, `.guardian`)
 * are skipped; so is anything that is not a regular file.
 *
 * A history pass that reports "0 commits scanned" on a repository that HAS
 * commits did not scan — gitleaks prints exactly that when git itself failed
 * (a bad ref, "dubious ownership") and still exits 0 — and is `failed`.
 *
 * Every finding says where it was found, in its `message`: `history`
 * (with the commit), `working_tree`, or `directory`.
 */
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { scannerAvailable, readJsonSafe } from '../tools/scanHelpers.js';
import { countCommits, repoState, resolveCommit, uncommittedFiles } from './git.js';
import { runProcess } from './processRunner.js';
import { listProjectFiles, PROJECT_WALK_EXCLUDE } from './projectFiles.js';
import { gitleaksParser } from './scannerParsers/gitleaks.js';
import { parseInputAsJson } from './scannerParsers/index.js';
/** Name of the history pass in `tools_run` (and of a directory scan). */
export const GITLEAKS_HISTORY = 'gitleaks';
/** Name of the uncommitted-files pass in `tools_run`. */
export const GITLEAKS_WORKING_TREE = 'gitleaks-working-tree';
/** Files larger than this are not copied into the files pass (and are counted). */
const MAX_FILE_BYTES = 25 * 1024 * 1024;
/** Never copied into a files pass, wherever they sit. */
const EXCLUDED_DIRS = [...PROJECT_WALK_EXCLUDE];
export async function runGitleaksScan(opts) {
    const result = { tools_run: [], missing_tools: [], parser_inputs: [], cancelled: false };
    if (!(await scannerAvailable('gitleaks'))) {
        result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'skipped', reason: 'not_installed' });
        result.missing_tools.push('gitleaks');
        return result;
    }
    if (opts.scope.kind === 'range') {
        const range = `${opts.scope.base}..${opts.scope.head}`;
        const commits = await countCommits(opts.projectPath, range);
        if (commits === 0) {
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'skipped',
                reason: `no commits in ${short(opts.scope.base)}..${short(opts.scope.head)}`,
            });
            return result;
        }
        await historyPass(opts, result, range, commits, await repoPrefix(opts.projectPath));
        return result;
    }
    const state = await repoState(opts.projectPath);
    switch (state.kind) {
        case 'has_commits': {
            await historyPass(opts, result, opts.scope.logOpts, null, posixRelative(state.toplevel, opts.projectPath));
            if (result.cancelled)
                return result;
            const files = await uncommittedFiles(opts.projectPath, true, EXCLUDED_DIRS);
            await filesPass(opts, result, files, 'working_tree', GITLEAKS_WORKING_TREE);
            return result;
        }
        case 'no_commits': {
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'skipped',
                reason: 'the repository has no commits yet — no history to scan',
            });
            const files = await uncommittedFiles(opts.projectPath, false, EXCLUDED_DIRS);
            await filesPass(opts, result, files, 'working_tree', GITLEAKS_WORKING_TREE);
            return result;
        }
        case 'error': {
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'failed',
                reason: `git could not read the repository (${state.message}) — history not scanned`,
            });
            await filesPass(opts, result, listProjectFiles(opts.projectPath), 'directory', GITLEAKS_WORKING_TREE);
            return result;
        }
        case 'not_git':
            await filesPass(opts, result, listProjectFiles(opts.projectPath), 'directory', GITLEAKS_HISTORY);
            return result;
    }
}
/**
 * `gitleaks detect` over commits. `logOpts` is passed to `git log` as-is, so
 * it must already be validated ({@link resolveLogOpts}). `expectedCommits` is
 * known for a range; otherwise any repository with commits must scan some.
 */
async function historyPass(opts, result, logOpts, expectedCommits, 
/** The project's path inside its repository ('' at the root): history paths are repo-relative. */
projectPrefix) {
    const outFile = join(opts.reportDir, 'secrets-history.json');
    rmSync(outFile, { force: true });
    const args = [
        'detect',
        '--no-banner',
        '--log-level=info',
        '--report-format=json',
        `--report-path=${outFile}`,
        '--redact',
        '-s',
        opts.projectPath,
    ];
    if (logOpts !== undefined && logOpts.length > 0)
        args.push(`--log-opts=${logOpts}`);
    const run = await runProcess({
        command: 'gitleaks',
        args,
        cwd: opts.projectPath,
        env: opts.env,
        signal: opts.signal,
        onLog: opts.onLog,
    });
    if (run.outcome === 'cancelled')
        result.cancelled = true;
    const raw = readJsonSafe(outFile);
    const commits = commitsScanned(run.stderr);
    const problems = runProblems(run, raw);
    if (commits === 0) {
        problems.push(logOpts
            ? `0 commits scanned for log_opts "${logOpts}" — nothing in that range was checked`
            : '0 commits scanned in a repository that has commits — git history was not read');
    }
    const gitError = gitErrorLine(run.stderr);
    if (gitError)
        problems.push(`git: ${gitError}`);
    if (raw !== null && problems.length === 0) {
        result.parser_inputs.push({ parser: locatedParser('history', projectPrefix), input: raw });
    }
    const scanned = commits ?? expectedCommits;
    result.tools_run.push(problems.length === 0
        ? { name: GITLEAKS_HISTORY, status: 'ok', reason: `history: ${describeCount(scanned, 'commit')} scanned` }
        : { name: GITLEAKS_HISTORY, status: 'failed', reason: problems.join('; ') });
}
/**
 * gitleaks over a list of project files, copied to a temporary directory.
 * `location` is `working_tree` for a repository, `directory` otherwise; the
 * pass is recorded as `gitleaks-working-tree` or `gitleaks` respectively.
 */
async function filesPass(opts, result, files, location, name) {
    const what = location === 'working_tree' ? 'uncommitted or untracked file(s)' : 'file(s)';
    const prefix = location === 'directory' ? 'not a git repository — scanned the directory: ' : 'working tree: ';
    const candidates = files.filter((f) => !isExcluded(f));
    if (candidates.length === 0) {
        result.tools_run.push({
            name,
            status: 'skipped',
            reason: location === 'working_tree' ? 'no uncommitted or untracked files' : 'the directory holds no files to scan',
        });
        return;
    }
    const tmp = mkdtempSync(join(tmpdir(), 'guardian-gitleaks-'));
    try {
        let copied = 0;
        let oversized = 0;
        for (const rel of candidates) {
            const from = join(opts.projectPath, rel);
            let size;
            try {
                const st = lstatSync(from);
                if (!st.isFile())
                    continue;
                size = st.size;
            }
            catch {
                continue;
            }
            if (size > MAX_FILE_BYTES) {
                oversized += 1;
                continue;
            }
            const to = join(tmp, rel);
            mkdirSync(dirname(to), { recursive: true });
            copyFileSync(from, to);
            copied += 1;
        }
        const notes = oversized > 0 ? `; ${oversized} file(s) over 25 MB not scanned` : '';
        if (copied === 0) {
            result.tools_run.push({
                name,
                status: 'skipped',
                reason: `${prefix}no regular file to scan${notes}`,
            });
            return;
        }
        const outFile = join(opts.reportDir, location === 'working_tree' ? 'secrets-working-tree.json' : 'secrets.json');
        rmSync(outFile, { force: true });
        const args = [
            'detect',
            '--no-git',
            '--no-banner',
            '--report-format=json',
            `--report-path=${outFile}`,
            '--redact',
            '-s',
            '.',
            `--gitleaks-ignore-path=${opts.projectPath}`,
        ];
        const projectConfig = join(opts.projectPath, '.gitleaks.toml');
        if (existsSync(projectConfig))
            args.push(`--config=${projectConfig}`);
        const run = await runProcess({
            command: 'gitleaks',
            args,
            cwd: tmp,
            env: opts.env,
            signal: opts.signal,
            onLog: opts.onLog,
        });
        if (run.outcome === 'cancelled')
            result.cancelled = true;
        const raw = readJsonSafe(outFile);
        const problems = runProblems(run, raw);
        if (raw !== null && problems.length === 0) {
            result.parser_inputs.push({ parser: locatedParser(location, ''), input: raw });
            result.tools_run.push({ name, status: 'ok', reason: `${prefix}${copied} ${what} scanned${notes}` });
        }
        else {
            result.tools_run.push({ name, status: 'failed', reason: `${prefix}${problems.join('; ')}` });
        }
    }
    finally {
        rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
}
/** Why a gitleaks run does not count: it did not finish, or wrote no JSON array. */
function runProblems(run, raw) {
    if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
        return [`gitleaks did not finish (${run.outcome})`];
    }
    // 0 = no leaks, 1 = leaks found; anything else is an error.
    if (run.exitCode !== 0 && run.exitCode !== 1) {
        return [`gitleaks exited ${String(run.exitCode)}: ${fatalLine(run.stderr) ?? 'no report'}`];
    }
    if (raw === null)
        return [`gitleaks wrote no report (exit ${String(run.exitCode)}): ${fatalLine(run.stderr) ?? ''}`.trim()];
    if (!Array.isArray(parseInputAsJson(raw)))
        return ['gitleaks report is not a JSON array'];
    return [];
}
/** gitleaks colours its log even when stderr is not a terminal. */
const ANSI = /\u001b\[[0-9;]*m/g;
/** The `N commits scanned.` count gitleaks logs, or null when it logged none. */
export function commitsScanned(stderr) {
    const m = /(\d+)\s+commits?\s+scanned/i.exec(stderr.replace(ANSI, ''));
    return m?.[1] !== undefined ? Number(m[1]) : null;
}
/** First `[git] …` error gitleaks relayed (it exits 0 regardless). */
function gitErrorLine(stderr) {
    for (const line of stderr.replace(ANSI, '').split(/\r?\n/)) {
        const m = /\bERR\b.*\[git\]\s*(.+)$/.exec(line);
        if (m?.[1] !== undefined)
            return m[1].trim();
    }
    return null;
}
function fatalLine(stderr) {
    const lines = stderr.replace(ANSI, '').split(/\r?\n/).map((l) => l.trim());
    return lines.find((l) => /\b(FTL|ERR)\b/.test(l)) ?? lines.find((l) => l.length > 0) ?? null;
}
function isExcluded(rel) {
    return rel.split('/').some((segment) => segment === '.guardian' || segment === '.git');
}
function describeCount(n, noun) {
    return n === null ? `an unreported number of ${noun}s` : `${n} ${noun}(s)`;
}
function short(sha) {
    return sha.slice(0, 12);
}
/**
 * gitleaks' parser, with where the secret was found written into each
 * finding, and history paths (relative to the REPOSITORY root) re-expressed
 * relative to the project when the project is a subdirectory of it.
 */
function locatedParser(location, projectPrefix) {
    return {
        name: gitleaksParser.name,
        parse(input, ctx) {
            const out = gitleaksParser.parse(input, ctx);
            return { findings: out.findings.map((f) => locate(f, location, projectPrefix)), cves: out.cves };
        },
    };
}
/** `projectPath` relative to the repository root, `/`-separated ('' when they are the same). */
async function repoPrefix(projectPath) {
    const state = await repoState(projectPath);
    return state.kind === 'has_commits' || state.kind === 'no_commits'
        ? posixRelative(state.toplevel, projectPath)
        : '';
}
function posixRelative(toplevel, projectPath) {
    const rel = relative(resolve(toplevel), resolve(projectPath)).replace(/\\/g, '/');
    return rel.startsWith('..') ? '' : rel;
}
function locate(f, location, projectPrefix) {
    const located = { ...f };
    if (projectPrefix !== '' && f.file_path?.startsWith(`${projectPrefix}/`)) {
        located.file_path = f.file_path.slice(projectPrefix.length + 1);
    }
    const commit = /;commit=([0-9a-f]+)/.exec(f.snippet ?? '')?.[1];
    const where = location === 'history'
        ? `location: history${commit ? ` (commit ${commit.slice(0, 12)})` : ''} — the secret is in a commit; ` +
            'removing it from the file does not remove it from the repository, rotate it'
        : location === 'working_tree'
            ? 'location: working_tree — in an uncommitted or untracked file, not (yet) in any commit'
            : 'location: directory — the project is not a git repository';
    return { ...located, message: where };
}
// ---- log_opts ---------------------------------------------------------
/** One ref in a range: starts with an alphanumeric, no whitespace or shell syntax. */
const REF = /^[A-Za-z0-9][A-Za-z0-9._/@{}~^-]*$/;
const SINCE = /^--since=[A-Za-z0-9][A-Za-z0-9:._+-]*$/;
export class LogOptsError extends Error {
    kind;
    constructor(message, 
    /** `unresolved_ref` when a ref names no commit; `invalid` otherwise. */
    kind) {
        super(message);
        this.kind = kind;
        this.name = 'LogOptsError';
    }
}
/**
 * Validate `log_opts` against the safe subset — `--all`, `<ref>..<ref>` (or
 * `...`), `--since=<date>` — and rewrite every ref to the commit id it names.
 * gitleaks splits the string on spaces and hands the pieces to `git log`, so
 * anything outside that subset (`--output=…`, `-p`, a path) is refused rather
 * than passed through. Throws {@link LogOptsError}.
 */
export async function resolveLogOpts(cwd, raw) {
    const tokens = raw.trim().split(/\s+/).filter((t) => t.length > 0);
    if (tokens.length === 0)
        return undefined;
    if (tokens.length > 4)
        throw new LogOptsError(`log_opts takes at most 4 options (got ${tokens.length})`, 'invalid');
    const out = [];
    for (const token of tokens) {
        if (token === '--all' || SINCE.test(token)) {
            out.push(token);
            continue;
        }
        const m = /^(.+?)(\.\.\.?)(.+)$/.exec(token);
        const left = m?.[1];
        const dots = m?.[2];
        const right = m?.[3];
        if (left === undefined || dots === undefined || right === undefined || !REF.test(left) || !REF.test(right)) {
            throw new LogOptsError(`log_opts option "${token}" is not allowed — use --all, <ref>..<ref> or --since=<date>`, 'invalid');
        }
        const from = await resolveCommit(cwd, left);
        if (from === null)
            throw new LogOptsError(`log_opts ref "${left}" does not name a commit`, 'unresolved_ref');
        const to = await resolveCommit(cwd, right);
        if (to === null)
            throw new LogOptsError(`log_opts ref "${right}" does not name a commit`, 'unresolved_ref');
        out.push(`${from}${dots}${to}`);
    }
    return out.join(' ');
}
//# sourceMappingURL=gitleaksScan.js.map