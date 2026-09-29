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
 *   | not a git repository      | —                          | the whole directory, in place       |
 *   | a commit range (review)   | exactly that range         | uncommitted files, when asked       |
 *   | a scoped scan             | the scope's range/--since  | exactly the scope's files           |
 *
 * **A scoped scan** (`platform/scope.ts`) reads only what its scope names:
 * `scope.diff.base` / `scope.since` are commit ranges (or `--since=<date>`)
 * for the history pass, and the scope's files — `paths`, or the staged /
 * uncommitted changes — go through the same copy-and-scan as uncommitted
 * files, whether or not a commit holds them.
 *
 * **Uncommitted files** are copied to a temporary directory, keeping their
 * relative paths, and scanned there with `gitleaks detect --no-git -s .`, so
 * the paths gitleaks reports ARE project-relative and the fingerprints in the
 * project's `.gitleaksignore` (`<file>:<rule>:<line>`) match. The copy has a
 * per-file and a total size limit; a file over either, or one that cannot be
 * read (EACCES, EBUSY), is not scanned and the pass says so — it is a named
 * gap (`ok` in `tools_run`, its name in `missing_tools`: "ran with reduced
 * coverage"), never a crashed scan. The temporary directory is removed; a
 * failure to remove it is noted, never allowed to discard results.
 *
 * **A directory that is not a repository** is scanned IN PLACE —
 * `gitleaks detect --no-git -s .` in the project — with a generated config
 * that extends the project's own `.gitleaks.toml` (or gitleaks' defaults) and
 * allowlists the directories no scan of the project's own files reads
 * (`node_modules`, `vendor`, `.git`, build output, `.guardian`). Copying it
 * first is not an option: the common case is a WordPress site copied off a
 * server, whose `wp-content/uploads` alone can be gigabytes.
 *
 * A history pass that reports "0 commits scanned" on a repository that HAS
 * commits did not scan — gitleaks prints exactly that when git itself failed
 * (a bad ref, "dubious ownership") and still exits 0 — and is `failed`. So is
 * any pass git could not list files for: every git error becomes a `failed`
 * pass, and nothing this helper meets is allowed to throw out of it and take
 * the passes that did finish with it.
 *
 * Every finding says where it was found, in its `message`: `history`
 * (with the commit), `working_tree`, or `directory`.
 *
 * **Every run uses `--redact`** — except for `scan_secrets verify_live`
 * (`captureSecrets`), which needs the values themselves. Such a run writes
 * its report into a private temporary directory instead of the report
 * directory (`secrets/verify/rawReport.ts`: 0700/0600 on POSIX), reads it
 * once, keeps the values of the verifiable rules in memory
 * (`GitleaksScanResult.captured`), deletes it, and hands on — and keeps under
 * `.guardian/reports` — only the sanitized report, every value replaced by
 * `REDACTED`. The directory is removed when the passes are done.
 */
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { openPrivateReportDir, sanitizeGitleaksReport } from '../secrets/verify/rawReport.js';
import { scannerAvailable, readJsonSafe } from '../tools/scanHelpers.js';
import { countCommits, git, repoState, resolveCommit, shallowBoundary, uncommittedFiles } from './git.js';
import { runProcess } from './processRunner.js';
import { PROJECT_WALK_EXCLUDE } from './projectFiles.js';
import { gitleaksParser } from './scannerParsers/gitleaks.js';
import { parseInputAsJson } from './scannerParsers/index.js';
/** Name of the history pass in `tools_run` (and of a directory scan). */
export const GITLEAKS_HISTORY = 'gitleaks';
/** Name of the uncommitted-files pass in `tools_run`. */
export const GITLEAKS_WORKING_TREE = 'gitleaks-working-tree';
/** Uncommitted files larger than this are not copied (a named gap). */
const MAX_FILE_BYTES = 25 * 1024 * 1024;
/** The uncommitted-files copy stops at this many bytes in total (a named gap). */
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
/** Never scanned by a files pass, wherever they sit. */
const EXCLUDED_DIRS = [...PROJECT_WALK_EXCLUDE];
export async function runGitleaksScan(opts) {
    const result = { tools_run: [], missing_tools: [], parser_inputs: [], cancelled: false };
    let raw = null;
    if (opts.captureSecrets !== undefined) {
        try {
            raw = openPrivateReportDir();
            result.captured = new Map();
        }
        catch (e) {
            // Never a fallback to an unredacted report anywhere else: the runs redact.
            result.capture_error = `no private temporary directory for the unredacted report (${errorCode(e)})`;
        }
    }
    try {
        await scan({ ...opts, raw }, result);
    }
    catch (e) {
        // Every step below handles its own failures; this is the net under them,
        // so a pass that did finish is never lost to one that did not.
        result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'failed', reason: `secret scan failed: ${message(e)}` });
    }
    finally {
        const failed = raw === null ? null : raw.remove();
        if (raw !== null && failed !== null) {
            const note = `the private temporary directory ${raw.dir} may still hold unredacted gitleaks output and could ` +
                `not be removed (${failed}) — delete it`;
            const entry = result.tools_run[0];
            if (entry)
                entry.reason = entry.reason ? `${entry.reason}; ${note}` : note;
            else
                result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'failed', reason: note });
        }
    }
    return result;
}
async function scan(opts, result) {
    if (!(await scannerAvailable('gitleaks'))) {
        result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'skipped', reason: 'not_installed' });
        result.missing_tools.push('gitleaks');
        return;
    }
    if (opts.scope.kind === 'scoped') {
        await scopedScan(opts, result, opts.scope);
        return;
    }
    if (opts.scope.kind === 'range') {
        const range = `${opts.scope.base}..${opts.scope.head}`;
        let commits;
        try {
            commits = await countCommits(opts.projectPath, range);
        }
        catch (e) {
            result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'failed', reason: message(e) });
            return;
        }
        if (commits === 0) {
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'skipped',
                reason: `no commits in ${short(opts.scope.base)}..${short(opts.scope.head)}`,
            });
        }
        else {
            await historyPass(opts, result, range, commits, await repoPrefix(opts.projectPath));
        }
        if (opts.scope.workingTree === true && !result.cancelled)
            await workingTreePass(opts, result, true);
        return;
    }
    const state = await repoState(opts.projectPath);
    switch (state.kind) {
        case 'has_commits':
            await historyPass(opts, result, opts.scope.logOpts, null, posixRelative(state.toplevel, opts.projectPath));
            if (!result.cancelled)
                await workingTreePass(opts, result, true);
            return;
        case 'no_commits':
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'skipped',
                reason: 'the repository has no commits yet — no history to scan',
            });
            await workingTreePass(opts, result, false);
            return;
        case 'error':
            result.tools_run.push({
                name: GITLEAKS_HISTORY,
                status: 'failed',
                reason: `git could not read the repository (${state.message}) — history not scanned`,
            });
            await directoryPass(opts, result, GITLEAKS_WORKING_TREE);
            return;
        case 'not_git':
            await directoryPass(opts, result, GITLEAKS_HISTORY);
            return;
    }
}
/**
 * A scoped scan — see the module comment. A history the scope names that
 * holds no commit is `skipped` (nothing changed there), never a failed
 * "0 commits scanned".
 */
async function scopedScan(opts, result, scope) {
    const { history, files } = scope;
    if (history !== null) {
        const logOpts = 'base' in history ? `${history.base}..${history.head}` : history.logOpts;
        const label = 'base' in history ? `${short(history.base)}..${short(history.head)}` : history.logOpts;
        let commits = null;
        try {
            commits =
                'base' in history
                    ? await countCommits(opts.projectPath, logOpts)
                    : await countCommitsSince(opts.projectPath, logOpts);
        }
        catch (e) {
            result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'failed', reason: message(e) });
        }
        if (commits === 0) {
            result.tools_run.push({ name: GITLEAKS_HISTORY, status: 'skipped', reason: `no commits in ${label}` });
        }
        else if (commits !== null) {
            await historyPass(opts, result, logOpts, commits, await repoPrefix(opts.projectPath));
        }
    }
    if (result.cancelled)
        return;
    // A commit-range scope with no untracked additions has nothing more to read.
    if (history !== null && files.length === 0)
        return;
    await filesPass(opts, result, files, {
        none: 'the scope holds no file',
        scanned: (n) => `scope: ${n} file(s) scanned, read from the working tree`,
    });
}
/** `git rev-list --count <--since=…> HEAD` — `logOpts` is one validated `--since=` option. */
async function countCommitsSince(cwd, logOpts) {
    const r = await git(cwd, ['rev-list', '--count', logOpts, 'HEAD', '--']);
    const n = Number(r.stdout.trim());
    if (r.exitCode !== 0 || !Number.isInteger(n)) {
        throw new Error(`git rev-list --count ${logOpts} failed: ${r.stderr.trim() || `exit ${r.exitCode}`}`);
    }
    return n;
}
/**
 * `gitleaks detect` over commits. `logOpts` is passed to `git log` as-is, so
 * it must already be validated ({@link resolveLogOpts}). `expectedCommits` is
 * known for a range; otherwise any repository with commits must scan some.
 * Either way the pass counts only on gitleaks' own word: its logged count,
 * or findings in its report.
 */
async function historyPass(opts, result, logOpts, expectedCommits, 
/** The project's path inside its repository ('' at the root): history paths are repo-relative. */
projectPrefix) {
    const outFile = join(opts.reportDir, 'secrets-history.json');
    rmSync(outFile, { force: true });
    const target = reportTarget(opts, outFile);
    const args = [
        'detect',
        '--no-banner',
        '--log-level=info',
        '--report-format=json',
        `--report-path=${target.path}`,
        ...target.redact,
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
    const report = takeReport(opts, target.path, outFile);
    const raw = report.text;
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
    // Every history pass runs on a repository — or a range — that holds
    // commits. gitleaks logging no count at all (a release that changed its
    // `N commits scanned.` line, or one that never walked the history) leaves
    // nothing saying history was read; git's own count of the range says what
    // there was to read, not what was. Only a report with findings proves it.
    if (commits === null && problems.length === 0 && reportFindings(raw) === 0) {
        problems.push('gitleaks logged no commit count and reported nothing — cannot tell that git history was read ' +
            `(its "N commits scanned" log line is missing${expectedCommits !== null ? `; git counts ${describeCount(expectedCommits, 'commit')} to read` : ''})`);
    }
    if (raw !== null && problems.length === 0) {
        pushParserInput(result, { parser: locatedParser('history', projectPrefix), input: raw }, report.secrets);
    }
    // A shallow clone's history ends at its boundary: what gitleaks read is
    // all there was HERE, not all there is (review I4). Ran, with a named gap.
    const truncated = await truncatedAt(opts.projectPath, logOpts);
    const truncation = truncated.length === 0
        ? null
        : `history truncated at ${truncated.slice(0, 3).map((s) => s.slice(0, 12)).join(', ')}${truncated.length > 3 ? ` and ${truncated.length - 3} more` : ''} — a shallow clone: the commits before it were not scanned (git fetch --unshallow, then re-run)`;
    // A missing count reaches here only with findings: say so, never git's count as gitleaks'.
    const scanned = commits;
    const reasons = problems.length === 0 ? [`history: ${describeCount(scanned, 'commit')} scanned`] : problems;
    if (truncation !== null) {
        reasons.push(truncation);
        result.missing_tools.push(GITLEAKS_HISTORY);
    }
    result.tools_run.push({
        name: GITLEAKS_HISTORY,
        status: problems.length === 0 ? 'ok' : 'failed',
        reason: reasons.join('; '),
    });
}
/**
 * The shallow-boundary commits the history pass's own walk reaches, or none
 * — review I4: `git clone --depth 1` of a repository whose secret was
 * removed in a later commit read "1 commit(s) scanned", coverage full, 0
 * findings. With no `log_opts` gitleaks walks every ref (`git log
 * --full-history --all`), so every boundary is reached; a range or
 * `--since=` reaches the boundaries `git rev-list` lists for it. A shallow
 * repository whose walk cannot be listed is reported truncated: the gap is
 * never assumed away.
 */
async function truncatedAt(cwd, logOpts) {
    const boundary = await shallowBoundary(cwd);
    if (boundary === null)
        return [];
    if (logOpts === undefined || logOpts.length === 0 || boundary.includes('(unknown)'))
        return boundary;
    // `logOpts` is validated (`resolveLogOpts`): --all, --since=<date>, resolved ranges.
    const tokens = logOpts.split(' ').filter((t) => t.length > 0);
    const hasRev = tokens.some((t) => t === '--all' || t.includes('..'));
    const r = await git(cwd, ['rev-list', ...tokens, ...(hasRev ? [] : ['HEAD']), '--']);
    if (r.exitCode !== 0)
        return boundary;
    const reached = new Set(r.stdout.split(/\r?\n/).map((l) => l.trim()));
    return boundary.filter((b) => reached.has(b));
}
/**
 * The files of a repository that no commit holds: listed by git (a git error
 * is a `failed` pass), copied, scanned — see {@link filesPass}.
 */
async function workingTreePass(opts, result, hasCommits) {
    let files;
    try {
        files = await uncommittedFiles(opts.projectPath, hasCommits, EXCLUDED_DIRS);
    }
    catch (e) {
        result.tools_run.push({ name: GITLEAKS_WORKING_TREE, status: 'failed', reason: `working tree: ${message(e)}` });
        return;
    }
    await filesPass(opts, result, files);
}
/**
 * gitleaks over a list of uncommitted project files, copied to a temporary
 * directory (see the module comment for the size limits and what a file that
 * cannot be read costs).
 */
async function filesPass(opts, result, files, labels = {
    none: 'no uncommitted or untracked files',
    scanned: (n) => `working tree: ${n} uncommitted or untracked file(s) scanned`,
}) {
    const name = GITLEAKS_WORKING_TREE;
    const candidates = files.filter((f) => !isExcluded(f));
    if (candidates.length === 0) {
        result.tools_run.push({ name, status: 'skipped', reason: labels.none });
        return;
    }
    const maxFile = opts.limits?.maxFileBytes ?? MAX_FILE_BYTES;
    const maxTotal = opts.limits?.maxTotalBytes ?? MAX_TOTAL_BYTES;
    let tmp;
    try {
        tmp = mkdtempSync(join(tmpdir(), 'guardian-gitleaks-'));
    }
    catch (e) {
        result.tools_run.push({ name, status: 'failed', reason: `working tree: no temporary directory: ${message(e)}` });
        return;
    }
    const gaps = [];
    const notes = [];
    let copied = 0;
    try {
        const unreadable = [];
        let oversized = 0;
        let overTotal = 0;
        let total = 0;
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
                continue; // deleted since git listed it: nothing to read
            }
            if (size > maxFile) {
                oversized += 1;
                continue;
            }
            if (total + size > maxTotal) {
                overTotal += 1;
                continue;
            }
            try {
                const to = join(tmp, rel);
                mkdirSync(dirname(to), { recursive: true });
                copyFileSync(from, to);
                copied += 1;
                total += size;
            }
            catch (e) {
                unreadable.push(`${rel} (${errorCode(e)})`);
            }
        }
        if (unreadable.length > 0) {
            gaps.push(`${unreadable.length} file(s) could not be read: ${unreadable.slice(0, 5).join(', ')}${unreadable.length > 5 ? ', …' : ''}`);
        }
        if (oversized > 0)
            gaps.push(`${oversized} file(s) not scanned: over ${megabytes(maxFile)} each`);
        if (overTotal > 0)
            gaps.push(`${overTotal} file(s) not scanned: over the ${bytesLabel(maxTotal)} total`);
        if (copied === 0) {
            result.tools_run.push({
                name,
                status: gaps.length > 0 ? 'failed' : 'skipped',
                reason: `working tree: no file to scan${gaps.length > 0 ? `; ${gaps.join('; ')}` : ''}`,
            });
            return;
        }
        const outFile = join(opts.reportDir, 'secrets-working-tree.json');
        rmSync(outFile, { force: true });
        const target = reportTarget(opts, outFile);
        const args = [
            'detect',
            '--no-git',
            '--no-banner',
            '--report-format=json',
            `--report-path=${target.path}`,
            ...target.redact,
            '-s',
            '.',
            `--gitleaks-ignore-path=${opts.projectPath}`,
        ];
        const projectConfig = join(opts.projectPath, '.gitleaks.toml');
        if (existsSync(projectConfig))
            args.push(`--config=${projectConfig}`);
        const run = await runProcess({ command: 'gitleaks', args, cwd: tmp, env: opts.env, signal: opts.signal, onLog: opts.onLog });
        if (run.outcome === 'cancelled')
            result.cancelled = true;
        const report = takeReport(opts, target.path, outFile);
        recordFilesRun(result, name, run, report, 'working_tree', labels.scanned(copied), gaps, notes);
    }
    finally {
        try {
            rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
        catch (e) {
            // Leaves a directory behind; must never take the results with it.
            const entry = result.tools_run.find((t) => t.name === name);
            const note = `temporary copy ${tmp} could not be removed (${errorCode(e)})`;
            if (entry)
                entry.reason = entry.reason ? `${entry.reason}; ${note}` : note;
        }
    }
}
/**
 * gitleaks over a directory that is not (readable as) a repository, in place:
 * `--no-git -s .` in the project, with a generated config that extends the
 * project's `.gitleaks.toml` (or gitleaks' defaults) and allowlists the
 * excluded directories. The config is written next to the report.
 */
async function directoryPass(opts, result, name) {
    const prefix = 'not a git repository — scanned the directory in place';
    let config;
    try {
        config = join(opts.reportDir, 'gitleaks-directory.toml');
        writeFileSync(config, directoryConfig(opts.projectPath));
    }
    catch (e) {
        result.tools_run.push({ name, status: 'failed', reason: `${prefix}: could not write its config: ${message(e)}` });
        return;
    }
    const outFile = join(opts.reportDir, 'secrets.json');
    rmSync(outFile, { force: true });
    const target = reportTarget(opts, outFile);
    const run = await runProcess({
        command: 'gitleaks',
        args: [
            'detect',
            '--no-git',
            '--no-banner',
            '--log-level=info',
            '--report-format=json',
            `--report-path=${target.path}`,
            ...target.redact,
            '-s',
            '.',
            `--config=${config}`,
        ],
        cwd: opts.projectPath,
        env: opts.env,
        signal: opts.signal,
        onLog: opts.onLog,
    });
    if (run.outcome === 'cancelled')
        result.cancelled = true;
    const report = takeReport(opts, target.path, outFile);
    const bytes = bytesScanned(run.stderr);
    if (bytes === 0 && runProblems(run, report.text).length === 0) {
        result.tools_run.push({ name, status: 'skipped', reason: `${prefix}: it holds nothing gitleaks reads (0 bytes)` });
        return;
    }
    const excluded = EXCLUDED_DIRS.join(', ');
    const scanned = bytes === null ? '' : ` (~${bytes} bytes)`;
    recordFilesRun(result, name, run, report, 'directory', `${prefix}${scanned}, excluding ${excluded}`, [], []);
}
/** The config for {@link directoryPass}: the project's (or the default) plus the excluded directories. */
export function directoryConfig(projectPath) {
    const own = join(projectPath, '.gitleaks.toml');
    const names = EXCLUDED_DIRS.map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    return [
        '# Generated by dev-guardian for one scan: the project\'s gitleaks config (or',
        '# gitleaks\' defaults) plus the directories no scan of the project\'s own files reads.',
        '[extend]',
        existsSync(own) ? `path = '''${own}'''` : 'useDefault = true',
        '',
        '[allowlist]',
        'description = "dev-guardian: vendored, generated and tool directories"',
        `paths = ['''(^|/)(${names})/''']`,
        '',
    ].join('\n');
}
/** A files-pass run into `tools_run` / `parser_inputs`; `gaps` make an ok run "reduced coverage". */
function recordFilesRun(result, name, run, report, location, okReason, gaps, notes) {
    const raw = report.text;
    const problems = runProblems(run, raw);
    if (raw !== null && problems.length === 0) {
        pushParserInput(result, { parser: locatedParser(location, ''), input: raw }, report.secrets);
        result.tools_run.push({ name, status: 'ok', reason: [okReason, ...gaps, ...notes].join('; ') });
        if (gaps.length > 0)
            result.missing_tools.push(name);
    }
    else {
        result.tools_run.push({ name, status: 'failed', reason: [...problems, ...gaps, ...notes].join('; ') });
    }
}
/** An unredacted report that is not a JSON array is withheld, unread: it may hold raw values. */
const WITHHELD_REPORT = JSON.stringify('gitleaks report withheld: not a JSON array, and it may hold unredacted values');
/** Where gitleaks writes this pass's report, and whether it redacts — see the module comment. */
function reportTarget(opts, outFile) {
    if (opts.raw === null)
        return { path: outFile, redact: ['--redact'] };
    return { path: opts.raw.pathFor(basename(outFile)), redact: [] };
}
/**
 * The pass's report: as gitleaks wrote it (a redacting run), or — from the
 * private directory — sanitized, with the raw report deleted at once and the
 * sanitized copy kept at `outFile`.
 */
function takeReport(opts, written, outFile) {
    if (opts.raw === null)
        return { text: readJsonSafe(written), secrets: null };
    const rawText = readJsonSafe(written);
    try {
        rmSync(written, { force: true });
    }
    catch {
        // Removed with its directory at the end of the scan (or reported there).
    }
    // The report file was pre-created empty (0600): still empty means gitleaks
    // wrote nothing — the same "wrote no report" a redacting run gets.
    if (rawText === null || rawText.trim() === '')
        return { text: null, secrets: null };
    const clean = sanitizeGitleaksReport(rawText, opts.captureSecrets ?? (() => false));
    if (clean === null)
        return { text: WITHHELD_REPORT, secrets: null };
    try {
        writeFileSync(outFile, clean.text);
    }
    catch {
        // The kept copy is for `report_paths`; the scan does not depend on it.
    }
    return { text: clean.text, secrets: clean.secrets };
}
function pushParserInput(result, task, secrets) {
    result.parser_inputs.push(task);
    if (secrets !== null)
        result.captured?.set(task, secrets);
}
function message(e) {
    return e instanceof Error ? e.message : String(e);
}
function errorCode(e) {
    const code = typeof e === 'object' && e !== null && 'code' in e ? e.code : undefined;
    return typeof code === 'string' ? code : message(e);
}
function megabytes(n) {
    return `${Math.round(n / (1024 * 1024))} MB`;
}
function bytesLabel(n) {
    return n >= 1024 * 1024 ? megabytes(n) : `${n}-byte`;
}
/** The `scanned ~N bytes` gitleaks logs, or null. */
function bytesScanned(stderr) {
    const m = /scanned ~(\d+) bytes/i.exec(stderr.replace(ANSI, ''));
    return m?.[1] !== undefined ? Number(m[1]) : null;
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
/** Entries in a gitleaks JSON report; 0 for no report or one that is not an array. */
function reportFindings(raw) {
    if (raw === null)
        return 0;
    const parsed = parseInputAsJson(raw);
    return Array.isArray(parsed) ? parsed.length : 0;
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