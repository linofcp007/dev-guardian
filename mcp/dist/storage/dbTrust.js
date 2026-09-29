/**
 * Is `<project>/.guardian/guardian.db` tracked by git?
 *
 * A database that arrived with the repository is the project's data, not
 * dev-guardian's: whoever committed it wrote its schema, and SQL inside it
 * (a trigger, a CHECK constraint) runs on every write the server makes. It is
 * refused (`db.ts#openDatabase`), and the answer to this question is how.
 *
 * ---- How the answer is got, and what "cannot tell" does ---------------
 *
 * `git ls-files -z -- <db> <db>-wal <db>-shm <db>-journal`, run in the
 * project with a {@link GIT_TIMEOUT_MS} bound. `ls-files` rather than
 * `--error-unmatch` on the one path because SQLite replays a WAL file into
 * the database when it opens it: a committed `guardian.db-wal` beside an
 * innocent `guardian.db` delivers the same trigger, so all four names are
 * asked in one call, and any of them listed means tracked. Exit 128 with "not
 * a git repository" is untracked for certain — there is no index to be in.
 * GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE are dropped from git's
 * environment (they would point the question at another repository) and the
 * locale is forced to C so that message can be read.
 *
 * When git cannot answer — not installed, timed out on a loaded machine,
 * refusing a repository another user owns ("dubious ownership") — the
 * database is untracked only if that is PLAUSIBLE, and otherwise refused
 * (fails safe: the per-user fallback is used, and the warning says why):
 *   - no `.git` in the project or above it: nothing can be tracked;
 *   - the repository's index is a readable v2/v3 index (paths stored whole)
 *     that does not contain `.guardian/guardian.db` anywhere: untracked,
 *     inferred — the database is used, WITH a warning that git could not be
 *     asked;
 *   - the index names it (in this project or any sub-project): tracked;
 *   - no index at all: untracked (nothing is tracked yet);
 *   - anything else (a v4 index, whose paths are prefix-compressed; an
 *     unreadable or oversized index; a malformed `.git` file): cannot tell,
 *     refused.
 * Chosen over "cannot tell → use it with a warning" because a warning in a
 * tool result does not undo a trigger that already ran, and over "cannot
 * tell → refuse" alone because the history then vanishes on every machine
 * without git on PATH, where the index answers the question exactly.
 */
import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
/** How long git may take to answer before the index is read instead. */
export const GIT_TIMEOUT_MS = 3000;
/** The database and the files SQLite reads with it, relative to the project. */
export const DATABASE_FILES = [
    '.guardian/guardian.db',
    '.guardian/guardian.db-wal',
    '.guardian/guardian.db-shm',
    '.guardian/guardian.db-journal',
];
/** An index larger than this is not read: "cannot tell". */
const MAX_INDEX_BYTES = 64 * 1024 * 1024;
/** See the module header. Never throws. */
export function gitTracksDatabase(projectPath, opts = {}) {
    const r = spawnSync(opts.git ?? 'git', ['ls-files', '-z', '--', ...DATABASE_FILES], {
        cwd: projectPath,
        encoding: 'utf8',
        timeout: opts.timeoutMs ?? GIT_TIMEOUT_MS,
        windowsHide: true,
        env: gitEnvironment(),
        maxBuffer: 1024 * 1024,
    });
    if (r.error !== undefined) {
        const code = r.error.code;
        const why = code === 'ENOENT' ? 'git is not installed' : code === 'ETIMEDOUT' ? `git took longer than ${opts.timeoutMs ?? GIT_TIMEOUT_MS} ms` : `git failed to run (${code ?? r.error.message})`;
        return fromRepository(projectPath, why);
    }
    if (r.status === 0) {
        const listed = r.stdout.split('\0').filter((s) => s !== '');
        return listed.length > 0
            ? { state: 'tracked', detail: `git tracks ${listed.join(', ')}` }
            : { state: 'untracked', detail: 'git does not track it' };
    }
    const stderr = typeof r.stderr === 'string' ? r.stderr : '';
    if (r.status === 128 && /not a git repository/i.test(stderr)) {
        return { state: 'untracked', detail: 'the project is not in a git repository' };
    }
    const first = stderr.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? '';
    return fromRepository(projectPath, `git exited ${r.status ?? 'on a signal'}${first !== '' ? ` (${first})` : ''}`);
}
/** process.env minus what would point git at another repository, in the C locale. */
function gitEnvironment() {
    const env = { ...process.env, LC_ALL: 'C', LANGUAGE: 'C', GIT_OPTIONAL_LOCKS: '0' };
    for (const key of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_NAMESPACE'])
        delete env[key];
    return env;
}
/** The verdict when git could not give one — see the module header. */
function fromRepository(projectPath, why) {
    const gitDir = findGitDir(projectPath);
    if (gitDir === null) {
        return { state: 'untracked', detail: `${why}, and there is no .git in the project or above it`, inferred: true };
    }
    if (gitDir === 'unreadable')
        return { state: 'unknown', detail: `${why}, and its .git could not be read` };
    const index = join(gitDir, 'index');
    let bytes;
    try {
        bytes = readBounded(index, MAX_INDEX_BYTES + 1);
        if (bytes.length > MAX_INDEX_BYTES)
            return { state: 'unknown', detail: `${why}, and its git index is too large to read` };
    }
    catch (error) {
        if (error.code === 'ENOENT') {
            return { state: 'untracked', detail: `${why}, and the repository has no index yet`, inferred: true };
        }
        return { state: 'unknown', detail: `${why}, and its git index could not be read` };
    }
    if (bytes.length < 12 || bytes.toString('latin1', 0, 4) !== 'DIRC') {
        return { state: 'unknown', detail: `${why}, and its git index is not one git writes` };
    }
    if (bytes.includes('.guardian/guardian.db')) {
        return { state: 'tracked', detail: `${why}; the git index lists .guardian/guardian.db`, inferred: true };
    }
    const version = bytes.readUInt32BE(4);
    if (version !== 2 && version !== 3) {
        return { state: 'unknown', detail: `${why}, and its git index (version ${version}) does not store whole paths` };
    }
    return { state: 'untracked', detail: `${why}; the git index does not list it`, inferred: true, plausibleOnly: true };
}
/**
 * The git directory of the repository `start` is in: a `.git` directory, or
 * the `gitdir:` a `.git` file names (a linked worktree, a submodule). Null
 * when there is none up to the root; 'unreadable' when one exists that
 * cannot be followed.
 */
function findGitDir(start) {
    let dir = resolve(start);
    for (;;) {
        const candidate = join(dir, '.git');
        try {
            const st = statSync(candidate);
            if (st.isDirectory())
                return candidate;
            if (st.isFile()) {
                const text = readBounded(candidate, 4096).toString('utf8');
                const target = /^gitdir:\s*(.+?)\s*$/m.exec(text)?.[1];
                if (target === undefined)
                    return 'unreadable';
                return isAbsolute(target) ? target : resolve(dir, target);
            }
            return 'unreadable';
        }
        catch (error) {
            if (error.code !== 'ENOENT')
                return 'unreadable';
        }
        const parent = dirname(dir);
        if (parent === dir)
            return null;
        dir = parent;
    }
}
/**
 * At most `size` bytes of `path`, judged by the descriptor it opened — the
 * rule `hooks/configFile.ts` states: a FIFO swapped in for the index would
 * otherwise hold the server's startup forever. Throws `ENOENT` when the file
 * does not exist and EINVAL for anything but a regular file.
 */
function readBounded(path, size) {
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
    try {
        const st = fstatSync(fd);
        if (!st.isFile())
            throw Object.assign(new Error(`${path} is not a regular file`), { code: 'EINVAL' });
        const want = Math.min(size, st.size);
        const buf = Buffer.alloc(want);
        let got = 0;
        while (got < want) {
            const n = readSync(fd, buf, got, want - got, got);
            if (n === 0)
                break;
            got += n;
        }
        return buf.subarray(0, got);
    }
    finally {
        closeSync(fd);
    }
}
//# sourceMappingURL=dbTrust.js.map