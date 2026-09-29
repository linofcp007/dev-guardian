/**
 * Reading and writing files inside the SCANNED project — a directory whose
 * contents dev-guardian does not control, and which may be hostile.
 *
 * `existsSync` + `readFileSync` / `writeFileSync` trust whatever the path
 * names. Measured on 3.0.0, with no tool call at all (the server's startup
 * `.gitignore` upkeep):
 *
 *   - a dangling `.gitignore` symlink to `<outside>/planted.conf` made the
 *     server CREATE that file outside the project (`existsSync` is false for a
 *     dangling link; `writeFileSync` follows it). Pointed at `~/.gitconfig`,
 *     it would have broken every git command the user runs;
 *   - `.gitignore -> /dev/zero` (Docker, 768 MB limit) OOM-killed the server
 *     in 21 s, before it ever listened.
 *
 * Every read of a project file goes through {@link readProjectText} (or
 * {@link readProjectBytes} / {@link readProjectHead} / {@link hashProjectFile}), and every write
 * through {@link writeProjectFile}. `test/unit/platform/rawRepoFsSites.test.ts`
 * fails when a raw `fs` read or write appears anywhere in `src/` that is not
 * on its list, and says why each listed one is not the project's.
 *
 * ## Reads
 *
 * A read is refused, with a typed reason, when the path:
 *
 *   - is lexically outside the project, or resolves (`realpath`, every link
 *     followed) outside it — `outside-project`. A link that STAYS inside
 *     (pnpm's `node_modules`, a `docs -> ../shared/docs` in a monorepo) is
 *     read as the file it names;
 *   - reaches a network or device path through any link below the project
 *     (`remote-link`) — judged with `lstat`/`readlink` only, before anything
 *     is opened, because the open itself is what hangs (`hooks/configFile.ts`);
 *   - is not a regular file (a FIFO, a device, a socket, a directory) —
 *     `not-a-regular-file`, judged on the OPENED descriptor, opened
 *     non-blocking, so a FIFO does not wait for a writer;
 *   - is larger than the caller's cap — `too-large`, and at most cap + 1
 *     bytes are ever read, so a file that grows during the read is refused too.
 *
 * {@link readProjectHead} judges a file the same way but is never
 * `too-large`: it reads the first N bytes and leaves the rest.
 *
 * A path that does not exist, or a dangling link, is `absent`. Text reads
 * are `hooks/configFile.ts`'s own `readSmallText` after the containment check
 * above: one judgement for the hooks and for the server. `readProjectBytes`
 * repeats that judgement for callers that need the bytes (a byte offset, a
 * content hash) — `configFile.ts` returns text only and must stay free of
 * any import, since the hook dispatcher loads it from `dist/` alone.
 *
 * **What the containment check does not cover.** The path is resolved, then
 * opened: a process that swaps a component for a link between the two can
 * still aim the open elsewhere. The descriptor is judged, so the swap can at
 * most make a small regular file outside the project be read. The threat
 * here is the repository's CONTENT — a clone, an archive, a pull request —
 * which cannot run anything before a scan; a process already running as the
 * user can read those files itself.
 *
 * ## Writes
 *
 * {@link writeProjectFile}: the target must be lexically inside the project;
 * every existing directory between the project and the file must resolve
 * inside it (a missing one is created one level at a time, never through a
 * link); the target itself is `lstat`ed and refused when it is a link — a
 * junction or a dangling link included — or anything but a regular file. The
 * content goes to a fresh temp file beside it (random name, opened `wx`), and
 * is then:
 *
 *   - `create`: published with `link()`, which fails on ANY existing entry at
 *     that name — a dangling link included — and never follows one. Not a
 *     `wx` open: on Windows a `wx` open over a dangling symlink follows it and
 *     creates the target (measured for `ci-init`, which this mirrors);
 *   - `replace`: renamed over the file. A rename replaces the directory entry;
 *     it never writes through a link or into an inode another hard link
 *     shares, and the file is never half-written.
 */
import { randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, realpathSync, renameSync, unlinkSync, writeSync, } from 'node:fs';
import { open as openAsync, lstat as lstatAsync, readlink as readlinkAsync } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { readSmallText, walkLinksUnder } from '../hooks/configFile.js';
/** A project file's default read cap: far above any config or source file, far below a denial of service. */
export const PROJECT_FILE_MAX_BYTES = 8 * 1024 * 1024;
/**
 * Lockfiles and generated manifests: a large monorepo's `package-lock.json`
 * or `pnpm-lock.yaml` runs to tens of megabytes.
 */
export const PROJECT_LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;
/** `O_NONBLOCK` where the platform has it; 0 on Windows, where it is undefined. */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);
const caseFold = (p) => (process.platform === 'win32' ? p.toLowerCase() : p);
/** `path` is `root` or lies below it, compared lexically. Case-insensitive on Windows. */
export function isWithinDir(root, path) {
    const rel = relative(caseFold(resolve(root)), caseFold(resolve(path)));
    return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
function realpathOrNull(p) {
    try {
        return realpathSync.native(p);
    }
    catch {
        return null;
    }
}
/** The project root in its resolved form, cached per spelling: every read resolves against it. */
const rootCache = new Map();
function realRoot(root) {
    const key = resolve(root);
    const cached = rootCache.get(key);
    if (cached !== undefined)
        return cached;
    const real = realpathOrNull(key) ?? key;
    if (rootCache.size > 64)
        rootCache.clear();
    rootCache.set(key, real);
    return real;
}
/**
 * Where `path` really is, when that is inside `root` — or why it is not read.
 * `path` may be absolute or relative to `root`.
 */
function locate(root, path) {
    const abs = resolve(root, path);
    if (!isWithinDir(root, abs))
        return { ok: false, read: { status: 'refused', reason: 'outside-project' } };
    const walk = walkLinksUnder(root, abs);
    if (!walk.ok)
        return { ok: false, read: { status: 'refused', reason: walk.reason } };
    let real;
    try {
        real = realpathSync.native(abs);
    }
    catch (e) {
        const code = e.code;
        // Missing, or a dangling link: nothing there to read.
        if (code === 'ENOENT' || code === 'ENOTDIR')
            return { ok: false, read: { status: 'absent' } };
        return { ok: false, read: { status: 'refused', reason: 'unreadable' } };
    }
    if (!isWithinDir(realRoot(root), real))
        return { ok: false, read: { status: 'refused', reason: 'outside-project' } };
    return { ok: true, real };
}
/**
 * A text file inside the project — or that it is `absent`, or why it was
 * `refused`. A leading byte-order mark is stripped. See the module doc.
 */
export function readProjectText(root, path, maxBytes = PROJECT_FILE_MAX_BYTES) {
    const where = locate(root, path);
    if (!where.ok)
        return where.read;
    return readSmallText(where.real, maxBytes);
}
/** {@link readProjectText}'s text, or `undefined` for anything else. */
export function readProjectTextOrUndefined(root, path, maxBytes = PROJECT_FILE_MAX_BYTES) {
    const r = readProjectText(root, path, maxBytes);
    return r.status === 'ok' ? r.text : undefined;
}
/**
 * {@link readProjectText}, parsed as JSON: `undefined` when the file is
 * absent, refused, or not JSON. For the many callers that only ever used the
 * value and treated every failure alike.
 */
export function readProjectJson(root, path, maxBytes = PROJECT_FILE_MAX_BYTES) {
    const text = readProjectTextOrUndefined(root, path, maxBytes);
    if (text === undefined)
        return undefined;
    try {
        return JSON.parse(text);
    }
    catch {
        return undefined;
    }
}
/**
 * A file's bytes, judged exactly as {@link readProjectText} judges them, for
 * a caller that needs the bytes themselves. No byte-order mark is stripped.
 */
export function readProjectBytes(root, path, maxBytes = PROJECT_FILE_MAX_BYTES) {
    const where = locate(root, path);
    if (!where.ok)
        return where.read;
    let fd;
    try {
        fd = openSync(where.real, OPEN_FLAGS);
    }
    catch (e) {
        const code = e.code;
        if (code === 'ENOENT' || code === 'ENOTDIR')
            return { status: 'absent' };
        if (code === 'EISDIR')
            return { status: 'refused', reason: 'not-a-regular-file' };
        return { status: 'refused', reason: 'unreadable' };
    }
    try {
        const st = fstatSync(fd);
        if (!st.isFile())
            return { status: 'refused', reason: 'not-a-regular-file' };
        if (st.size > maxBytes)
            return { status: 'refused', reason: 'too-large' };
        let buf = Buffer.allocUnsafe(st.size + 1);
        let total = 0;
        for (;;) {
            if (total === buf.length) {
                if (buf.length > maxBytes)
                    break;
                const bigger = Buffer.allocUnsafe(Math.min(buf.length * 2, maxBytes + 1));
                buf.copy(bigger, 0, 0, total);
                buf = bigger;
            }
            const n = readSync(fd, buf, total, buf.length - total, null);
            if (n === 0)
                break;
            total += n;
        }
        if (total > maxBytes)
            return { status: 'refused', reason: 'too-large' };
        return { status: 'ok', bytes: buf.subarray(0, total) };
    }
    catch {
        return { status: 'refused', reason: 'unreadable' };
    }
    finally {
        try {
            closeSync(fd);
        }
        catch {
            /* nothing left to do with it */
        }
    }
}
/**
 * The first `maxBytes` bytes of a project file, as text — judged as
 * {@link readProjectText} judges a file (contained, a regular file on a
 * non-blocking descriptor), except that a longer file is never refused: at
 * most `maxBytes` bytes are read, and the rest is left unread. For a caller
 * that decides from a file's head (a plugin header, a manifest's first
 * document), where the file itself may be of any size. A leading
 * byte-order mark is stripped; a multi-byte character cut at the end is
 * replaced, as `Buffer#toString` replaces it.
 */
export function readProjectHead(root, path, maxBytes) {
    const where = locate(root, path);
    if (!where.ok)
        return where.read;
    let fd;
    try {
        fd = openSync(where.real, OPEN_FLAGS);
    }
    catch (e) {
        const code = e.code;
        if (code === 'ENOENT' || code === 'ENOTDIR')
            return { status: 'absent' };
        if (code === 'EISDIR')
            return { status: 'refused', reason: 'not-a-regular-file' };
        return { status: 'refused', reason: 'unreadable' };
    }
    try {
        const st = fstatSync(fd);
        if (!st.isFile())
            return { status: 'refused', reason: 'not-a-regular-file' };
        const buf = Buffer.allocUnsafe(Math.max(0, Math.min(maxBytes, st.size)));
        let total = 0;
        while (total < buf.length) {
            const n = readSync(fd, buf, total, buf.length - total, null);
            if (n === 0)
                break;
            total += n;
        }
        let text = buf.subarray(0, total).toString('utf8');
        if (text.charCodeAt(0) === 0xfeff)
            text = text.slice(1);
        return { status: 'ok', text };
    }
    catch {
        return { status: 'refused', reason: 'unreadable' };
    }
    finally {
        try {
            closeSync(fd);
        }
        catch {
            /* nothing left to do with it */
        }
    }
}
/**
 * The sha256 of a project file's CONTENT for a tree hash, streamed so no size
 * cap applies — or a stable stand-in that never follows the path anywhere:
 *
 *   - a link (a junction included) hashes as `link:<its target text>`, as git
 *     itself stores one, and is never opened: `x -> /dev/zero` would
 *     otherwise be read without end;
 *   - anything but a regular file (a FIFO, a device, a socket) is `special`,
 *     judged on a non-blocking descriptor;
 *   - a path that vanished, or cannot be read, is `missing`.
 */
export async function hashProjectFile(root, path) {
    const abs = resolve(root, path);
    if (!isWithinDir(root, abs))
        return 'outside';
    let st;
    try {
        st = await lstatAsync(abs);
    }
    catch {
        return 'missing';
    }
    if (st.isSymbolicLink()) {
        try {
            return `link:${await readlinkAsync(abs)}`;
        }
        catch {
            return 'link';
        }
    }
    if (!st.isFile())
        return 'special';
    let handle;
    try {
        handle = await openAsync(abs, OPEN_FLAGS);
    }
    catch {
        return 'missing';
    }
    try {
        const fst = await handle.stat();
        if (!fst.isFile())
            return 'special';
        const hash = createHash('sha256');
        const chunk = Buffer.allocUnsafe(1024 * 1024);
        for (;;) {
            const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
            if (bytesRead === 0)
                break;
            hash.update(chunk.subarray(0, bytesRead));
        }
        return hash.digest('hex');
    }
    catch {
        return 'missing';
    }
    finally {
        await handle.close().catch(() => undefined);
    }
}
/**
 * The sha256 (hex) of a regular file's bytes, streamed — or `null` when the
 * path is absent, not a regular file (judged on a non-blocking descriptor, so
 * a FIFO is never waited on and a device never read), or unreadable. NOT
 * contained: for a path that may legitimately lie anywhere (a rule pack the
 * user registered), where the property wanted is that the read ends.
 */
export function hashRegularFileSync(path) {
    let fd;
    try {
        fd = openSync(path, OPEN_FLAGS);
    }
    catch {
        return null;
    }
    try {
        if (!fstatSync(fd).isFile())
            return null;
        const hash = createHash('sha256');
        const chunk = Buffer.allocUnsafe(1024 * 1024);
        for (;;) {
            const n = readSync(fd, chunk, 0, chunk.length, null);
            if (n === 0)
                break;
            hash.update(chunk.subarray(0, n));
        }
        return hash.digest('hex');
    }
    catch {
        return null;
    }
    finally {
        try {
            closeSync(fd);
        }
        catch {
            /* nothing left to do with it */
        }
    }
}
/**
 * `lstat`'s answer for `path`: a link (a Windows junction included, which
 * `lstat` reports as one) is `link` and is never followed.
 */
export function projectEntryKind(path) {
    let st;
    try {
        st = lstatSync(path);
    }
    catch {
        return 'absent';
    }
    if (st.isSymbolicLink())
        return 'link';
    if (st.isFile())
        return 'file';
    if (st.isDirectory())
        return 'directory';
    return 'other';
}
/**
 * Whether anything — a dangling link included — is at `path`, which must lie
 * lexically inside `root` (anything outside is `false`, never looked at). For
 * a path named by a repository file, where `existsSync` would both follow a
 * link and answer about any path at all.
 */
export function presentInProject(root, path) {
    const abs = resolve(root, path);
    return isWithinDir(root, abs) && projectEntryKind(abs) !== 'absent';
}
/**
 * Where `path` resolves, when that is inside `root`; `null` when it does not
 * exist or resolves outside. For a caller that decides by `stat` (is it a
 * directory?) and must not be sent outside the project by a link to do so.
 */
export function realpathInProject(root, path) {
    const abs = resolve(root, path);
    if (!isWithinDir(root, abs))
        return null;
    if (!walkLinksUnder(root, abs).ok)
        return null;
    const real = realpathOrNull(abs);
    if (real === null || !isWithinDir(realRoot(root), real))
        return null;
    return real;
}
/**
 * `statSync(path)`'s answer for a project path, except that a link leading
 * out of the project (or to a network or device path) is `outside` and is
 * never followed there. For a caller that asks "is it a directory?" and
 * would otherwise walk, list or read wherever a link pointed.
 */
export function projectPathKind(root, path) {
    const abs = resolve(root, path);
    if (!isWithinDir(root, abs))
        return 'outside';
    if (projectEntryKind(abs) === 'absent')
        return 'absent';
    const real = realpathInProject(root, abs);
    if (real === null)
        return realpathOrNull(abs) === null ? 'absent' : 'outside';
    let st;
    try {
        st = lstatSync(real);
    }
    catch {
        return 'absent';
    }
    if (st.isFile())
        return 'file';
    if (st.isDirectory())
        return 'directory';
    return 'other';
}
/**
 * The entries of a directory inside the project — `[]` when it is absent,
 * not a directory, cannot be listed, or is reached through a link out of the
 * project. Entries are typed from the directory itself (`Dirent`), so a walk
 * built on this never descends a directory link, in or out of the project:
 * no loop, and no listing of anything outside. A `link` entry naming a file
 * can still be read with {@link readProjectText}, which judges where it
 * leads.
 */
export function listProjectDir(root, dir) {
    return listProjectDirOrNull(root, dir) ?? [];
}
/**
 * {@link listProjectDir}, except that a directory that could not be listed
 * — absent, not a directory, unreadable, or reached through a link out of
 * the project — is `null` rather than `[]`: for a walk that must tell an
 * empty directory from one it never read, and say so.
 */
export function listProjectDirOrNull(root, dir) {
    const real = realpathInProject(root, dir);
    if (real === null)
        return null;
    let entries;
    try {
        entries = readdirSync(real, { withFileTypes: true });
    }
    catch {
        return null;
    }
    return entries.map((e) => ({
        name: e.name,
        kind: e.isSymbolicLink() ? 'link' : e.isFile() ? 'file' : e.isDirectory() ? 'directory' : 'other',
    }));
}
/** A readable sentence for a refusal, for a tool's `reason` field. */
export function describeWriteRefusal(reason, detail) {
    switch (reason) {
        case 'outside-project':
            return 'the path is outside the project';
        case 'escaping-directory':
            return `a directory on the way is a link out of the project, or not a directory${detail ? ` (${detail})` : ''}`;
        case 'link':
            return 'the file is a link (symlink or junction) and is never written through';
        case 'not-a-regular-file':
            return 'the path exists and is not a regular file';
        case 'exists':
            return 'a file is already there';
        case 'failed':
            return `the write failed${detail ? `: ${detail}` : ''}`;
    }
}
/** A readable sentence for a read refusal. */
export function describeReadRefusal(reason) {
    switch (reason) {
        case 'outside-project':
            return 'it resolves outside the project (a link) and was not read';
        case 'remote-link':
            return 'it is reached through a link to a network or device path and was not opened';
        case 'not-a-regular-file':
            return 'it is not a regular file (a FIFO, a device, a socket or a directory) and was not read';
        case 'too-large':
            return 'it is larger than the size cap and was not read';
        case 'unreadable':
            return 'it could not be read (permissions, a link loop, or an I/O error)';
    }
}
/**
 * Makes every missing directory between `root` and `dir`, one level at a
 * time, and checks every existing one resolves inside `root` and is a
 * directory. `null` on success, else the offending path.
 */
function ensureDirsInside(root, dir) {
    const rootAbs = resolve(root);
    const rootReal = realRoot(root);
    const parts = relative(rootAbs, resolve(dir)).split(/[\\/]+/).filter((p) => p.length > 0);
    let current = rootAbs;
    for (const part of parts) {
        current = join(current, part);
        let st = null;
        try {
            st = lstatSync(current);
        }
        catch {
            st = null;
        }
        if (st === null) {
            try {
                mkdirSync(current);
            }
            catch (e) {
                if (e.code !== 'EEXIST')
                    return current;
            }
            try {
                st = lstatSync(current);
            }
            catch {
                return current;
            }
        }
        if (st.isSymbolicLink()) {
            const real = realpathOrNull(current);
            if (real === null || !isWithinDir(rootReal, real))
                return current;
            try {
                if (!lstatSync(real).isDirectory())
                    return current;
            }
            catch {
                return current;
            }
            continue;
        }
        if (!st.isDirectory())
            return current;
    }
    return null;
}
/**
 * `rel` below `root` as a real directory, every component of it created here
 * or already a plain directory — or `null` when any component is a link (a
 * junction included, even one that stays inside the project), is not a
 * directory, or cannot be created. For dev-guardian's own output directories
 * inside the project (`.guardian/reports/…`), which nothing in a repository
 * has a reason to make a link, and which a scanner then writes into.
 */
export function makeProjectDir(root, rel) {
    const rootAbs = resolve(root);
    const target = resolve(rootAbs, rel);
    if (!isWithinDir(rootAbs, target))
        return null;
    let current = rootAbs;
    for (const part of relative(rootAbs, target).split(/[\\/]+/).filter((p) => p.length > 0)) {
        current = join(current, part);
        let st;
        try {
            st = lstatSync(current);
        }
        catch {
            st = null;
        }
        if (st === null) {
            try {
                mkdirSync(current);
                st = lstatSync(current);
            }
            catch {
                return null;
            }
        }
        if (st.isSymbolicLink() || !st.isDirectory())
            return null;
    }
    return target;
}
function removeQuietly(path) {
    try {
        unlinkSync(path);
    }
    catch {
        /* already gone, or held by another process: the name is random and hidden */
    }
}
/** A fresh temp file beside `target` holding `content`, opened `wx` so an existing entry is never touched. */
function writeTempBeside(target, content, mode) {
    const tmp = join(dirname(target), `.${randomBytes(8).toString('hex')}.dev-guardian.tmp`);
    const fd = openSync(tmp, 'wx', mode ?? 0o666);
    let done = false;
    try {
        let off = 0;
        while (off < content.length)
            off += writeSync(fd, content, off, content.length - off);
        done = true;
    }
    finally {
        closeSync(fd);
        if (!done)
            removeQuietly(tmp);
    }
    return tmp;
}
/**
 * Writes `content` to `path` inside `root` — see the module doc. Never
 * throws: a refusal or a filesystem error comes back as `{ ok: false }`.
 */
export function writeProjectFile(root, path, content, options) {
    const target = resolve(root, path);
    if (!isWithinDir(root, target) || caseFold(target) === caseFold(resolve(root))) {
        return { ok: false, reason: 'outside-project' };
    }
    const bytes = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
    const badDir = ensureDirsInside(root, dirname(target));
    if (badDir !== null)
        return { ok: false, reason: 'escaping-directory', detail: relative(resolve(root), badDir) };
    let existing = null;
    try {
        existing = lstatSync(target);
    }
    catch (e) {
        if (e.code !== 'ENOENT') {
            return { ok: false, reason: 'failed', detail: e.message };
        }
    }
    if (existing !== null) {
        if (existing.isSymbolicLink())
            return { ok: false, reason: 'link' };
        if (!existing.isFile())
            return { ok: false, reason: 'not-a-regular-file' };
        if (options.mode === 'create')
            return { ok: false, reason: 'exists' };
    }
    let tmp;
    try {
        tmp = writeTempBeside(target, bytes, existing === null ? undefined : existing.mode & 0o777);
    }
    catch (e) {
        return { ok: false, reason: 'failed', detail: e.message };
    }
    try {
        if (existing === null) {
            try {
                linkSync(tmp, target);
            }
            catch (e) {
                const code = e.code;
                if (code === 'EEXIST')
                    return { ok: false, reason: options.mode === 'create' ? 'exists' : 'link' };
                // No hard links here (FAT/exFAT, some network shares): an lstat
                // check and a rename. The one race left — an entry created at the
                // name between the two — is replaced, never written through.
                if (projectEntryKind(target) !== 'absent')
                    return { ok: false, reason: 'exists' };
                renameSync(tmp, target);
            }
        }
        else {
            renameSync(tmp, target);
        }
        return { ok: true, bytes: bytes.length };
    }
    catch (e) {
        return { ok: false, reason: 'failed', detail: e.message };
    }
    finally {
        removeQuietly(tmp);
    }
}
//# sourceMappingURL=projectFs.js.map