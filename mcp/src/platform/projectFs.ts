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
 * user can read those files itself. **A hard link is not a link here**: it is
 * a regular file with a second name, indistinguishable from any other, so one
 * that shares an inode with a file outside the project is read as the
 * project's own (a repository cannot carry one — git stores content, not
 * inodes — but a directory copied with `cp -l` can).
 *
 * **Bytes read are not memory used.** A cap bounds what is read, not what a
 * caller builds from it: 30 MiB of newlines split into an array, or 30 MiB of
 * `{},` handed to `JSON.parse`, took a 768 MB server down (review of 3.0,
 * W2E). A caller iterates lines with `platform/textLines.ts`, parses JSON or
 * YAML only under a small cap of its own, and spends a {@link ReadBudget}
 * across a walk, so no project makes one tool call read without end.
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
import {
  closeSync,
  constants,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
  type Stats,
} from 'node:fs';
import { open as openAsync, lstat as lstatAsync, readlink as readlinkAsync } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { readSmallText, walkLinksUnder, type RefusalReason } from '../hooks/configFile.js';
import { parseJsonBounded } from './boundedJson.js';

/** A project file's default read cap: far above any config or source file, far below a denial of service. */
export const PROJECT_FILE_MAX_BYTES = 8 * 1024 * 1024;

/**
 * Lockfiles and generated manifests: a large monorepo's `package-lock.json`
 * or `pnpm-lock.yaml` runs to tens of megabytes.
 */
export const PROJECT_LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;

/**
 * Why an existing project path was not read. `read-budget`: the walk it was
 * found by had spent its {@link ReadBudget} before reaching it.
 */
export type ProjectReadRefusal = RefusalReason | 'outside-project' | 'read-budget';

export type ProjectTextRead =
  | { status: 'absent' }
  | { status: 'ok'; text: string }
  | { status: 'refused'; reason: ProjectReadRefusal };

export type ProjectBytesRead =
  | { status: 'absent' }
  | { status: 'ok'; bytes: Buffer }
  | { status: 'refused'; reason: ProjectReadRefusal };

/** `O_NONBLOCK` where the platform has it; 0 on Windows, where it is undefined. */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

const caseFold = (p: string): string => (process.platform === 'win32' ? p.toLowerCase() : p);

/** `path` is `root` or lies below it, compared lexically. Case-insensitive on Windows. */
export function isWithinDir(root: string, path: string): boolean {
  const rel = relative(caseFold(resolve(root)), caseFold(resolve(path)));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function realpathOrNull(p: string): string | null {
  try {
    return realpathSync.native(p);
  } catch {
    return null;
  }
}

/** The project root in its resolved form, cached per spelling: every read resolves against it. */
const rootCache = new Map<string, string>();
function realRoot(root: string): string {
  const key = resolve(root);
  const cached = rootCache.get(key);
  if (cached !== undefined) return cached;
  const real = realpathOrNull(key) ?? key;
  if (rootCache.size > 64) rootCache.clear();
  rootCache.set(key, real);
  return real;
}

type Located = { ok: true; real: string } | { ok: false; read: { status: 'absent' } | { status: 'refused'; reason: ProjectReadRefusal } };

/**
 * Where `path` really is, when that is inside `root` — or why it is not read.
 * `path` may be absolute or relative to `root`.
 */
function locate(root: string, path: string): Located {
  const abs = resolve(root, path);
  if (!isWithinDir(root, abs)) return { ok: false, read: { status: 'refused', reason: 'outside-project' } };
  const walk = walkLinksUnder(root, abs);
  if (!walk.ok) return { ok: false, read: { status: 'refused', reason: walk.reason } };
  let real: string;
  try {
    real = realpathSync.native(abs);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    // Missing, or a dangling link: nothing there to read.
    if (code === 'ENOENT' || code === 'ENOTDIR') return { ok: false, read: { status: 'absent' } };
    return { ok: false, read: { status: 'refused', reason: 'unreadable' } };
  }
  if (!isWithinDir(realRoot(root), real)) return { ok: false, read: { status: 'refused', reason: 'outside-project' } };
  return { ok: true, real };
}

/**
 * A text file inside the project — or that it is `absent`, or why it was
 * `refused`. A leading byte-order mark is stripped. See the module doc.
 */
export function readProjectText(root: string, path: string, maxBytes: number = PROJECT_FILE_MAX_BYTES): ProjectTextRead {
  const where = locate(root, path);
  if (!where.ok) return where.read;
  return readSmallText(where.real, maxBytes);
}

/** {@link readProjectText}'s text, or `undefined` for anything else. */
export function readProjectTextOrUndefined(
  root: string,
  path: string,
  maxBytes: number = PROJECT_FILE_MAX_BYTES,
): string | undefined {
  const r = readProjectText(root, path, maxBytes);
  return r.status === 'ok' ? r.text : undefined;
}

/**
 * {@link readProjectText}, parsed as JSON: `undefined` when the file is
 * absent, refused, or not JSON. For the many callers that only ever used the
 * value and treated every failure alike.
 */
export function readProjectJson(root: string, path: string, maxBytes: number = PROJECT_FILE_MAX_BYTES): unknown {
  const text = readProjectTextOrUndefined(root, path, maxBytes);
  if (text === undefined) return undefined;
  // Bounded by structure too (platform/boundedJson.ts): a lock file under the
  // byte cap took JSON.parse past the heap. Too complex reads as unreadable.
  const parsed = parseJsonBounded(text);
  return parsed.ok ? parsed.value : undefined;
}

/**
 * A file's bytes, judged exactly as {@link readProjectText} judges them, for
 * a caller that needs the bytes themselves. No byte-order mark is stripped.
 */
export function readProjectBytes(root: string, path: string, maxBytes: number = PROJECT_FILE_MAX_BYTES): ProjectBytesRead {
  const where = locate(root, path);
  if (!where.ok) return where.read;
  let fd: number;
  try {
    fd = openSync(where.real, OPEN_FLAGS);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { status: 'absent' };
    if (code === 'EISDIR') return { status: 'refused', reason: 'not-a-regular-file' };
    return { status: 'refused', reason: 'unreadable' };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { status: 'refused', reason: 'not-a-regular-file' };
    if (st.size > maxBytes) return { status: 'refused', reason: 'too-large' };
    let buf = Buffer.allocUnsafe(st.size + 1);
    let total = 0;
    for (;;) {
      if (total === buf.length) {
        if (buf.length > maxBytes) break;
        const bigger = Buffer.allocUnsafe(Math.min(buf.length * 2, maxBytes + 1));
        buf.copy(bigger, 0, 0, total);
        buf = bigger;
      }
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
    }
    if (total > maxBytes) return { status: 'refused', reason: 'too-large' };
    return { status: 'ok', bytes: buf.subarray(0, total) };
  } catch {
    return { status: 'refused', reason: 'unreadable' };
  } finally {
    try {
      closeSync(fd);
    } catch {
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
export function readProjectHead(root: string, path: string, maxBytes: number): ProjectTextRead {
  const where = locate(root, path);
  if (!where.ok) return where.read;
  let fd: number;
  try {
    fd = openSync(where.real, OPEN_FLAGS);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { status: 'absent' };
    if (code === 'EISDIR') return { status: 'refused', reason: 'not-a-regular-file' };
    return { status: 'refused', reason: 'unreadable' };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { status: 'refused', reason: 'not-a-regular-file' };
    const buf = Buffer.allocUnsafe(Math.max(0, Math.min(maxBytes, st.size)));
    let total = 0;
    while (total < buf.length) {
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
    }
    let text = buf.subarray(0, total).toString('utf8');
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return { status: 'ok', text };
  } catch {
    return { status: 'refused', reason: 'unreadable' };
  } finally {
    try {
      closeSync(fd);
    } catch {
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
export async function hashProjectFile(root: string, path: string): Promise<string> {
  const abs = resolve(root, path);
  if (!isWithinDir(root, abs)) return 'outside';
  let st: Stats;
  try {
    st = await lstatAsync(abs);
  } catch {
    return 'missing';
  }
  if (st.isSymbolicLink()) {
    try {
      return `link:${await readlinkAsync(abs)}`;
    } catch {
      return 'link';
    }
  }
  if (!st.isFile()) return 'special';
  let handle;
  try {
    handle = await openAsync(abs, OPEN_FLAGS);
  } catch {
    return 'missing';
  }
  try {
    const fst = await handle.stat();
    if (!fst.isFile()) return 'special';
    const hash = createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      hash.update(chunk.subarray(0, bytesRead));
    }
    return hash.digest('hex');
  } catch {
    return 'missing';
  } finally {
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
export function hashRegularFileSync(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch {
    return null;
  }
  try {
    if (!fstatSync(fd).isFile()) return null;
    const hash = createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      hash.update(chunk.subarray(0, n));
    }
    return hash.digest('hex');
  } catch {
    return null;
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* nothing left to do with it */
    }
  }
}

/** What is at a project path, without following a link. */
export type ProjectEntryKind = 'absent' | 'file' | 'directory' | 'link' | 'other';

/**
 * `lstat`'s answer for `path`: a link (a Windows junction included, which
 * `lstat` reports as one) is `link` and is never followed.
 */
export function projectEntryKind(path: string): ProjectEntryKind {
  let st: Stats;
  try {
    st = lstatSync(path);
  } catch {
    return 'absent';
  }
  if (st.isSymbolicLink()) return 'link';
  if (st.isFile()) return 'file';
  if (st.isDirectory()) return 'directory';
  return 'other';
}

/** What is at a project path, judged without following anything: {@link ProjectEntryKind}, or `remote`. */
export type ProjectEntryKindIn = ProjectEntryKind | 'remote';

/**
 * {@link projectEntryKind} for a path below `root`, safe on any component:
 * every link on the way below `root` is walked first with `lstat` and
 * `readlink` only (`hooks/configFile.ts#walkLinksUnder`), so one that points
 * at a network or device path is `remote` and nothing reaches it. A plain
 * `lstat` follows every component but the last — a `wp-content` link to
 * `\\host\share` held `lstat('wp-content/themes/x')`, like `existsSync`, for
 * 157 s on Windows (review of 3.0, W2E). A path outside `root` is `absent`.
 */
export function projectEntryKindIn(root: string, path: string): ProjectEntryKindIn {
  const abs = resolve(root, path);
  if (!isWithinDir(root, abs)) return 'absent';
  const walk = walkLinksUnder(root, abs);
  if (!walk.ok) return walk.reason === 'remote-link' ? 'remote' : 'other';
  return projectEntryKind(abs);
}

/**
 * What is at `path`, an absolute path named by repository content that may
 * lie anywhere on disk (a solution's `ProjectReference`, a path a tool
 * printed): `remote` for a network path — lexically (`\\host\share`,
 * `\\?\…`, `//host`) or through a link on the way — which is never opened,
 * stat'ed or followed; otherwise as {@link projectEntryKindIn} from the
 * filesystem root.
 */
export function entryKindAnywhere(path: string): ProjectEntryKindIn {
  const lexicallyRemote = /^(?:\\\\|\/\/)/;
  if (lexicallyRemote.test(path)) return 'remote';
  const abs = resolve(path);
  if (lexicallyRemote.test(abs)) return 'remote';
  return projectEntryKindIn(parse(abs).root, abs);
}

/**
 * Whether anything — a dangling link, or a link to a network path, included
 * — is at `path`, which must lie lexically inside `root` (anything outside is
 * `false`, never looked at). For a path named by a repository file, where
 * `existsSync` would follow a link (to a network path too, blocking the
 * server) and answer about any path at all. Nothing is followed:
 * {@link projectEntryKindIn}.
 */
export function presentInProject(root: string, path: string): boolean {
  return projectEntryKindIn(root, path) !== 'absent';
}

/**
 * Where `path` resolves, when that is inside `root`; `null` when it does not
 * exist or resolves outside. For a caller that decides by `stat` (is it a
 * directory?) and must not be sent outside the project by a link to do so.
 */
export function realpathInProject(root: string, path: string): string | null {
  const abs = resolve(root, path);
  if (!isWithinDir(root, abs)) return null;
  if (!walkLinksUnder(root, abs).ok) return null;
  const real = realpathOrNull(abs);
  if (real === null || !isWithinDir(realRoot(root), real)) return null;
  return real;
}

/** What a project path is when followed — through links that stay inside the project only. */
export type ProjectPathKind = 'absent' | 'file' | 'directory' | 'other' | 'outside';

/**
 * `statSync(path)`'s answer for a project path, except that a link leading
 * out of the project (or to a network or device path) is `outside` and is
 * never followed there. For a caller that asks "is it a directory?" and
 * would otherwise walk, list or read wherever a link pointed.
 */
export function projectPathKind(root: string, path: string): ProjectPathKind {
  const abs = resolve(root, path);
  if (!isWithinDir(root, abs)) return 'outside';
  // Links below the root walked first, lstat/readlink only: one to a network
  // or device path is never followed, not even to ask whether it dangles —
  // that realpath is what blocked the server (review of 3.0, W2E); a loop is
  // `other`.
  const walk = walkLinksUnder(root, abs);
  if (!walk.ok) return walk.reason === 'remote-link' ? 'outside' : 'other';
  if (projectEntryKind(abs) === 'absent') return 'absent';
  const real = realpathOrNull(abs);
  if (real === null) return 'absent';
  if (!isWithinDir(realRoot(root), real)) return 'outside';
  let st: Stats;
  try {
    st = lstatSync(real);
  } catch {
    return 'absent';
  }
  if (st.isFile()) return 'file';
  if (st.isDirectory()) return 'directory';
  return 'other';
}

/**
 * What a link below `root` finally names — `directory`, `file`, `other`,
 * `absent` (dangling) — wherever that is, or `remote` when a link on the way
 * points at a network or device path (never followed). Metadata only: a
 * local target is `lstat`ed after the links were walked, nothing is opened.
 * For a walk that must tell a directory link out of the project (a
 * sub-project it did not enter) from a file link it names elsewhere.
 */
export function linkTargetKind(root: string, path: string): 'directory' | 'file' | 'other' | 'absent' | 'remote' {
  const abs = resolve(root, path);
  const walk = walkLinksUnder(root, abs);
  if (!walk.ok) return walk.reason === 'remote-link' ? 'remote' : 'other';
  const real = realpathOrNull(abs);
  if (real === null) return 'absent';
  try {
    const st = lstatSync(real);
    return st.isDirectory() ? 'directory' : st.isFile() ? 'file' : 'other';
  } catch {
    return 'absent';
  }
}

/**
 * A link a directory walk does not follow, named by what it leads to — or
 * null for one it need not name: a link that stays inside is walked in its
 * own place, and a file link out is read where it is found and named by that
 * read. A link to a network path or to a device, a pipe or something that
 * cannot be resolved is never asked what it is (on Windows the question
 * itself reaches the host), so it is named as such, never as "a directory"
 * (round 3 of the review: a `yarn.lock` linked to `\\host\share` read as
 * "a directory link").
 */
export function linkNotFollowed(root: string, path: string): { kind: 'directory' | 'remote' | 'other'; says: string } | null {
  const where = projectPathKind(root, path);
  if (where !== 'outside' && where !== 'other') return null;
  const target = linkTargetKind(root, path);
  if (target === 'directory') return { kind: 'directory', says: 'a directory link out of the project, not followed' };
  if (target === 'remote') return { kind: 'remote', says: 'a link to a network path, never followed' };
  if (target === 'other') return { kind: 'other', says: 'a link to a device, a pipe or a path that cannot be resolved, never followed' };
  return null;
}

/** A directory entry, typed WITHOUT following it: a link is `link`, whatever it names. */
export interface ProjectDirEntry {
  name: string;
  kind: 'file' | 'directory' | 'link' | 'other';
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
export function listProjectDir(root: string, dir: string): ProjectDirEntry[] {
  return listProjectDirOrNull(root, dir) ?? [];
}

/**
 * {@link listProjectDir}, except that a directory that could not be listed
 * — absent, not a directory, unreadable, or reached through a link out of
 * the project — is `null` rather than `[]`: for a walk that must tell an
 * empty directory from one it never read, and say so.
 */
export function listProjectDirOrNull(root: string, dir: string): ProjectDirEntry[] | null {
  const real = realpathInProject(root, dir);
  if (real === null) return null;
  let entries;
  try {
    entries = readdirSync(real, { withFileTypes: true });
  } catch {
    return null;
  }
  return entries.map((e) => ({
    name: e.name,
    kind: e.isSymbolicLink() ? 'link' : e.isFile() ? 'file' : e.isDirectory() ? 'directory' : 'other',
  }));
}

/** Why a project write did not happen. */
export type ProjectWriteRefusal =
  /** The target is not below the project root. */
  | 'outside-project'
  /** A directory on the way resolves outside the project, or is not a directory. */
  | 'escaping-directory'
  /** The target is a link — a junction or a dangling link included. */
  | 'link'
  /** The target exists and is not a regular file (a directory, a FIFO, a device). */
  | 'not-a-regular-file'
  /** `create` only: something is already there. */
  | 'exists'
  /** The filesystem refused (permissions, a read-only checkout, a full disk). */
  | 'failed';

export type ProjectWriteResult =
  | { ok: true; bytes: number }
  | { ok: false; reason: ProjectWriteRefusal; detail?: string };

export interface ProjectWriteOptions {
  /** `create`: only when nothing is at that name. `replace`: create, or replace a regular file. */
  mode: 'create' | 'replace';
}

/** A readable sentence for a refusal, for a tool's `reason` field. */
export function describeWriteRefusal(reason: ProjectWriteRefusal, detail?: string): string {
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
export function describeReadRefusal(reason: ProjectReadRefusal): string {
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
    case 'read-budget':
      return "it was not read: this check's read budget was spent before it";
  }
}

/**
 * What one walk of a project may read in all: `bytes` and `files`. Per-file
 * caps bound one read; a walk that reads every manifest, header or config it
 * finds needs a bound of its own — 80 `requirements-N.txt` of 8 MiB each (one
 * git blob, a few KB on the wire) were each under the cap and together took a
 * 768 MB server down (review of 3.0, W2E). A read the budget cannot cover is
 * `read-budget`, and the caller names the file like any other refusal.
 */
export class ReadBudget {
  private bytesLeft: number;
  private filesLeft: number;
  private spentOn: string[] = [];

  constructor(
    readonly maxBytes: number,
    readonly maxFiles: number,
  ) {
    this.bytesLeft = maxBytes;
    this.filesLeft = maxFiles;
  }

  /** Whether anything is left to read. */
  get spent(): boolean {
    return this.bytesLeft <= 0 || this.filesLeft <= 0;
  }

  /** The paths refused for the budget, in the order they were asked for. */
  get refused(): readonly string[] {
    return this.spentOn;
  }

  /** `bytes, files` in a sentence, for a note. */
  describe(): string {
    return `${Math.round(this.maxBytes / (1024 * 1024))} MiB / ${this.maxFiles} files`;
  }

  /** {@link readProjectText} within the budget: at most `maxBytes`, and never past what is left. */
  readText(root: string, path: string, maxBytes: number): ProjectTextRead {
    const cap = this.take(path, maxBytes);
    if (cap === null) return { status: 'refused', reason: 'read-budget' };
    const r = readProjectText(root, path, cap);
    return this.settle(path, r, cap < maxBytes, r.status === 'ok' ? Buffer.byteLength(r.text) : 0);
  }

  /** {@link readProjectHead} within the budget. */
  readHead(root: string, path: string, maxBytes: number): ProjectTextRead {
    const cap = this.take(path, maxBytes);
    if (cap === null) return { status: 'refused', reason: 'read-budget' };
    const r = readProjectHead(root, path, cap);
    return this.settle(path, r, false, r.status === 'ok' ? Buffer.byteLength(r.text) : 0);
  }

  /** The cap for the next read, or null (refused) when nothing is left. */
  private take(path: string, maxBytes: number): number | null {
    if (this.spent) {
      this.spentOn.push(path);
      return null;
    }
    this.filesLeft -= 1;
    return Math.min(maxBytes, this.bytesLeft);
  }

  private settle(path: string, r: ProjectTextRead, capped: boolean, bytes: number): ProjectTextRead {
    this.bytesLeft -= bytes;
    // Too large for what was LEFT, though not for the caller's own cap: the budget's refusal.
    if (capped && r.status === 'refused' && r.reason === 'too-large') {
      this.bytesLeft = 0;
      this.spentOn.push(path);
      return { status: 'refused', reason: 'read-budget' };
    }
    return r;
  }
}

/**
 * Makes every missing directory between `root` and `dir`, one level at a
 * time, and checks every existing one resolves inside `root` and is a
 * directory. `null` on success, else the offending path.
 */
function ensureDirsInside(root: string, dir: string): string | null {
  const rootAbs = resolve(root);
  const rootReal = realRoot(root);
  const parts = relative(rootAbs, resolve(dir)).split(/[\\/]+/).filter((p) => p.length > 0);
  let current = rootAbs;
  for (const part of parts) {
    current = join(current, part);
    let st: Stats | null = null;
    try {
      st = lstatSync(current);
    } catch {
      st = null;
    }
    if (st === null) {
      try {
        mkdirSync(current);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') return current;
      }
      try {
        st = lstatSync(current);
      } catch {
        return current;
      }
    }
    if (st.isSymbolicLink()) {
      // Never followed to a network or device path, not even by realpath.
      if (!walkLinksUnder(rootAbs, current).ok) return current;
      const real = realpathOrNull(current);
      if (real === null || !isWithinDir(rootReal, real)) return current;
      try {
        if (!lstatSync(real).isDirectory()) return current;
      } catch {
        return current;
      }
      continue;
    }
    if (!st.isDirectory()) return current;
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
export function makeProjectDir(root: string, rel: string): string | null {
  const rootAbs = resolve(root);
  const target = resolve(rootAbs, rel);
  if (!isWithinDir(rootAbs, target)) return null;
  let current = rootAbs;
  for (const part of relative(rootAbs, target).split(/[\\/]+/).filter((p) => p.length > 0)) {
    current = join(current, part);
    let st: Stats | null;
    try {
      st = lstatSync(current);
    } catch {
      st = null;
    }
    if (st === null) {
      try {
        mkdirSync(current);
        st = lstatSync(current);
      } catch {
        return null;
      }
    }
    if (st.isSymbolicLink() || !st.isDirectory()) return null;
  }
  return target;
}

function removeQuietly(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone, or held by another process: the name is random and hidden */
  }
}

/** A fresh temp file beside `target` holding `content`, opened `wx` so an existing entry is never touched. */
function writeTempBeside(target: string, content: Buffer, mode: number | undefined): string {
  const tmp = join(dirname(target), `.${randomBytes(8).toString('hex')}.dev-guardian.tmp`);
  const fd = openSync(tmp, 'wx', mode ?? 0o666);
  let done = false;
  try {
    let off = 0;
    while (off < content.length) off += writeSync(fd, content, off, content.length - off);
    done = true;
  } finally {
    closeSync(fd);
    if (!done) removeQuietly(tmp);
  }
  return tmp;
}

/**
 * Writes `content` to `path` inside `root` — see the module doc. Never
 * throws: a refusal or a filesystem error comes back as `{ ok: false }`.
 */
export function writeProjectFile(
  root: string,
  path: string,
  content: string | Buffer,
  options: ProjectWriteOptions,
): ProjectWriteResult {
  const target = resolve(root, path);
  if (!isWithinDir(root, target) || caseFold(target) === caseFold(resolve(root))) {
    return { ok: false, reason: 'outside-project' };
  }
  const bytes = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
  const badDir = ensureDirsInside(root, dirname(target));
  if (badDir !== null) return { ok: false, reason: 'escaping-directory', detail: relative(resolve(root), badDir) };

  let existing: Stats | null = null;
  try {
    existing = lstatSync(target);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') {
      return { ok: false, reason: 'failed', detail: (e as Error).message };
    }
  }
  if (existing !== null) {
    if (existing.isSymbolicLink()) return { ok: false, reason: 'link' };
    if (!existing.isFile()) return { ok: false, reason: 'not-a-regular-file' };
    if (options.mode === 'create') return { ok: false, reason: 'exists' };
  }

  let tmp: string;
  try {
    tmp = writeTempBeside(target, bytes, existing === null ? undefined : existing.mode & 0o777);
  } catch (e) {
    return { ok: false, reason: 'failed', detail: (e as Error).message };
  }
  try {
    if (existing === null) {
      try {
        linkSync(tmp, target);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code === 'EEXIST') return { ok: false, reason: options.mode === 'create' ? 'exists' : 'link' };
        // No hard links here (FAT/exFAT, some network shares): an lstat
        // check and a rename. The one race left — an entry created at the
        // name between the two — is replaced, never written through.
        if (projectEntryKind(target) !== 'absent') return { ok: false, reason: 'exists' };
        renameSync(tmp, target);
      }
    } else {
      renameSync(tmp, target);
    }
    return { ok: true, bytes: bytes.length };
  } catch (e) {
    return { ok: false, reason: 'failed', detail: (e as Error).message };
  } finally {
    removeQuietly(tmp);
  }
}
