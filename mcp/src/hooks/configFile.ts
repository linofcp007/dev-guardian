/**
 * Reading a small file that a project or a user controls — the hooks'
 * `.guardian/hooks.config.json`, `.guardian/hooks-allowlist.json` and
 * `~/.config/dev-guardian/hooks.json`, and the registry configuration the
 * install hook consults (`.npmrc`, `package.json`, `pip.conf`, …).
 *
 * Every one of those reads runs synchronously inside a hook that Claude Code
 * kills after 15 s, and a hook that dies lets the tool call through. The
 * reader this replaced did `existsSync` and then `readFileSync`, with no check
 * on WHAT the path was: `mkfifo .guardian/hooks.config.json` blocked the read
 * forever, `ln -s /dev/zero .guardian/hooks.config.json` read without end, and
 * a 300 MB file took 23 s on Windows — each one the whole guard switched off
 * by making it time out (Task 23 fix round 2, N1).
 *
 * So the reader judges what it OPENED, never what the path said a moment
 * earlier:
 *
 *   1. `openSync(path, O_RDONLY | O_NONBLOCK)` — a link is followed, and on
 *      POSIX a FIFO opens at once instead of waiting for a writer. Windows has
 *      no `O_NONBLOCK` (the flag is 0 there); a named pipe opens at once
 *      anyway when a server is listening, and fails when none is.
 *   2. `fstatSync(fd)` on that descriptor: only a regular file no larger than
 *      the cap is read. A Windows symlink to a named pipe `stat`s as a 0-byte
 *      regular file but `fstat`s as what it is, and a path swapped for a FIFO
 *      or a `/dev/zero` link after any earlier check changes nothing — the
 *      descriptor is the thing being judged (Task 23 fix round 3; the round-2
 *      reader `stat`ed the path and then read it, and hung on both).
 *   3. `readSync` at most cap + 1 bytes from that descriptor; more than the cap
 *      is `too-large`, which also covers a file that grew after the `fstat`.
 *   4. `closeSync` in a `finally`.
 *
 * A path that does not exist is `absent`; any other failure is `refused`
 * (`unreadable`). The hook treats `refused` exactly like `absent` — the
 * protective defaults — and names the file in its SessionStart notice. A
 * leading UTF-8 byte-order mark (PowerShell 5 writes one) is stripped before
 * parsing.
 *
 * ## A link to the network, refused before anything is opened
 *
 * Judging the descriptor cannot help when the OPEN is what hangs. A Windows
 * link — the file itself, or `.guardian` as a directory link — to
 * `\\<unreachable host>\share\…` blocks `openSync` for minutes (~136 s was
 * measured), far past the 15 s the hook has. So when the caller names the
 * directory the file lives under (`under`: the project for `.guardian/…`, the
 * home directory for `~/.config/dev-guardian/hooks.json`), every path
 * component below it is walked first with `lstat` and `readlink` only —
 * neither follows a link, so no link target is ever touched — resolving each
 * local link hop by hop, and the file is refused (`remote-link`) when any link
 * on the way points at a UNC or device-namespace path (`\\…`, `//…`, `\\?\…`,
 * `\\.\…`). Covered: the file, `.guardian`, `.config`, `dev-guardian`, and a
 * chain of local links ending in such a target. Not covered: the directory
 * named by `under` itself and its ancestors (the user's own layout), and a
 * local path the OS itself redirects (a mapped drive letter, a DFS mount).
 *
 * Pure `node:` built-ins, no other import: the hook dispatcher loads the
 * compiled copy from `mcp/dist/hooks/` in an install with no `node_modules`.
 */

import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync } from 'node:fs';
import { isAbsolute, join, parse, relative, resolve } from 'node:path';

/** The largest hook configuration file the hooks will read. */
export const MAX_HOOK_CONFIG_BYTES = 64 * 1024;

/** Why an existing path was not read. */
export type RefusalReason = 'not-a-regular-file' | 'too-large' | 'unreadable' | 'remote-link';

export type SmallFileRead =
  | { status: 'absent' }
  | { status: 'ok'; value: unknown }
  /** A small regular file whose content is not JSON. */
  | { status: 'invalid' }
  /** A path that exists but was not read: not a regular file, too large, or reached through a network link. */
  | { status: 'refused'; reason: RefusalReason };

type TextRead =
  | { status: 'absent' }
  | { status: 'ok'; text: string }
  | { status: 'refused'; reason: RefusalReason };

/** `O_NONBLOCK` where the platform has it; 0 on Windows, where it is undefined. */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

/** Link hops followed before a path is refused as a loop (Linux's own limit is 40). */
const MAX_LINK_HOPS = 32;

/**
 * A link target that leaves the local filesystem: a UNC path (`\\host\share`,
 * `//host/share`) or the Win32 device namespace (`\\?\…`, `\\.\…`), and the NT
 * object-manager spelling (`\??\…`). Opening any of them may wait on the
 * network, or on a device, for longer than the hook may take.
 */
export function isRemoteOrDeviceTarget(target: string): boolean {
  return /^(?:[\\/]{2}|\\\?\?\\)/.test(target);
}

export type LinkWalk = { ok: true } | { ok: false; reason: 'remote-link' | 'unreadable'; at: string };

/**
 * Walks `path`'s components below `under` with `lstat` and `readlink` only —
 * never opening, stat-ing or otherwise following a link — and says whether any
 * link on the way (a local link's own target included, hop by hop) points off
 * the local filesystem. `path` outside `under` is not walked (`ok`). A
 * component that does not exist ends the walk (`ok`): the open that follows
 * will report it. More than {@link MAX_LINK_HOPS} links is a loop
 * (`unreadable`). See the module doc for what this does and does not cover.
 */
export function walkLinksUnder(under: string, path: string): LinkWalk {
  const rel = relative(resolve(under), resolve(path));
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return { ok: true };
  let current = resolve(under);
  const queue = rel.split(/[\\/]+/).filter((p) => p.length > 0);
  let hops = 0;
  for (let part = queue.shift(); part !== undefined; part = queue.shift()) {
    if (part === '.') continue;
    if (part === '..') {
      current = resolve(current, '..');
      continue;
    }
    const next = join(current, part);
    let isLink: boolean;
    try {
      isLink = lstatSync(next).isSymbolicLink();
    } catch {
      return { ok: true };
    }
    if (!isLink) {
      current = next;
      continue;
    }
    hops += 1;
    if (hops > MAX_LINK_HOPS) return { ok: false, reason: 'unreadable', at: next };
    let target: string;
    try {
      target = readlinkSync(next);
    } catch {
      return { ok: false, reason: 'unreadable', at: next };
    }
    if (isRemoteOrDeviceTarget(target)) return { ok: false, reason: 'remote-link', at: next };
    // Continue from the link's target, itself walked component by component
    // from its root: an intermediate component of it may be a link too.
    const resolved = resolve(current, target);
    const root = parse(resolved).root;
    queue.unshift(...resolved.slice(root.length).split(/[\\/]+/).filter((p) => p.length > 0));
    current = root;
  }
  return { ok: true };
}

function readText(path: string, maxBytes: number): TextRead {
  let fd: number;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    // A dangling symlink is ENOENT too: nothing there to read.
    if (code === 'ENOENT' || code === 'ENOTDIR') return { status: 'absent' };
    // Windows refuses to open a directory as a file.
    if (code === 'EISDIR') return { status: 'refused', reason: 'not-a-regular-file' };
    return { status: 'refused', reason: 'unreadable' };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { status: 'refused', reason: 'not-a-regular-file' };
    if (st.size > maxBytes) return { status: 'refused', reason: 'too-large' };
    const buf = Buffer.alloc(maxBytes + 1);
    let total = 0;
    while (total < buf.length) {
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
    }
    // More than the cap: the file grew after the fstat. Still refused.
    if (total > maxBytes) return { status: 'refused', reason: 'too-large' };
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
 * A small JSON file, parsed — or why it was not. With `under`, the path's
 * components below that directory are walked for a network link first
 * ({@link walkLinksUnder}); see the module doc.
 */
export function readSmallJsonFile(
  path: string,
  maxBytes: number = MAX_HOOK_CONFIG_BYTES,
  under?: string,
): SmallFileRead {
  if (under !== undefined) {
    const walk = walkLinksUnder(under, path);
    if (!walk.ok) return { status: 'refused', reason: walk.reason };
  }
  const r = readText(path, maxBytes);
  if (r.status !== 'ok') return r;
  try {
    return { status: 'ok', value: JSON.parse(r.text) as unknown };
  } catch {
    return { status: 'invalid' };
  }
}

/**
 * A small text file's content, or `undefined` for anything else. `under`
 * works as in {@link readSmallJsonFile}.
 */
export function readSmallTextFile(path: string, maxBytes: number, under?: string): string | undefined {
  if (under !== undefined && !walkLinksUnder(under, path).ok) return undefined;
  const r = readText(path, maxBytes);
  return r.status === 'ok' ? r.text : undefined;
}
