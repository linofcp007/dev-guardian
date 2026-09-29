/**
 * Whether a stored project path is another SPELLING of a directory — the
 * same directory entries, written differently — and never a path that
 * reaches it through a link.
 *
 * Spellings of one directory: a lower-case drive letter (2.0.0 stored
 * `resolve(input)`: `c:\Users\…`), letter case on a case-insensitive file
 * system, an 8.3 short name, separators, `.` components and a trailing
 * separator. None of those can come to mean another directory. A link can:
 * `~/work/current` repointed from project A to project B, or `/proc/self/cwd`,
 * which is whatever directory the reading process runs in — a path anyone can
 * write into a database that then "matches" every project it is opened in.
 *
 * Two questions, answered two ways:
 *
 *   - {@link isSpellingOf} asks it of a path read from a database that may be
 *     ANYONE's (the legacy adoption, `storage/dbProvenance.ts`), and never
 *     gives that path to the file system. The spellings are derived from the
 *     project's OWN path — its drive-letter case, its separators, its own 8.3
 *     short form from the short-name API — and the stored string is compared
 *     with them lexically. Round 4 stat'ed each stored path to learn what it
 *     spelled: an archive whose database listed four scans under
 *     `\\192.0.2.x\share\proj` held the server for 60 541 ms before it
 *     answered (the MCP client timed out; a reachable host is sent the user's
 *     NTLM credentials), and a macOS `/net/<host>` path mounts on a stat.
 *   - {@link spellingOnlyCanonical} asks it of a path in the user's OWN
 *     database (the startup rewrite of 2.0.0 spellings,
 *     `storage/maintenance.ts`), where there is no project path to derive
 *     from: it resolves the stored path on disk, local paths only.
 *
 * Both refuse, before anything else, a path naming a network share, a device
 * or an NT namespace ({@link isNetworkOrDevicePath}).
 */

import { spawnSync } from 'node:child_process';
import { lstatSync, statSync } from 'node:fs';
import { isAbsolute, join, parse, resolve, sep } from 'node:path';
import { canonicalPath } from './projectPath.js';

/**
 * `\\server\share`, `//server/share`, `\\?\…`, `\\.\…` (devices, pipes) and
 * `\??\…` (the NT object namespace): paths the file system answers by going
 * to the network or to a device. Never looked at, never a spelling.
 */
export function isNetworkOrDevicePath(path: string): boolean {
  return /^[\\/]{2}/.test(path) || path.startsWith('\\??\\');
}

const isWindows = (): boolean => process.platform === 'win32';

/**
 * `path` as its components — the root first (`C:` upper-cased, or `''` for
 * `/`), then each name — read lexically: separators of either kind on
 * Windows, repeated separators, `.` components and a trailing separator
 * dropped. Null for anything that is not a plain local absolute path, and for
 * a `..` component (`a\link\..` is not `a` when `link` is a link).
 */
function lexicalComponents(path: string, windows: boolean): string[] | null {
  if (path.includes('\0') || isNetworkOrDevicePath(path)) return null;
  let root: string;
  let rest: string;
  if (windows) {
    const drive = /^([A-Za-z]):[\\/]/.exec(path);
    if (drive === null || drive[1] === undefined) return null;
    root = `${drive[1].toUpperCase()}:`;
    rest = path.slice(3);
  } else {
    if (!path.startsWith('/')) return null;
    root = '';
    rest = path.slice(1);
  }
  const names = rest.split(windows ? /[\\/]+/ : /\/+/).filter((s) => s !== '' && s !== '.');
  if (names.includes('..')) return null;
  return [root, ...names];
}

/**
 * The 8.3 short spelling of `canonical` (a directory of the user's own,
 * never a path read from a database), as components; null when it cannot be
 * had. `cmd`'s `%~sI` is the short-name API within reach of Node, which has
 * no binding for `GetShortPathNameW`. A path holding `%` (which `cmd` would
 * expand) or `"` is not asked about.
 */
function shortComponents(canonical: string): string[] | null {
  if (!isWindows() || /[%"]/.test(canonical)) return null;
  const cmd = join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'cmd.exe');
  const r = spawnSync(cmd, ['/d', '/v:off', '/s', '/c', `"for %I in ("${canonical}") do @echo %~sI"`], {
    encoding: 'utf8',
    timeout: 3000,
    windowsHide: true,
    windowsVerbatimArguments: true,
  });
  if (r.error !== undefined || r.status !== 0 || typeof r.stdout !== 'string') return null;
  return lexicalComponents(r.stdout.trim(), true);
}

/**
 * A test for "is `stored` a spelling of `canonicalProject`" — the project's
 * canonical path ({@link canonicalPath}) — that never gives `stored` to the
 * file system. Compared component by component with the project's own
 * components, or (Windows) its own 8.3 short ones, asked of the short-name
 * API at most once and only when a stored path holds a `~`. Letter case is
 * ignored on Windows and macOS, whose file systems ignore it by default: on
 * a case-sensitive volume a case variant is at most a different directory
 * the attacker would have had to guess by name anyway, which is what the
 * check makes them do.
 */
export function spellingMatcher(canonicalProject: string): (stored: string) => boolean {
  const windows = isWindows();
  const fold = windows || process.platform === 'darwin';
  const same = (a: string, b: string | undefined): boolean =>
    b !== undefined && (fold ? a.toLowerCase() === b.toLowerCase() : a === b);
  const own = lexicalComponents(canonicalProject, windows);
  let short: string[] | null | undefined;
  return (stored: string): boolean => {
    if (own === null) return false;
    const parts = lexicalComponents(stored, windows);
    if (parts === null || parts.length !== own.length) return false;
    if (parts.every((p, i) => same(p, own[i]))) return true;
    if (!windows || !parts.some((p) => p.includes('~'))) return false;
    short ??= shortComponents(canonicalProject);
    const shortForm = short;
    if (shortForm === null || shortForm.length !== own.length) return false;
    return parts.every((p, i) => same(p, own[i]) || same(p, shortForm[i]));
  };
}

/** Whether `stored` is a spelling of `canonicalProject` ({@link spellingMatcher}, for one path). */
export function isSpellingOf(stored: string, canonicalProject: string): boolean {
  return spellingMatcher(canonicalProject)(stored);
}

/**
 * The canonical spelling of `path` when it names an existing LOCAL directory,
 * differs from it, and reaches it through no link; null otherwise. Resolves
 * `path` on disk — for paths in the user's own database only (see the module
 * comment); a network or device path is refused before any look.
 */
export function spellingOnlyCanonical(path: string): string | null {
  if (!isAbsolute(path) || isNetworkOrDevicePath(path)) return null;
  try {
    if (!statSync(path).isDirectory()) return null;
  } catch {
    return null;
  }
  const canonical = canonicalPath(path);
  if (canonical === path) return null;
  // Every component, from the root down, must be a real directory entry.
  const resolved = resolve(path);
  const root = parse(resolved).root;
  let current = root;
  for (const part of resolved.slice(root.length).split(sep).filter((s) => s !== '')) {
    current = join(current, part);
    try {
      if (lstatSync(current).isSymbolicLink()) return null;
    } catch {
      return null;
    }
  }
  return canonical;
}
