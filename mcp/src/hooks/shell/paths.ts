/**
 * Paths as a command moves between directories: a target resolved against the
 * `cd`, `pushd` or `Set-Location` before it (`resolveFrom`, `cwdAfter`), its
 * directory, the normalised form the registry checks compare, and `*` / `?`
 * matching on a name. Moved out of `bashGuard.ts`; the effects model and the
 * rules both read paths this way.
 *
 * Pure functions. No I/O.
 */

import { psParam } from './command.js';

/** A path as the registry checks compare it: `/` separators, no doubled or trailing one, lower-cased. */
export function normalizedPath(path: string): string {
  return path.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase();
}

/** A path that does not depend on the current directory: `/…`, `~…`, `$VAR…`, `%VAR%…`, `\\…`, `C:…`. */
export function isAbsolutePath(path: string): boolean {
  return /^(?:[\\/~$%]|[A-Za-z]:)/.test(path);
}

/**
 * `target` as the command sees it after the `cd`s before it (`cwd`; `''` while
 * there was none): joined onto `cwd` unless absolute, every `\` read as `/`,
 * and `.` and `..` segments folded. So `cd ~/.config/dev-guardian && echo … >
 * hooks.json` names the file it writes, and so does `echo … >
 * .guardian/x/../hooks.config.json`.
 */
export function resolveFrom(cwd: string, target: string): string {
  const joined = cwd === '' || isAbsolutePath(target) ? target : `${cwd.replace(/[\\/]+$/, '')}/${target}`;
  const parts = joined.replace(/\\/g, '/').split('/');
  const out: string[] = [];
  parts.forEach((part, i) => {
    if (part === '.' || (part === '' && i > 0 && i < parts.length - 1)) return;
    const prev = out[out.length - 1];
    if (part === '..' && prev !== undefined && prev !== '..' && prev !== '') {
      out.pop();
      return;
    }
    out.push(part);
  });
  return out.join('/');
}

/** `a/b/c` → `a/b`; `''` when there is no directory part. */
export function dirOf(path: string): string {
  const cut = path.lastIndexOf('/');
  return cut < 0 ? '' : path.slice(0, cut);
}

/** The longest current directory tracked. */
export const MAX_CWD = 320;

export const CD_COMMANDS = new Set(['cd', 'chdir', 'pushd', 'set-location', 'sl', 'push-location']);

export const CD_RETURNS = new Set(['popd', 'pop-location']);

/**
 * The directory a `cd`, `pushd` or `Set-Location` moves to from `cwd`, or
 * `undefined` when `name` is none of them. A bare `cd` goes home; `cd -`,
 * `popd` and `Pop-Location` go back somewhere this does not track, which reads
 * as where the command started (`''`).
 */
export function cwdAfter(name: string, args: readonly string[], cwd: string, dataDir?: string): string | undefined {
  if (CD_RETURNS.has(name)) return '';
  if (!CD_COMMANDS.has(name)) return undefined;
  const dir =
    psParam(args, ['path', 'literalpath']) ?? args.find((a) => a === '-' || !(a.startsWith('-') || /^\/d$/i.test(a)));
  if (dir === undefined) return '~';
  if (dir === '-') return '';
  const next = resolveFrom(cwd, dir);
  // Only a directory a later relative path could need is tracked: one that
  // names a configuration directory or a parent of one — or dev-guardian's
  // data directory, whose registry is guarded too (review 3.0 wave 2, round
  // 2). Any other relative target still names its own path in full. And
  // never one longer than a real directory: a chain of `cd`s built to be slow.
  if (next.length > MAX_CWD) return '';
  const tracked =
    /\.guardian|dev-guardian|\.config|\.claude|registry|guardian_data_dir|localappdata|xdg_data_home|\.local/i.test(next) ||
    (dataDir !== undefined && normalizedPath(next).startsWith(dataDir));
  return tracked ? next : '';
}

/**
 * `*` / `?` matching without backtracking (a `[…]` class matches any one
 * character): the classic two-pointer walk, O(pattern × name). A pattern
 * turned into a RegExp of `.*` runs backtracks exponentially on a name it
 * does not match.
 */
export function wildcardMatch(pattern: string, name: string): boolean {
  const pat = pattern.replace(/\[[^\]]*\]/g, '?');
  let pi = 0;
  let ni = 0;
  let star = -1;
  let mark = 0;
  while (ni < name.length) {
    const c = pat.charAt(pi);
    if (pi < pat.length && (c === '?' || c === name.charAt(ni))) {
      pi += 1;
      ni += 1;
    } else if (pi < pat.length && c === '*') {
      star = pi;
      mark = ni;
      pi += 1;
    } else if (star >= 0) {
      pi = star + 1;
      mark += 1;
      ni = mark;
    } else return false;
  }
  while (pat.charAt(pi) === '*') pi += 1;
  return pi === pat.length;
}
