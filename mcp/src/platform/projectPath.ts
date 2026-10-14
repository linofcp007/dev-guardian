/**
 * Resolve and validate a project_path argument.
 *
 * Rules (in order):
 *  1. Missing or empty → resolve to `process.cwd()`.
 *  2. On Windows, a network (UNC) path — `\\host\share`, `//host/share` — is
 *     refused before any file-system call (see {@link isNetworkPath}).
 *  3. Resolved path must exist and be a directory.
 *  4. The path is returned in CANONICAL form — see {@link canonicalPath}.
 *  5. It must not be a filesystem root or the user-home root — mass scans
 *     starting there are almost always a mistake and can take hours.
 *
 * Callers receive `ResolvedProjectPath`, which always carries the resolved
 * absolute path and an optional warning the caller surfaces in tool output
 * (currently unused; reserved for the `.guardian/` writability fallback
 * which lives in `storage/db.ts`). A refusal is an
 * {@link InvalidProjectPathError}; {@link projectPathErrorCode} is the domain
 * error code every tool answers it with.
 */

import { existsSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { parse, resolve } from 'node:path';
import { walkLinksUnder } from '../hooks/configFile.js';

type InvalidProjectPathReason = 'not_found' | 'not_a_directory' | 'root_or_home' | 'network_path';

const REASON_HINT: Record<InvalidProjectPathReason, string> = {
  not_found: '',
  not_a_directory: '',
  root_or_home: '',
  network_path:
    ' — a network (UNC) path: dev-guardian scans local directories only, because every file call on a ' +
    'share that does not answer blocks the whole server; scan a local copy of the project',
};

export class InvalidProjectPathError extends Error {
  constructor(
    public readonly reason: InvalidProjectPathReason,
    public readonly path: string,
    /** The link on the way that leads to the network, when the path itself is spelled locally. */
    via?: string,
  ) {
    super(`Invalid project_path (${reason}): ${path}${via !== undefined ? ` (through the link ${via})` : ''}${REASON_HINT[reason]}`);
    this.name = 'InvalidProjectPathError';
  }
}

/**
 * The domain error code for a `project_path` that {@link resolveProjectPath}
 * refused: `target_not_found` when nothing is there, `unsupported_target`
 * when something is but it cannot be a project (a file, a root or home
 * directory, a network path) — and for any other error resolving it. Every
 * tool used to answer all of these with `not_a_git_repo`, which named a
 * cause none of them has (review 8, finding 16).
 */
export function projectPathErrorCode(e: unknown): 'target_not_found' | 'unsupported_target' {
  return e instanceof InvalidProjectPathError && e.reason === 'not_found' ? 'target_not_found' : 'unsupported_target';
}

/**
 * Whether `p` is a Windows network path: two leading separators of either
 * kind (`\\host\share`, `//host/share`, and the `\\?\` / `\\.\` device
 * forms). Judged on the string alone — `existsSync`, `statSync` and
 * `realpathSync` on an unreachable host block the event loop for about 21 s
 * each, and every tool takes a `project_path` (review 8, finding 8: a ping
 * sent 300 ms after `detect_stack` was given such a path was answered after
 * 20.7 s). Never true on POSIX, where `//x` is a local path.
 */
export function isNetworkPath(p: string, platform: NodeJS.Platform = process.platform): boolean {
  return platform === 'win32' && /^[\\/]{2}/.test(p);
}

interface ResolvedProjectPath {
  path: string;
  warning?: string;
}

export function resolveProjectPath(input?: string): ResolvedProjectPath {
  const raw = input && input.length > 0 ? input : process.cwd();
  // The input names the host; `resolve()` is pure, and its result is checked
  // too (a relative path under a UNC working directory).
  if (isNetworkPath(raw)) throw new InvalidProjectPathError('network_path', raw);
  const candidate = resolve(raw);
  if (isNetworkPath(candidate)) throw new InvalidProjectPathError('network_path', candidate);
  // A local spelling can still lead there: a link (a directory symlink, a
  // junction) on the way to a share. `existsSync` and `statSync` follow it,
  // and on a share that does not answer each blocked ~21 s — 42 s, then
  // "does not exist" (review 10). Decided on the links' own text, read with
  // lstat and readlink only, like the UNC spelling above.
  if (process.platform === 'win32') {
    const walk = walkLinksUnder(parse(candidate).root, candidate);
    if (!walk.ok && walk.reason === 'remote-link') throw new InvalidProjectPathError('network_path', candidate, walk.at);
  }

  if (!existsSync(candidate)) {
    throw new InvalidProjectPathError('not_found', candidate);
  }
  if (!statSync(candidate).isDirectory()) {
    throw new InvalidProjectPathError('not_a_directory', candidate);
  }
  const canonical = canonicalPath(candidate);
  if (isRootOrHome(canonical)) {
    throw new InvalidProjectPathError('root_or_home', canonical);
  }

  return { path: canonical };
}

/**
 * One spelling per directory, because every scan, finding and snapshot is
 * keyed by the `project_path` string. The live database held the same
 * project as both `C:\Users\ADMINI~1\…` (an 8.3 short name — what
 * `os.tmpdir()` returns on many Windows machines) and
 * `C:\Users\Administrator\…`, which split its history in two and made every
 * project-scoped lookup through one spelling miss the other.
 *
 *   - `realpathSync.native`: long names, links resolved, true on-disk case.
 *   - win32: upper-case drive letter and backslashes, whatever the input
 *     used. A drive-letter path that realpath would turn into its UNC target
 *     (a mapped network drive) keeps the drive letter: `cmd.exe` cannot use a
 *     UNC working directory and Git Bash handles one poorly, and every
 *     scanner runs in this directory.
 *   - A path realpath cannot resolve keeps its lexical `resolve()` form.
 *
 * Only NEW paths are affected: rows already stored under another spelling
 * are left as they are (the path may not even exist on this machine).
 */
export function canonicalPath(p: string): string {
  const resolved = resolve(p);
  let canonical = resolved;
  try {
    canonical = realpathSync.native(resolved);
  } catch {
    /* unresolvable (permissions, vanished): keep the lexical form */
  }
  if (process.platform === 'win32') {
    if (canonical.startsWith('\\\\') && !resolved.startsWith('\\\\')) canonical = resolved;
    canonical = canonical
      .replace(/\//g, '\\')
      .replace(/^([a-z]):/, (_m, drive: string) => `${drive.toUpperCase()}:`);
  }
  return canonical;
}

function isRootOrHome(p: string): boolean {
  // Filesystem root (e.g. "C:\\" or "/")
  if (parse(p).root === p) return true;
  // User home root (e.g. "/home/foo" or "C:\\Users\\foo"), in either spelling.
  const home = resolve(homedir());
  return p === home || p === canonicalPath(home);
}
