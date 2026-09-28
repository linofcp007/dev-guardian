/**
 * Resolve and validate a project_path argument.
 *
 * Rules (in order):
 *  1. Missing or empty → resolve to `process.cwd()`.
 *  2. Resolved path must exist and be a directory.
 *  3. The path is returned in CANONICAL form — see {@link canonicalPath}.
 *  4. It must not be a filesystem root or the user-home root — mass scans
 *     starting there are almost always a mistake and can take hours.
 *
 * Callers receive `ResolvedProjectPath`, which always carries the resolved
 * absolute path and an optional warning the caller surfaces in tool output
 * (currently unused; reserved for the `.guardian/` writability fallback
 * which lives in `storage/db.ts`).
 */

import { existsSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { parse, resolve } from 'node:path';

export class InvalidProjectPathError extends Error {
  constructor(
    public readonly reason: 'not_found' | 'not_a_directory' | 'root_or_home',
    public readonly path: string,
  ) {
    super(`Invalid project_path (${reason}): ${path}`);
    this.name = 'InvalidProjectPathError';
  }
}

export interface ResolvedProjectPath {
  path: string;
  warning?: string;
}

export function resolveProjectPath(input?: string): ResolvedProjectPath {
  const candidate = resolve(input && input.length > 0 ? input : process.cwd());

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
