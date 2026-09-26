/**
 * The absolute path a bare command name resolves to on PATH — so a test can
 * probe ONE binary and then spawn that same binary, instead of probing a bare
 * name and spawning a bare name that may resolve elsewhere the second time
 * (the current directory is searched first on Windows, and a PATH with
 * `C:\Windows\System32` ahead of Git's `bin` turns bare `bash` into the WSL
 * launcher).
 */

import { statSync } from 'node:fs';
import { delimiter, extname, isAbsolute, join } from 'node:path';

export interface ResolveOptions {
  /** Defaults to `process.env.PATH` (or `Path`); split on the host's `path.delimiter`. */
  readonly path?: string;
  /** Windows only: extensions tried for a name without one. Defaults to `PATHEXT`. */
  readonly pathext?: string;
  /** Decides whether `PATHEXT` applies. Defaults to the host's. */
  readonly platform?: NodeJS.Platform;
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * `command` as an absolute path: itself when already absolute and present,
 * else the first match on PATH (with `PATHEXT` extensions on Windows), else
 * `null`. Never the current directory: a test must not run whatever happens to
 * sit in its cwd.
 */
export function resolveExecutable(command: string, options: ResolveOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  if (isAbsolute(command)) return isFile(command) ? command : null;
  const pathVar = options.path ?? process.env['PATH'] ?? process.env['Path'] ?? '';
  const exts =
    platform === 'win32' && extname(command) === ''
      ? (options.pathext ?? process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD').split(';').filter((e) => e !== '')
      : [''];
  for (const dir of pathVar.split(delimiter)) {
    if (dir.trim() === '') continue;
    for (const ext of exts) {
      const candidate = join(dir.replace(/^"|"$/g, ''), command + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

/** Whether `absPath` is Windows' own `bash.exe` — the WSL launcher in System32/SysWOW64. */
export function isWslLauncher(absPath: string, systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows'): boolean {
  const norm = (p: string): string => p.replace(/\//g, '\\').toLowerCase();
  const root = norm(systemRoot).replace(/\\+$/, '');
  const p = norm(absPath);
  return p === `${root}\\system32\\bash.exe` || p === `${root}\\syswow64\\bash.exe` || p === `${root}\\sysnative\\bash.exe`;
}
