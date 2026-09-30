/**
 * Where a bare command name resolves: looked up in-process, on PATH, and
 * never in the working directory (review of 3.0, W2E).
 *
 * `resolveBinary` used to ask `where` (Windows) / `which` with a 2 s
 * timeout. `where` searches the CURRENT DIRECTORY before PATH, and Claude
 * Code starts a project's MCP server in the project root: a repository that
 * carried `nuclei.bat` had it reported as the installed scanner, and spawned.
 * The spawns themselves were no better. Measured on Windows 11 with
 * `NoDefaultCurrentDirectoryInExePath` unset, cwd = a directory holding
 * planted files: `spawnSync('dgplanted')` ran `dgplanted.exe` from it, and
 * an `execa` of `trivy` ran a planted `trivy.cmd` over the real `trivy.exe` on
 * PATH (libuv's search and `cmd.exe`'s both start with the current
 * directory). The 2 s timeout was a flake of its own under load.
 *
 * So:
 *
 *   - {@link findOnPath} walks PATH itself: absolute entries only — an empty
 *     entry, `.`, any relative or drive-relative entry is skipped, since each
 *     means "the current directory" to somebody — and, on Windows, a network
 *     entry (`\\host\share`) too: a dead share blocks a lookup for minutes,
 *     and this runs on the event loop. On Windows each entry is tried with
 *     each PATHEXT extension, as `where` does; an App Execution Alias
 *     (`WindowsApps\winget.exe`, which `stat` refuses with EACCES) counts.
 *     On POSIX a candidate must be a regular file with an execute bit.
 *   - the process runner spawns the path this returns, never the bare name
 *     ({@link commandFor});
 *   - {@link hardenCommandSearch}, called once at startup by the server and
 *     the CLI, is the second layer for every spawn that still passes a bare
 *     name (git's, owned elsewhere, among them): on Windows it sets
 *     `NoDefaultCurrentDirectoryInExePath`, which libuv and `cmd.exe` both
 *     honour (measured: set at runtime, the two planted files above stop
 *     running), and on every platform it drops PATH entries that are empty or
 *     relative — an empty entry is the current directory to `execvp`.
 */

import { accessSync, constants, lstatSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';

const DEFAULT_PATHEXT = '.COM;.EXE;.BAT;.CMD';

/**
 * An environment's value for `name` — case-insensitively on Windows, where
 * `Path` is the usual spelling. With two spellings (a merged `{...process.env,
 * PATH}`), the one Node hands the child: it sorts the keys and keeps the first.
 */
function envValue(env: NodeJS.ProcessEnv, name: string, platform: NodeJS.Platform): string | undefined {
  if (platform !== 'win32') return env[name];
  const key = Object.keys(env)
    .filter((k) => k.toUpperCase() === name)
    .sort()[0];
  return key === undefined ? undefined : env[key];
}

/** Whether one PATH entry may be searched (see the module doc). */
function searchable(entry: string, platform: NodeJS.Platform): boolean {
  // A drive letter, a colon and a separator: `C:\x`. Not `C:x` (drive-relative), not `\\host\share`, not `\\?\…`.
  return platform === 'win32' ? /^[A-Za-z]:[\\/]/.test(entry) : entry.startsWith('/');
}

/** The directories a bare name is looked up in, in PATH order. */
export function searchDirs(pathText: string, platform: NodeJS.Platform = process.platform): string[] {
  const out: string[] = [];
  for (const raw of pathText.split(platform === 'win32' ? ';' : ':')) {
    const entry = platform === 'win32' ? raw.trim().replace(/^"(.*)"$/, '$1') : raw;
    if (entry !== '' && searchable(entry, platform)) out.push(entry);
  }
  return out;
}

/** The extensions tried on Windows: none when the name already carries one of PATHEXT's. */
function extensionsFor(name: string, env: NodeJS.ProcessEnv): string[] {
  const pathext = (envValue(env, 'PATHEXT', 'win32') ?? DEFAULT_PATHEXT)
    .split(';')
    .map((e) => e.trim().toLowerCase())
    .filter((e) => /^\.[a-z0-9]{1,8}$/.test(e));
  const exts = pathext.length > 0 ? pathext : DEFAULT_PATHEXT.toLowerCase().split(';');
  return exts.includes(extname(name).toLowerCase()) ? [''] : exts;
}

/** Whether `file` is something a spawn would run. */
function runnable(file: string, platform: NodeJS.Platform): boolean {
  try {
    const st = statSync(file);
    if (!st.isFile()) return false;
    if (platform === 'win32') return true;
    accessSync(file, constants.X_OK);
    return true;
  } catch (err) {
    // An App Execution Alias: `stat` refuses it (EACCES) while `lstat` sees the reparse point (measured).
    if (platform === 'win32' && (err as NodeJS.ErrnoException).code === 'EACCES') {
      try {
        return lstatSync(file).isSymbolicLink();
      } catch {
        return false;
      }
    }
    return false;
  }
}

/** A command name with no directory in it — what a spawn would search for. */
export function isBareName(name: string, platform: NodeJS.Platform = process.platform): boolean {
  return name !== '' && name !== '.' && name !== '..' && !/[\\/]/.test(name) && !(platform === 'win32' && name.includes(':'));
}

/**
 * Names found, by PATH, PATHEXT and name — re-checked with one `stat` on
 * every hit. A miss is never cached: a tool installed meanwhile is found.
 * Measured on Windows 11 with 60 PATH entries × 16 PATHEXT extensions: a
 * miss cost about 110 ms of `stat`s, a found scanner 70 ms, a cache hit one `stat`.
 */
const found = new Map<string, string>();
const FOUND_CACHE_MAX = 256;

/**
 * The absolute path a bare command name resolves to on `env`'s PATH, or null
 * when it is on none of its searchable entries. A name that is not bare — it
 * holds a separator or, on Windows, a drive colon — is not looked up (null).
 */
export function findOnPath(name: string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string | null {
  if (!isBareName(name, platform)) return null;
  const cacheKey = `${platform}\0${envValue(env, 'PATH', platform) ?? ''}\0${envValue(env, 'PATHEXT', platform) ?? ''}\0${name}`;
  const cached = found.get(cacheKey);
  if (cached !== undefined && runnable(cached, platform)) return cached;
  const exts = platform === 'win32' ? extensionsFor(name, env) : [''];
  for (const dir of searchDirs(envValue(env, 'PATH', platform) ?? '', platform)) {
    for (const ext of exts) {
      const candidate = join(dir, `${name}${ext}`);
      if (runnable(candidate, platform)) {
        if (found.size >= FOUND_CACHE_MAX) found.clear();
        found.set(cacheKey, candidate);
        return candidate;
      }
    }
  }
  return null;
}

/**
 * What to hand a spawn for `command`: the absolute path a bare name resolves
 * to, else `command` unchanged — a path is spawned as given, and a bare name
 * found nowhere fails to spawn (ENOENT) as it always did, with
 * {@link hardenCommandSearch} keeping the current directory out of that last
 * search.
 */
export function commandFor(command: string, env: NodeJS.ProcessEnv = process.env): string {
  return findOnPath(command, env) ?? command;
}

/**
 * The process-wide layer (see the module doc). Idempotent; returns the
 * non-empty PATH entries it dropped, for the caller to log (an empty one —
 * a trailing `;` is common — is dropped silently).
 */
export function hardenCommandSearch(platform: NodeJS.Platform = process.platform): string[] {
  if (platform === 'win32') process.env['NoDefaultCurrentDirectoryInExePath'] = '1';
  const key = platform === 'win32' ? (Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH') : 'PATH';
  const current = process.env[key];
  if (current === undefined) return [];
  const sepChar = platform === 'win32' ? ';' : ':';
  const kept: string[] = [];
  const dropped: string[] = [];
  let changed = false;
  for (const raw of current.split(sepChar)) {
    const entry = platform === 'win32' ? raw.trim().replace(/^"(.*)"$/, '$1') : raw;
    // A network entry is kept here — it is absolute, and the user put it there; only the in-process lookup skips it.
    if (entry !== '' && (searchable(entry, platform) || (platform === 'win32' && /^\\\\[^\\?.]/.test(entry)))) {
      kept.push(raw);
      continue;
    }
    changed = true;
    if (entry !== '') dropped.push(raw);
  }
  if (changed) process.env[key] = kept.join(sepChar);
  return dropped;
}
