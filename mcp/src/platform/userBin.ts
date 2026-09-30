/**
 * The per-user tools directory the pinned installers write to — `~/.local/bin`,
 * `%USERPROFILE%\.local\bin` on Windows — and making sure this server finds
 * what is installed there.
 *
 * `install_toolchain`'s pinned release installers (Syft, Trivy, gitleaks and
 * cosign: `runners/installCatalog.ts`) copy the binary there and leave PATH
 * alone. On Windows that directory is on no default PATH, and on macOS
 * neither is `~/.local/bin`, so a tool installed that way was reported
 * missing by the very next scan (review of 3.0, W2E). The server therefore
 * APPENDS the directory to its own PATH — at startup, and whenever a scanner
 * is looked up or probed — which every `where` / `which` lookup and every
 * spawn by bare name then sees:
 *
 *   - appended, never prepended: a tool anywhere on the user's own PATH still
 *     wins, and nothing there is shadowed;
 *   - only when the directory exists; an install that creates it is followed
 *     by another call;
 *   - the PATH the server started with is kept, to tell the user when a
 *     terminal of theirs will not find the tool the server now does.
 */

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

/** This process's PATH before anything here changed it. */
const STARTUP_PATH = process.env['PATH'] ?? '';

/** `<home>/.local/bin`, or null when there is no home to speak of. */
export function userBinDir(home?: string): string | null {
  let h = home;
  if (h === undefined) {
    try {
      h = homedir();
    } catch {
      return null;
    }
  }
  return h.trim() === '' ? null : join(h, '.local', 'bin');
}

function normalised(entry: string, win: boolean): string {
  const unquoted = entry.trim().replace(/^"(.*)"$/, '$1');
  const out = resolve(unquoted).replace(/[\\/]+$/, '');
  return win ? out.toLowerCase() : out;
}

/**
 * Whether `dir` is one of the entries of the PATH value `pathValue` —
 * compared resolved, without a trailing separator, and case-insensitively
 * (and unquoted) on Windows.
 */
export function pathHasDir(dir: string, pathValue: string, platform: NodeJS.Platform = process.platform): boolean {
  const win = platform === 'win32';
  const want = normalised(dir, win);
  return pathValue
    .split(win ? ';' : ':')
    .filter((e) => e.trim() !== '')
    .some((e) => normalised(e, win) === want);
}

export interface UserBinPath {
  /** The per-user tools directory; null when there is no home. */
  dir: string | null;
  /** This call appended it to the PATH. */
  added: boolean;
  /** It was on the PATH this server started with — a terminal of the user's finds its tools too. */
  onUserPath: boolean;
}

/**
 * Appends {@link userBinDir} to `env.PATH` (this process's, by default) when
 * the directory exists and is not there yet — see the module doc.
 * Idempotent, and cheap enough to call before every lookup.
 */
export function ensureUserBinOnPath(env: NodeJS.ProcessEnv = process.env, home?: string): UserBinPath {
  const dir = userBinDir(home);
  if (dir === null) return { dir: null, added: false, onUserPath: false };
  const onUserPath = pathHasDir(dir, STARTUP_PATH);
  const current = env['PATH'] ?? '';
  if (pathHasDir(dir, current) || !existsSync(dir)) return { dir, added: false, onUserPath };
  env['PATH'] = current === '' ? dir : `${current}${current.endsWith(delimiter) ? '' : delimiter}${dir}`;
  return { dir, added: true, onUserPath };
}

/**
 * Where an installer that writes `binary` into the per-user tools directory
 * puts it, and — when that directory was not on the PATH the server started
 * with — a note that the server finds it there but a terminal will not.
 */
export function userBinPlacement(binary: string, home?: string): { binary_path: string; path_note?: string } | null {
  const dir = userBinDir(home);
  if (dir === null) return null;
  const binaryPath = join(dir, binary);
  if (pathHasDir(dir, STARTUP_PATH)) return { binary_path: binaryPath };
  return {
    binary_path: binaryPath,
    path_note:
      `${dir} is not on your PATH: dev-guardian looks there itself, so its scans find ${binary}, ` +
      'but a terminal will not until you add that directory to PATH',
  };
}
