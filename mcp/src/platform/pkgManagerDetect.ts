/**
 * Detect which system package managers are reachable.
 *
 * On Windows we probe `winget`, `scoop`, and `choco` in order — that order
 * is the design's preference, not alphabetic. On macOS/Linux we usually
 * defer to the install scripts which already do their own detection, but
 * `unixCandidates` is exposed for completeness.
 *
 * The probe uses `where` (Windows) / `which` (POSIX) with a short timeout
 * because some Windows boxes have stale PATH entries that block for seconds.
 */

import { execa } from 'execa';

export interface PkgManagerCandidate {
  name: string;
  available: boolean;
  command_path?: string;
}

export interface PkgManagerProbeDeps {
  /**
   * Resolve a binary on PATH. Returns its absolute path or null. Injectable
   * for testing — production uses `defaultResolver` which calls `execa`.
   */
  resolveBinary: (name: string) => Promise<string | null>;
}

export const WINDOWS_CANDIDATES_ORDER = ['winget', 'scoop', 'choco'] as const;
export const UNIX_CANDIDATES_ORDER = ['brew', 'apt-get', 'dnf', 'yum', 'pacman', 'zypper'] as const;

export async function windowsCandidates(
  deps: PkgManagerProbeDeps = defaultDeps(),
): Promise<PkgManagerCandidate[]> {
  return probeAll(WINDOWS_CANDIDATES_ORDER, deps);
}

export async function unixCandidates(
  deps: PkgManagerProbeDeps = defaultDeps(),
): Promise<PkgManagerCandidate[]> {
  return probeAll(UNIX_CANDIDATES_ORDER, deps);
}

/**
 * Returns the first reachable candidate from `windowsCandidates`, or null.
 */
export async function firstWindowsAvailable(
  deps: PkgManagerProbeDeps = defaultDeps(),
): Promise<PkgManagerCandidate | null> {
  for (const name of WINDOWS_CANDIDATES_ORDER) {
    const path = await deps.resolveBinary(name);
    if (path) {
      return { name, available: true, command_path: path };
    }
  }
  return null;
}

async function probeAll(
  order: readonly string[],
  deps: PkgManagerProbeDeps,
): Promise<PkgManagerCandidate[]> {
  const out: PkgManagerCandidate[] = [];
  for (const name of order) {
    const path = await deps.resolveBinary(name);
    const candidate: PkgManagerCandidate = { name, available: path !== null };
    if (path !== null) candidate.command_path = path;
    out.push(candidate);
  }
  return out;
}

function defaultDeps(): PkgManagerProbeDeps {
  return { resolveBinary };
}

export async function resolveBinary(name: string): Promise<string | null> {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const result = await execa(finder, [name], { timeout: 2_000, reject: false });
    if (result.exitCode !== 0) return null;
    const firstLine = result.stdout.split(/\r?\n/)[0]?.trim();
    return firstLine && firstLine.length > 0 ? firstLine : null;
  } catch {
    return null;
  }
}
