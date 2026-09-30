/**
 * Detect which system package managers are reachable.
 *
 * On Windows we probe `winget`, `scoop`, and `choco` in order — that order
 * is the design's preference, not alphabetic. On macOS/Linux we usually
 * defer to the install scripts which already do their own detection, but
 * `unixCandidates` is exposed for completeness.
 *
 * The probe walks PATH in-process (`binaryPath.ts`): never the current
 * directory, never a spawn, never a timeout.
 */

import { findOnPath } from './binaryPath.js';

export interface PkgManagerCandidate {
  name: string;
  available: boolean;
  command_path?: string;
}

export interface PkgManagerProbeDeps {
  /**
   * Resolve a binary on PATH. Returns its absolute path or null. Injectable
   * for testing — production uses {@link resolveBinary}.
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

/**
 * A bare name's absolute path on PATH, or null. In-process and never the
 * current directory — `where` searched it first, and timed out under load
 * (`platform/binaryPath.ts`). Async only to keep its callers' shape.
 */
export async function resolveBinary(name: string): Promise<string | null> {
  return Promise.resolve(findOnPath(name));
}
