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
export const WINDOWS_CANDIDATES_ORDER = ['winget', 'scoop', 'choco'];
export const UNIX_CANDIDATES_ORDER = ['brew', 'apt-get', 'dnf', 'yum', 'pacman', 'zypper'];
export async function windowsCandidates(deps = defaultDeps()) {
    return probeAll(WINDOWS_CANDIDATES_ORDER, deps);
}
export async function unixCandidates(deps = defaultDeps()) {
    return probeAll(UNIX_CANDIDATES_ORDER, deps);
}
/**
 * Returns the first reachable candidate from `windowsCandidates`, or null.
 */
export async function firstWindowsAvailable(deps = defaultDeps()) {
    for (const name of WINDOWS_CANDIDATES_ORDER) {
        const path = await deps.resolveBinary(name);
        if (path) {
            return { name, available: true, command_path: path };
        }
    }
    return null;
}
async function probeAll(order, deps) {
    const out = [];
    for (const name of order) {
        const path = await deps.resolveBinary(name);
        const candidate = { name, available: path !== null };
        if (path !== null)
            candidate.command_path = path;
        out.push(candidate);
    }
    return out;
}
function defaultDeps() {
    return { resolveBinary };
}
/**
 * A bare name's absolute path on PATH, or null. In-process and never the
 * current directory — `where` searched it first, and timed out under load
 * (`platform/binaryPath.ts`). Async only to keep its callers' shape.
 */
export async function resolveBinary(name) {
    return Promise.resolve(findOnPath(name));
}
//# sourceMappingURL=pkgManagerDetect.js.map