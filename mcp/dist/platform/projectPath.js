/**
 * Resolve and validate a project_path argument.
 *
 * Rules (in order):
 *  1. Missing or empty → resolve to `process.cwd()`.
 *  2. Resolved path must exist and be a directory.
 *  3. Resolved path must not be a filesystem root or the user-home root —
 *     mass scans starting there are almost always a mistake and can take
 *     hours.
 *
 * Callers receive `ResolvedProjectPath`, which always carries the resolved
 * absolute path and an optional warning the caller surfaces in tool output
 * (currently unused; reserved for the `.guardian/` writability fallback
 * which lives in `storage/db.ts`).
 */
import { existsSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { parse, resolve } from 'node:path';
export class InvalidProjectPathError extends Error {
    reason;
    path;
    constructor(reason, path) {
        super(`Invalid project_path (${reason}): ${path}`);
        this.reason = reason;
        this.path = path;
        this.name = 'InvalidProjectPathError';
    }
}
export function resolveProjectPath(input) {
    const candidate = resolve(input && input.length > 0 ? input : process.cwd());
    if (!existsSync(candidate)) {
        throw new InvalidProjectPathError('not_found', candidate);
    }
    if (!statSync(candidate).isDirectory()) {
        throw new InvalidProjectPathError('not_a_directory', candidate);
    }
    if (isRootOrHome(candidate)) {
        throw new InvalidProjectPathError('root_or_home', candidate);
    }
    return { path: candidate };
}
function isRootOrHome(p) {
    // Filesystem root (e.g. "C:\\" or "/")
    if (parse(p).root === p)
        return true;
    // User home root (e.g. "/home/foo" or "C:\\Users\\foo")
    const home = resolve(homedir());
    if (p === home)
        return true;
    return false;
}
//# sourceMappingURL=projectPath.js.map