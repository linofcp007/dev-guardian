/**
 * Helpers shared by the scan tools.
 *
 * - `scannerAvailable(name)` returns the resolved path or null. Cheap (1
 *   `where`/`which` call) and cached for the life of one tool invocation
 *   to avoid hammering during composite scans (e.g. security_scan_full).
 * - `ensureReportDir(projectPath, scanId, subdir)` builds and creates
 *   `.guardian/reports/<subdir>-<short-scan-id>/`. Tools point scanners at
 *   files under that directory.
 * - `readJsonSafe(path)` returns the file contents, or null when the file
 *   does not exist or could not be read. Treating "file missing" as null
 *   (rather than throwing) is what lets a scan-tool gracefully degrade
 *   when one scanner inside a composite run was skipped.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { resolveBinary } from '../platform/pkgManagerDetect.js';
/**
 * Process-lifetime cache of resolved scanner paths. `where`/`which` is
 * cheap but `audit_executive` triggers ~10 of these in sequence; caching
 * trims ~200ms off a typical executive audit and stops Windows from
 * hammering its PATH searcher.
 *
 * Negative results are also cached so a missing scanner doesn't get
 * re-probed by every sub-tool. Call `resetScannerCache()` from tests.
 */
const scannerPathCache = new Map();
export async function scannerAvailable(name) {
    if (scannerPathCache.has(name)) {
        return scannerPathCache.get(name) ?? null;
    }
    const resolved = await resolveBinary(name);
    scannerPathCache.set(name, resolved);
    return resolved;
}
/** Test-only: clear the cache between scenarios. */
export function resetScannerCache() {
    scannerPathCache.clear();
}
export function ensureReportDir(projectPath, scanId, prefix) {
    const short = scanId.slice(0, 8);
    const dir = join(projectPath, '.guardian', 'reports', `${prefix}-${short}`);
    if (!existsSync(dir))
        mkdirSync(dir, { recursive: true });
    return dir;
}
export function readJsonSafe(path) {
    try {
        if (!existsSync(path))
            return null;
        return readFileSync(path, 'utf8');
    }
    catch {
        return null;
    }
}
/**
 * Find the newest direct child directory of `parent` whose name starts with
 * `prefix` and was created at or after `sinceMs`. Used by `security_scan_full`
 * to locate the timestamped output of `scripts/scan/full-security-scan.sh`
 * without modifying the script.
 */
export function findNewestDir(parent, prefix, sinceMs) {
    if (!existsSync(parent))
        return null;
    let best = null;
    for (const entry of readdirSync(parent)) {
        if (!entry.startsWith(prefix))
            continue;
        const abs = join(parent, entry);
        try {
            const s = statSync(abs);
            if (!s.isDirectory())
                continue;
            if (s.mtimeMs < sinceMs)
                continue;
            if (!best || s.mtimeMs > best.mtimeMs)
                best = { path: abs, mtimeMs: s.mtimeMs };
        }
        catch {
            /* skip transient */
        }
    }
    return best?.path ?? null;
}
//# sourceMappingURL=scanHelpers.js.map