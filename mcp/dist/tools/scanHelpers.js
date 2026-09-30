/**
 * Helpers shared by the scan tools.
 *
 * - `scannerAvailable(name)` returns the resolved path or null. Cheap (1
 *   `where`/`which` call) and cached to avoid hammering during composite
 *   scans (e.g. security_scan_full) — see the cache's own comment for how
 *   long each answer lives.
 * - `ensureReportDir(projectPath, scanId, subdir)` builds and creates
 *   `.guardian/reports/<subdir>-<short-scan-id>/`. Tools point scanners at
 *   files under that directory.
 * - `readJsonSafe(path)` returns the file contents, or null when the file
 *   does not exist or could not be read. Treating "file missing" as null
 *   (rather than throwing) is what lets a scan-tool gracefully degrade
 *   when one scanner inside a composite run was skipped.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readSmallTextFile } from '../hooks/configFile.js';
import { resolveBinary } from '../platform/pkgManagerDetect.js';
import { makeProjectDir } from '../platform/projectFs.js';
import { ensureUserBinOnPath } from '../platform/userBin.js';
import { resetTrivyVersionCache } from '../runners/trivyRun.js';
/**
 * Cache of resolved scanner paths. `where`/`which` is cheap but
 * `audit_executive` triggers ~10 of these in sequence; caching trims ~200ms
 * off a typical executive audit and stops Windows from hammering its PATH
 * searcher.
 *
 * A found scanner is cached for the process lifetime. "Not installed" is
 * cached for `NEGATIVE_SCANNER_CACHE_TTL_MS` only — long enough that one
 * composite scan does not re-probe it per sub-tool, short enough that a
 * scanner installed meanwhile is seen. It used to be cached for the server's
 * whole life, so a re-scan straight after `install_toolchain` still said
 * `not_installed`; `install_toolchain` now also calls `resetScannerCache()`
 * when it finishes.
 */
export const NEGATIVE_SCANNER_CACHE_TTL_MS = 60_000;
const scannerPathCache = new Map();
export async function scannerAvailable(name) {
    const hit = scannerPathCache.get(name);
    if (hit && (hit.path !== null || Date.now() - hit.at < NEGATIVE_SCANNER_CACHE_TTL_MS)) {
        return hit.path;
    }
    // The per-user tools directory the pinned installers write to is on this
    // server's PATH before any lookup (`platform/userBin.ts`): a Trivy
    // install_toolchain put in %USERPROFILE%\.local\bin was reported missing.
    ensureUserBinOnPath();
    const resolved = await resolveBinary(name);
    scannerPathCache.set(name, { path: resolved, at: Date.now() });
    return resolved;
}
/** Forget every cached answer — after an install, and between test scenarios. Trivy's probed version too. */
export function resetScannerCache() {
    scannerPathCache.clear();
    resetTrivyVersionCache();
}
/**
 * `<project>/.guardian/reports/<prefix>-<short id>/`, created — or, when any
 * directory on that path is a link (a junction included) or not a directory,
 * a fresh directory under the OS temp directory instead.
 *
 * The scanners write their reports here and this server reads them back, so
 * the directory must be the project's own: a repository (an archive, a
 * checkout) can carry a `.guardian` or `.guardian/reports` link, and
 * `mkdirSync(…, { recursive: true })` created the report directory at its
 * end, outside the project, for every scanner to write into. Some names are
 * predictable (`surface-<tree hash>`), so the leaf is checked too.
 */
export function ensureReportDir(projectPath, scanId, prefix) {
    const short = scanId.slice(0, 8);
    const made = makeProjectDir(projectPath, join('.guardian', 'reports', `${prefix}-${short}`));
    if (made !== null)
        return made;
    process.stderr.write(`[dev-guardian] ${join(projectPath, '.guardian', 'reports')} is a link or not a directory; ` +
        `this scan's reports go to the temp directory instead\n`);
    return mkdtempSync(join(tmpdir(), `guardian-reports-${prefix}-`));
}
/**
 * The largest report read back. A V8 string holds about 512 MiB; a report
 * past that could not be parsed anyway.
 */
export const MAX_REPORT_BYTES = 512 * 1024 * 1024;
/**
 * A report file's text, or null when it does not exist, is not a regular
 * file (judged on a descriptor opened non-blocking: a FIFO or a device is
 * never waited on or read), is over {@link MAX_REPORT_BYTES}, or could not be
 * read.
 */
export function readJsonSafe(path) {
    return readSmallTextFile(path, MAX_REPORT_BYTES) ?? null;
}
//# sourceMappingURL=scanHelpers.js.map