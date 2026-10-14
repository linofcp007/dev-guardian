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

import { createHash } from 'node:crypto';
import { lstatSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir, userInfo } from 'node:os';
import { dirname, join } from 'node:path';
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

const scannerPathCache = new Map<string, { path: string | null; at: number }>();

export async function scannerAvailable(name: string): Promise<string | null> {
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
export function resetScannerCache(): void {
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
export function ensureReportDir(projectPath: string, scanId: string, prefix: string): string {
  const short = scanId.slice(0, 8);
  const made = makeProjectDir(projectPath, join('.guardian', 'reports', `${prefix}-${short}`));
  if (made !== null) {
    // Every component of the path was just verified a real directory.
    pruneReports(dirname(made), prefix, made);
    return made;
  }
  process.stderr.write(
    `[dev-guardian] ${join(projectPath, '.guardian', 'reports')} is a link or not a directory; ` +
      `this scan's reports go to the temp directory instead\n`,
  );
  const fallback = mkdtempSync(join(tmpdir(), `${TEMP_REPORTS_PREFIX}${prefix}-`));
  try {
    // Just made by mkdtemp: nothing else is in it yet.
    writeFileSync(join(fallback, OWNER_MARKER), accountToken(), { flag: 'wx' });
  } catch {
    /* unmarked: never pruned, which is the safe side */
  }
  // Pruned like the project's (review 11): every such scan left one behind.
  pruneReports(tmpdir(), prefix, fallback, `${TEMP_REPORTS_PREFIX}${prefix}`, { markedOnly: true });
  return fallback;
}

/** The temp directory fallback's names: `guardian-reports-<kind>-<random>`. */
const TEMP_REPORTS_PREFIX = 'guardian-reports-';

/**
 * The file in a temp fallback directory that names the account that made it
 * ({@link accountToken}): in a temp directory several accounts share, only a
 * directory holding this account's is pruned.
 */
const OWNER_MARKER = '.dev-guardian-owner';

/** This account, as an owner marker holds it: a digest of its user name and home directory. */
function accountToken(): string {
  let user = '';
  try {
    user = userInfo().username;
  } catch {
    /* no user entry: the home directory alone */
  }
  return createHash('sha256').update(`dev-guardian-owner\n${user}\n${homedir()}`).digest('hex');
}

/** Whether `dir` holds this account's {@link OWNER_MARKER}. */
function markedByThisAccount(dir: string): boolean {
  return readSmallTextFile(join(dir, OWNER_MARKER), 256)?.trim() === accountToken();
}

/**
 * How many report directories of one kind `.guardian/reports/` keeps — the
 * newest, by modification time; `GUARDIAN_KEEP_REPORTS` overrides it (1 or
 * more). Nothing pruned them: a toy project held 29 after about 8 scans, a
 * mid-size one 4.3 MB after 3 CI runs, all of it untracked (review 8,
 * finding 14 and C5).
 */
export const DEFAULT_KEPT_REPORTS = 3;

/**
 * The report kinds pruned: scan output read back into the database, which
 * nothing reads again afterwards. A document a user asked for (`sbom-`,
 * `vex-`, `perf-`), DAST evidence (`dast-`, which a stored finding points
 * at) and a skill audit are never pruned.
 */
export const PRUNED_REPORT_PREFIXES: ReadonlySet<string> = new Set([
  'sast',
  'bugs',
  'compliance',
  'depsaudit',
  'deps',
  'iac',
  'secrets',
  'surface',
  'review',
  'containers',
  'quality',
  'wordpress',
  'init-secrets',
]);

function keptReports(): number {
  const n = Number(process.env['GUARDIAN_KEEP_REPORTS']);
  return Number.isInteger(n) && n >= 1 ? n : DEFAULT_KEPT_REPORTS;
}

/**
 * Removes the older `<prefix>-<id>` directories of `reportsDir` — a directory
 * `ensureReportDir` just verified link-free — keeping the newest
 * {@link keptReports}, `current` always among them. Only real directories
 * are touched (a `Dirent` is typed without following a link, and `rmSync`
 * removes a link inside one, never what it names). Best effort: a directory
 * a running scanner still holds is left for the next scan.
 *
 * `name`: the directories' name before `-<id>` — `prefix` in a project's
 * `.guardian/reports/`, `guardian-reports-<prefix>` in the temp directory
 * {@link ensureReportDir} falls back to, which nothing pruned (review 11).
 * On POSIX only this account's own directories are touched. `markedOnly`
 * (the temp directory): only one holding this account's
 * {@link OWNER_MARKER} — Windows reports no owner (every uid reads 0), and
 * the prune deleted a folder SYSTEM owned in a shared temp directory
 * (review 12).
 */
export function pruneReports(
  reportsDir: string,
  prefix: string,
  current: string,
  name: string = prefix,
  opts: { markedOnly?: boolean } = {},
): void {
  if (!PRUNED_REPORT_PREFIXES.has(prefix)) return;
  let entries;
  try {
    entries = readdirSync(reportsDir, { withFileTypes: true });
  } catch {
    return;
  }
  const uid = process.getuid?.();
  const others: Array<{ path: string; mtime: number }> = [];
  for (const e of entries) {
    if (!e.isDirectory() || !e.name.startsWith(`${name}-`)) continue;
    // The id after the prefix: `deps-<id>` is not `depsaudit-<id>`'s, nor
    // `init-secrets-<id>` a `secrets-` one (a prefix is never a hyphenated
    // form of another's id: ids are hex, a tree hash or mkdtemp's suffix).
    if (!/^[0-9A-Za-z]{1,64}$/.test(e.name.slice(name.length + 1))) continue;
    const path = join(reportsDir, e.name);
    if (path === current) continue;
    try {
      const st = lstatSync(path);
      if (!st.isDirectory() || st.isSymbolicLink() || (uid !== undefined && st.uid !== uid)) continue;
      if (opts.markedOnly !== true || markedByThisAccount(path)) {
        others.push({ path, mtime: st.mtimeMs });
      }
    } catch {
      /* gone meanwhile */
    }
  }
  others.sort((a, b) => b.mtime - a.mtime);
  // `current` is one of the kept.
  for (const d of others.slice(Math.max(0, keptReports() - 1))) {
    try {
      rmSync(d.path, { recursive: true, force: true });
    } catch {
      /* held by a running scanner: the next scan prunes it */
    }
  }
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
export function readJsonSafe(path: string): string | null {
  return readSmallTextFile(path, MAX_REPORT_BYTES) ?? null;
}
