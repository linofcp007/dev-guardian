/**
 * vitest `globalSetup`: keeps every Semgrep the suite starts out of the home
 * directory, and checks afterwards that none of them wrote there.
 *
 * ---- The defect this fixes (review 3.0, W2D) ------------------------------
 *
 * Semgrep writes three files under the user's home on every run, whatever it
 * is asked to do: `~/.semgrep/settings.yml` (already isolated per worker by
 * `semgrepSettings.ts`), `~/.semgrep/semgrep.log` (its log, truncated by each
 * run) and `~/.cache/semgrep_version` (its version check, which `--version`
 * performs too). The suite's own Semgrep runs — the rule-pack tests, the scan
 * tools, the CLI e2e — were rewriting the developer's real log and version
 * cache: seen at 18:03 on 2026-09-29, from a test run.
 *
 * Semgrep reads `SEMGREP_LOG_FILE`, `SEMGREP_VERSION_CACHE_PATH` and
 * `SEMGREP_ENABLE_VERSION_CHECK` (semgrep/env.py, semgrep/commands/scan.py).
 * They are set here, in the main process, before any worker starts — so every
 * worker, and every process a test spawns with the inherited environment,
 * points Semgrep at the run's own directory. `semgrepSettings.ts` then gives
 * each worker its own copy (a shared log would be truncated by every run).
 *
 * Only the TEST environment is redirected; `mcp/src` leaves the user's
 * Semgrep files where the user keeps them (see `semgrepSettings.ts`).
 *
 * ---- The guard ---------------------------------------------------------
 *
 * The run's teardown compares those files in the home directory the run
 * inherited with what they were before it started. A change is printed, with
 * the paths; with `GUARDIAN_REQUIRE_ISOLATED_HOME=1` it fails the run. It is
 * not a failure by default because it cannot tell who wrote: a Semgrep the
 * developer (or the dev-guardian MCP server of an open session) runs during
 * the suite writes the same files. In a container, or on a machine nothing
 * else is using, set the variable and it is exact.
 *
 * `GUARDIAN_TEST_RUN_DIR` (a test-internal variable) is the run's own
 * directory, removed at teardown: the per-worker Semgrep directories live in
 * it, so a worker whose last test file was skipped — whose `afterAll` hooks
 * therefore never ran — leaves nothing behind. 63 such directories were found
 * in the real temp directory when this was written.
 */

import { mkdtempSync, readdirSync, rmdirSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmDirOrDefer } from '../helpers/tempDir.js';

/** The Semgrep files under a home directory that no test may write. */
export function semgrepHomeFiles(home: string): string[] {
  return [
    join(home, '.semgrep', 'semgrep.log'),
    join(home, '.semgrep', 'settings.yml'),
    join(home, '.cache', 'semgrep_version'),
  ];
}

/** `path -> mtime` (or `absent`) for each file. */
export function snapshot(paths: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const p of paths) {
    try {
      const s = statSync(p);
      out.set(p, `${String(s.mtimeMs)}:${String(s.size)}`);
    } catch {
      out.set(p, 'absent');
    }
  }
  return out;
}

/** The paths whose snapshot differs. */
export function touched(before: ReadonlyMap<string, string>, after: ReadonlyMap<string, string>): string[] {
  return [...before.keys()].filter((p) => before.get(p) !== after.get(p));
}

/**
 * Removes `<tmp>/guardian-semgrep-settings/<pid>-<thread>` directories whose
 * process is gone — what the previous layout left when a worker's last file
 * was skipped — and the parent once it is empty. A directory of a process
 * still running (another checkout's suite, mid-run) is left alone.
 */
export function sweepLegacySettingsDirs(root = join(tmpdir(), 'guardian-semgrep-settings')): void {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return;
  }
  for (const name of entries) {
    const pid = Number(/^(\d+)-\d+$/.exec(name)?.[1]);
    if (!Number.isInteger(pid) || pid <= 0) continue;
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch (e) {
      alive = (e as NodeJS.ErrnoException).code === 'EPERM';
    }
    if (!alive) rmDirOrDefer(join(root, name));
  }
  try {
    rmdirSync(root);
  } catch {
    /* not empty: a live run still uses it */
  }
}

export default function setup(): () => void {
  sweepLegacySettingsDirs();
  const runDir = mkdtempSync(join(tmpdir(), 'guardian-test-run-'));
  process.env['GUARDIAN_TEST_RUN_DIR'] = runDir;
  // Workers refine these per worker (`semgrepSettings.ts`); these are for the
  // main process and anything started before a worker's setup file ran.
  process.env['SEMGREP_LOG_FILE'] = join(runDir, 'semgrep.log');
  process.env['SEMGREP_VERSION_CACHE_PATH'] = join(runDir, 'semgrep_version');
  process.env['SEMGREP_ENABLE_VERSION_CHECK'] = '0';

  const watched = semgrepHomeFiles(homedir());
  const before = snapshot(watched);
  return () => {
    rmDirOrDefer(runDir);
    const changed = touched(before, snapshot(watched));
    if (changed.length === 0) return;
    const message =
      `A Semgrep wrote into the home directory during this run: ${changed.join(', ')}. The suite points ` +
      'SEMGREP_LOG_FILE / SEMGREP_VERSION_CACHE_PATH / SEMGREP_SETTINGS_FILE at its own directory; a test that ' +
      'spawns Semgrep with an environment that drops them writes here instead. (Something outside the suite — ' +
      'a Semgrep you ran, or an open session\'s MCP server — writes the same files.)';
    if (process.env['GUARDIAN_REQUIRE_ISOLATED_HOME'] === '1') throw new Error(message);
    process.stderr.write(`\n[dev-guardian test setup] warning: ${message}\n`);
  };
}
