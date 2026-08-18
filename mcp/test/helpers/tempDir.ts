/**
 * Removing a temp directory in a way that survives Windows.
 *
 * `rmSync(p, { recursive: true, force: true })` is NOT enough on Windows, and
 * the difference is the whole reason this file exists: `force` suppresses
 * `ENOENT` and nothing else. A directory some child process still holds open
 * — a `git` index lock, a pack being written, `semgrep` mid-read, an
 * antivirus scanner — fails with `EBUSY` or `EPERM`, and `rmSync` throws.
 *
 * `maxRetries` + `retryDelay` make Node retry exactly those errors (`EBUSY`,
 * `EMFILE`, `ENFILE`, `ENOTEMPTY`, `EPERM`) rather than giving up on the first
 * attempt.
 *
 * ---- What this is, and what it is not ---------------------------------
 *
 * `fixprWorktree.test.ts`'s `afterAll` temp-directory assertion misfired three
 * times during full-suite runs and has never failed when that file is run on
 * its own. Real `git` processes spawning under load is the most plausible
 * cause consistent with that pattern, and this removes it.
 *
 * **It is hardening against a mechanism, not a reproduction.** The flake has
 * never been caught in the act here, so this is not proof of a fix. Stated
 * plainly because this repo has already "fixed" one flake against a mechanism
 * nobody had observed, and it came back — the second time it was diagnosed by
 * reproducing it 5 times in 333 runs under load before touching anything.
 * That standard was not met here, and pretending otherwise is how the first
 * one got shipped twice.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Recursive delete that retries the Windows lock errors instead of throwing. */
export function rmDir(path: string): void {
  rmSync(path, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

/**
 * Temp directories created by the current test file, for `cleanupTempDirs()`
 * to remove. Module state is per test FILE, not global: vitest gives each test
 * file its own module registry, so one file's `afterAll` can never delete a
 * concurrently-running sibling's directory. That isolation is what makes a
 * blanket `afterAll(cleanupTempDirs)` safe here where a prefix sweep of the OS
 * temp directory would not be.
 */
const created: string[] = [];

/**
 * `mkdtempSync(join(tmpdir(), prefix))`, but the directory is registered for
 * cleanup.
 *
 * ---- Why this exists -------------------------------------------------
 *
 * 28 of the 36 test files that create temp directories had no cleanup of any
 * kind. Measured on 2026-08-18, before this was added: **48,719** directories
 * had accumulated under the OS temp directory across one week of test runs —
 * 20,331 from `scanDast`, 9,949 from `surfaceTools` (which alone calls
 * `mkdtempSync` 36 times and removed none), 4,564 from spec discovery, and so
 * on down a tail of sixteen more prefixes.
 *
 * It was logged as minor housekeeping. It was not: a suite that leaks tens of
 * thousands of directories a week degrades the machine it runs on, and on
 * Windows it eventually slows every subsequent `mkdtemp` in the same
 * directory.
 *
 * Prefer this over a bare `mkdtempSync` in any test that does not have its own
 * deliberate teardown.
 */
export function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  created.push(dir);
  return dir;
}

/**
 * Removes every directory this file made through `makeTempDir`. Wire it up
 * once per test file:
 *
 *     afterAll(cleanupTempDirs);
 *
 * Runs at `afterAll` rather than `afterEach` deliberately — a directory
 * created in `beforeAll` and used by every test in the file must outlive each
 * individual test. Failures are swallowed: cleanup must never convert a
 * passing suite into a failing one, and a directory a child process still
 * holds open is the OS's problem, not the test's. `rmDir` already retries the
 * Windows lock errors before giving up.
 */
export function cleanupTempDirs(): void {
  for (const dir of created.splice(0)) {
    try {
      rmDir(dir);
    } catch {
      // Intentionally ignored — see the doc comment.
    }
  }
}
