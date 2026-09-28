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

import { appendFileSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Recursive delete that retries the Windows lock errors instead of throwing. */
export function rmDir(path: string): void {
  rmSync(path, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

/**
 * The directories a cleanup could not remove, one per line, for
 * {@link removeLeftovers} to remove at the start and the end of the next run
 * (`test/setup/tempLeftovers.ts`).
 *
 * `rmDir`'s retries last a second. A test that TIMED OUT leaves its scanner,
 * `git` or app process running — vitest abandons the test's promise and
 * kills nothing — and on Windows a directory that is a live process's working
 * directory, or holds a file it has open, cannot be removed. The cleanup gave
 * up, swallowed the error, and the directory stayed: measured on 2026-09-27,
 * the OS temp directory held 109 `guardian-gitleaks-*`, 40
 * `guardian-app-runner-*`, 23 `guardian-ci-init-*` and a tail of a dozen more
 * prefixes, all from the two days before, every leftover of a test that timed
 * out under load. By the end of the run those processes have exited, or the
 * next run finds them gone.
 */
export const LEFTOVERS_FILE = join(tmpdir(), 'dev-guardian-test-leftovers.txt');

/** {@link rmDir}; when something still holds the directory, it is listed for {@link removeLeftovers} instead. */
export function rmDirOrDefer(dir: string, list = LEFTOVERS_FILE): void {
  try {
    rmDir(dir);
  } catch {
    try {
      appendFileSync(list, `${dir}\n`);
    } catch {
      /* the directory stays; nothing more can be done from here */
    }
  }
}

/** Whether `inner` is `outer` or lies below it. */
function within(outer: string, inner: string): boolean {
  const rel = relative(outer, inner);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Only what a test made: a directory directly inside the OS temp directory —
 * the shape `mkdtempSync(join(tmpdir(), prefix))` gives every test directory —
 * or a `dev-guardian-test-*` directly in the home directory; and never one that
 * holds this checkout or the working directory. Anything else listed is dropped
 * unread — the list is a plain file anyone can write. "Anywhere inside the
 * temp directory" deleted this repository's own test/unit/testHelpers when the
 * checkout itself sat in /tmp, as a CI runner's or a container's does.
 */
export function isDisposable(dir: string): boolean {
  let real: string;
  try {
    real = realpathSync.native(dir);
  } catch {
    return false; // gone already
  }
  const here = realpathSync.native(dirname(fileURLToPath(import.meta.url)));
  if (within(real, here) || within(real, realpathSync.native(process.cwd()))) return false;
  if (dirname(real) === realpathSync.native(tmpdir())) return true;
  return dirname(real) === realpathSync.native(homedir()) && basename(real).startsWith('dev-guardian-test-');
}

/** Removes every listed directory it can; the ones still held stay listed for the next run. */
export function removeLeftovers(list = LEFTOVERS_FILE): void {
  let listed: string[];
  try {
    listed = readFileSync(list, 'utf8').split(/\r?\n/).filter((l) => l !== '');
  } catch {
    return; // no list: nothing was left behind
  }
  const still = [...new Set(listed)].filter((dir) => {
    if (!isDisposable(dir)) return false;
    try {
      rmDir(dir);
      return false;
    } catch {
      return true;
    }
  });
  try {
    if (still.length === 0) rmSync(list, { force: true });
    else writeFileSync(list, `${still.join('\n')}\n`);
  } catch {
    /* the next run tries again */
  }
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
 * individual test. Failures never throw: cleanup must never convert a
 * passing suite into a failing one. A directory a child process still holds
 * open is listed for the end of the run instead ({@link rmDirOrDefer}).
 */
export function cleanupTempDirs(): void {
  for (const dir of created.splice(0)) rmDirOrDefer(dir);
}
