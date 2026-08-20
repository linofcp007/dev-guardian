/**
 * Gives every vitest worker its own Semgrep settings file, so that concurrent
 * Semgrep invocations stop racing each other on one global file.
 *
 * ---- The defect this fixes ------------------------------------------------
 *
 * Semgrep keeps a single settings file per USER — `~/.semgrep/settings.yml`
 * (`%USERPROFILE%\.semgrep\settings.yml` on Windows), overridable with
 * `SEMGREP_SETTINGS_FILE`. Every invocation reads it and then WRITES it back:
 * `Settings.__attrs_post_init__` calls `save()` unconditionally, "in case we
 * retrieved default contents".
 *
 * `save()` is careful — it writes to a `mkstemp` file and then `os.replace`s
 * it over the target, with a comment in Semgrep's own source saying this
 * exists because otherwise "concurrent instances of the program [would] be
 * writing to the file at the same time and get race conditions", and it
 * catches `PermissionError`.
 *
 * The READ path is not careful. `get_default_contents` does an `os.access`
 * check and then `self.path.open()`, with no `try`. On Windows, another
 * process's `os.replace` landing in that window makes the `open` fail with
 * `PermissionError: [Errno 13]`, which nothing catches — so Semgrep dies with
 * a Python traceback and a non-zero exit, and the test that invoked it
 * reports `Command failed: semgrep --config …`. That reads as a broken rule
 * pack or a broken scanner. It is neither.
 *
 * Measured directly, firing N Semgrep processes simultaneously at a trivial
 * target (see the task report): **3 failures in 288 invocations at 24-way
 * concurrency, every one of them `PermissionError: [Errno 13] … settings.yml`,
 * and 0 in 288 with this isolation in place.** ~1% per invocation does not
 * sound like much until you count how many Semgrep calls a full run makes,
 * and that a single failed call takes its whole test file down with it. It is
 * the mechanism behind "42 test files failed / 86 passed" during three
 * concurrent agent runs, and behind those same files passing instantly when
 * run alone.
 *
 * Note what this is NOT: it is not a CPU-contention problem, and capping
 * vitest's worker count does not fix it. Fewer workers means a lower
 * collision RATE — the same defect with a longer fuse — while a settings file
 * nobody else is touching removes the collision entirely.
 *
 * ---- Why this is safe -----------------------------------------------------
 *
 * The file holds three keys: `anonymous_user_id`, `has_shown_metrics_
 * notification` and `api_token`. This project never logs Semgrep in (the real
 * file on the development machine carries no token, only an anonymous id), so
 * nothing about how Semgrep resolves rules or reports findings changes.
 *
 * The file is SEEDED rather than left for Semgrep to create, and
 * `has_shown_metrics_notification` is seeded `true` deliberately: a fresh
 * settings file makes Semgrep print its "METRICS: Using configs from the
 * Registry…" banner to stderr on the first registry-backed run
 * (`notifications.possibly_notify_user`), which would be new output on a
 * stream this project's own "pristine output" tests care about. `true` is the
 * state of any machine that has already run Semgrep once, which is every
 * machine this suite runs on after its first use.
 *
 * Only the TEST environment is redirected. `mcp/src` deliberately does not do
 * this: overriding a user's Semgrep settings location from inside a scanner
 * would discard their login state, which is theirs to manage.
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { threadId } from 'node:worker_threads';
import { afterAll } from 'vitest';

/** `pid` alone is not enough (one vitest process runs many workers) and
 *  `threadId` alone is not enough (concurrent runs, e.g. two agents, repeat
 *  low thread ids). Together they are unique across both, and BOUNDED — one
 *  directory per worker, reused for every test file that worker runs, rather
 *  than one per file. This suite has leaked tens of thousands of temp
 *  directories before; see `test/helpers/tempDir.ts`. */
const settingsDir = join(tmpdir(), 'guardian-semgrep-settings', `${process.pid}-${threadId}`);

mkdirSync(settingsDir, { recursive: true });
const settingsFile = join(settingsDir, 'settings.yml');
writeFileSync(
  settingsFile,
  'has_shown_metrics_notification: true\n' +
    `anonymous_user_id: 00000000-0000-4000-8000-${String(process.pid).padStart(12, '0').slice(-12)}\n`,
);
process.env['SEMGREP_SETTINGS_FILE'] = settingsFile;

afterAll(() => {
  try {
    // `maxRetries`/`retryDelay` for the same Windows lock reasons
    // `test/helpers/tempDir.ts` documents at length.
    rmSync(settingsDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch {
    // Cleanup must never turn a passing suite red. A directory a Semgrep
    // subprocess still holds open is the OS's problem, not this file's.
  }
});
