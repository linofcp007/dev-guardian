/**
 * A synchronous spawn whose bound is the thing a slow run actually reports.
 *
 * ---- The defect this fixes (review 3.0, R7-I1) ----------------------------
 *
 * The CLI e2e files spawn the CLI with `spawnSync(…, { timeout: 15_000 })` or
 * `45_000`, a bound meant to turn a CLI that never exits into a failure that
 * names it. None of those bounds could ever be what a slow run reported:
 * vitest's default `testTimeout` is 10 s, and a synchronous body that returns
 * after 12 s is failed AFTER the fact with "Test timed out in 10000ms" — so a
 * spawn taking 10–15 s failed as an anonymous test timeout, and one past the
 * bound came back with `status: null`, which the tests then reported as
 * "expected null to be 0". Neither message names the command.
 *
 * So:
 *
 * - {@link spawnSyncCapped} throws {@link SpawnCapError} — naming the command,
 *   its arguments and the bound — when the bound kills the child, instead of
 *   handing back a `status: null` for an assertion to misreport;
 * - {@link timeoutAbove} is the per-file `testTimeout` a file with such
 *   spawns sets (`vi.setConfig`), comfortably above its cap, so a hung spawn
 *   reaches its own bound (and its own message) before vitest's.
 *
 * The bound stays what it is — a hang-breaker nothing asserts by reaching.
 */

import { spawnSync, type SpawnSyncOptionsWithStringEncoding, type SpawnSyncReturns } from 'node:child_process';

/** A capped synchronous spawn that outlived its bound and was killed. */
export class SpawnCapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpawnCapError';
  }
}

/**
 * The per-file `testTimeout` for tests whose synchronous spawns are capped at
 * `capMs`: twice the cap. One hung spawn reaches its own bound with room left
 * for the rest of the test (setup, the other, healthy spawns), so the
 * {@link SpawnCapError} is what the run reports. A test whose healthy spawns
 * together take longer than this is slow, not hung, and vitest says so.
 *
 * Not `testTimeoutAbove`: vitest's static test listing (`vitest list`) reads
 * any call whose name starts with `test` as a test, and reported 15 phantom
 * tests named after its argument (review 3.0, R7 round 2).
 */
export function timeoutAbove(capMs: number): number {
  return 2 * capMs;
}

/** `spawnSync` with a mandatory `timeout`; a child killed by it throws {@link SpawnCapError}. */
export function spawnSyncCapped(
  command: string,
  args: readonly string[],
  options: SpawnSyncOptionsWithStringEncoding & { timeout: number },
): SpawnSyncReturns<string> {
  const r = spawnSync(command, args, options);
  const code = (r.error as NodeJS.ErrnoException | undefined)?.code;
  if (code === 'ETIMEDOUT') {
    throw new SpawnCapError(
      `${[command, ...args].join(' ')} did not finish within ${String(options.timeout / 1000)} s and was killed. ` +
        'This bound is a hang-breaker: a healthy run is far below it.\n' +
        `stdout (tail): ${(r.stdout ?? '').slice(-2000)}\nstderr (tail): ${(r.stderr ?? '').slice(-2000)}`,
    );
  }
  return r;
}
