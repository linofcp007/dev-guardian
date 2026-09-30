/**
 * Time-shape assertions that a loaded machine, or v8 coverage, cannot fail.
 *
 * ---- Why (review 3.0, R7-I2) ----------------------------------------------
 *
 * `npm run test:coverage` is the only run that enforces the coverage
 * thresholds, and it failed on timing alone: an absolute "under 1000 ms" or
 * "under 50 ms" bound measures the machine, and v8's instrumentation makes
 * every function several times slower. Widening the bound (a best-of-three,
 * a bigger ceiling) only moved the line.
 *
 * What those tests are FOR is the shape: the ReDoS and quadratic-scan defects
 * they guard against cost 16x the time for 4x the input, where a linear
 * implementation costs 4x. A ratio of two times measured in the same process,
 * moments apart, under the same instrumentation, keeps that distinction and
 * loses the machine — so linearity is asserted as {@link expectLinear}, and an
 * absolute bound, where one is worth keeping, runs only under
 * `GUARDIAN_PERF_STRICT=1` (a quiet machine; see `docs/env.md`).
 */

import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { expect } from 'vitest';

/** `GUARDIAN_PERF_STRICT=1`: the absolute time bounds run (a quiet machine). */
export const PERF_STRICT = process.env['GUARDIAN_PERF_STRICT'] === '1';

/**
 * A full garbage collection, run before each timed call so that none lands
 * inside it. A vitest worker carries the heap of every file it has run; in a
 * loaded full run (Docker, review 3.0 R7) a collection of that heap landing
 * in the larger input's timings — every one of them — read as 25x for 4x
 * the input on a shape that is 4.7x standalone. `--expose-gc` is not on the
 * workers' command line, so the flag is set here and `gc` taken from a new
 * context, where V8 installs it; a no-op if that ever stops working.
 */
const collectGarbage: () => void = (() => {
  try {
    setFlagsFromString('--expose-gc');
    const gc: unknown = runInNewContext('gc');
    if (typeof gc === 'function') return () => void gc();
  } catch {
    /* no gc: timings keep whatever collections land in them */
  }
  return () => {};
})();

/** The best of `runs` timings after one warm-up run: a quadratic shape is slow every time, a busy scheduler once. */
export function bestOf(runs: number, run: () => void): number {
  run();
  let best = Number.POSITIVE_INFINITY;
  for (let k = 0; k < runs; k += 1) {
    collectGarbage();
    const t0 = performance.now();
    run();
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

export interface LinearityOptions {
  /** How much larger the second input is. Default 4: linear ~4x, quadratic ~16x. */
  readonly factor?: number;
  /** The ratio the larger input must stay under. Default 12 (well under 16, well over 4). */
  readonly maxRatio?: number;
  /** Timings below this many ms are read as this many, so timer noise on tiny values cannot fail it. Default 1. */
  readonly floorMs?: number;
  /** Best of how many runs. Default 5. */
  readonly runs?: number;
}

/**
 * Asserts that `run(n * factor)` costs well under `maxRatio` times `run(n)` —
 * linear, not quadratic. Returns both timings for a caller that wants to
 * report them.
 */
export function expectLinear(
  label: string,
  run: (size: number) => void,
  n: number,
  opts: LinearityOptions = {},
): { small: number; large: number } {
  const factor = opts.factor ?? 4;
  const maxRatio = opts.maxRatio ?? 12;
  const floor = opts.floorMs ?? 1;
  const runs = opts.runs ?? 5;
  const small = bestOf(runs, () => run(n));
  const large = bestOf(runs, () => run(n * factor));
  expect(
    large,
    `${label}: ${String(factor)}x the input took ${large.toFixed(1)} ms against ${small.toFixed(1)} ms — ` +
      `a ratio over ${String(maxRatio)} is superlinear (linear is ~${String(factor)}x)`,
  ).toBeLessThan(maxRatio * Math.max(small, floor));
  return { small, large };
}
