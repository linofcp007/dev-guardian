/**
 * Time-shape assertions that catch the defect they were written for, measured
 * so that a loaded machine or v8 coverage moves them as little as it can —
 * not "not at all": at 100% CPU a single comparison still drifts, and every
 * bound here was set against its probe's worst reading under load (the
 * distribution is in the review 3.0 R7 round-2 commit), not an idle one.
 *
 * ---- Why (review 3.0, R7) ---------------------------------------------------
 *
 * An absolute "under 1000 ms" bound measures the machine: `npm run
 * test:coverage` — the only run that enforces the coverage thresholds — failed
 * on timing alone. What those tests are for is a SHAPE, and the defects they
 * guard come in two kinds, which need two different assertions:
 *
 * 1. Superlinear in the input: a regex restarted at every position, a search
 *    restarted after every occurrence. {@link expectLinear} compares the cost
 *    of `factor` times the input with the cost of the input: linear reads
 *    ~factor, quadratic ~factor², and the bound is the geometric middle,
 *    factor^1.5 (22.6 for the default 8x), so either side has a 2.8x margin.
 *    At 4x (bound 12) a defect scaling n^1.8 read 8.8 and passed.
 *
 * 2. Bounded by a cap: the input is cut into 16 KB windows or statements, so a
 *    rule that is quadratic INSIDE one costs a large constant per window and
 *    the total stays linear in the input — every ratio across windows reads
 *    linear, whatever a window costs (a JWT finder at ~90 ms a window read
 *    4.09 for 4x and passed). Such code gets two assertions: a ratio of two
 *    sizes that both fit in one window ({@link expectLinear} below the cap),
 *    and {@link expectNearReference}: the cost at a full size is at most k
 *    times the cost of a REFERENCE run — the same function, the same size, an
 *    input with nothing pathological in it — measured in the same process,
 *    interleaved. The reference scales with the machine and the
 *    instrumentation, so the ceiling does too, where milliseconds do not.
 *
 * ---- Measuring (review 3.0, R7-I2 round 2) ----------------------------------
 *
 * What a loaded machine does to a timing is add to it — never subtract — and
 * in bursts: at 24 busy processes on 24 hardware threads, one side of a
 * comparison ran seventeen times slower than idle across its 50 ms samples
 * and the other side, sampled in between, three times (a synthetic n^1.25
 * read 24.7 against a bound of 22.6). Long samples average a burst in; they
 * do not remove it. So:
 *
 * - The two sides run in CHUNKS, alternated — a chunk of one, a chunk of the
 *   other — and every chunk lasts about the same time, {@link MIN_CHUNK_MS}
 *   or one call of the slower side, whichever is longer (up to
 *   {@link MAX_CHUNK_MS} for the cheaper side); a cheaper call is repeated
 *   inside its chunk. Equal durations give both sides the same odds of being
 *   preempted; alternation gives them the same moments.
 * - A side's cost is its CHEAPEST chunk, per call: the one nothing landed in.
 *   Every side runs at least {@link CHUNKS} chunks — at least 120 ms in all —
 *   or, for slow calls, 6 once the comparison has run {@link LONG_MS}, and 3
 *   once it has run {@link SLOW_MS}. Chunks of long calls average a burst
 *   in; a 5 ms chunk is either clean or thrown away.
 * - A comparison that reads over its bound is measured again, up to three
 *   times in all, and the cheapest reading is the verdict — the way `timeit`
 *   keeps the minimum of its repeats. A defect reads over the bound every
 *   time, idle or loaded (the positive controls in
 *   test/unit/testHelpers/timing.test.ts, and each defect reintroduced); a
 *   loaded machine does so in bursts. A comparison that took over
 *   {@link SLOW_MS} is not repeated: its calls take seconds — a defect's, as
 *   a rule — and it has to fail inside its test's timeout. Every reading is
 *   logged (below).
 * - A full GC runs before each comparison, so the worker's accumulated heap
 *   is not collected inside one.
 * - Absolute bounds, where one is still worth having, run only with
 *   `GUARDIAN_PERF_STRICT=1` (a quiet machine; see docs/env.md).
 *
 * Measured, 24 busy processes on 24 hardware threads, ~20 comparisons a shape:
 * a linear shape read 3.7-26.3 with the paired 50 ms samples this replaced,
 * and 7.8-8.6 this way; the n^1.25 control 3.8-24.7 against 12.8-14.2. In the
 * suite, 20 runs of the timing files at that load: 1 621 comparisons of the
 * 81 probes of current code, one over its bound (and measured again), no
 * ratio verdict over 14.8 against 22.6 — while every defect reintroduced
 * failed its assertion.
 */

import { appendFileSync } from 'node:fs';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { expect } from 'vitest';

/**
 * `GUARDIAN_TEST_TIMING_LOG=<file>`: every measurement is appended to that
 * file as a JSON line — how the distributions and the defect readings in the
 * review were taken. Unset, nothing is written.
 */
function record(entry: Record<string, unknown>): void {
  const file = process.env['GUARDIAN_TEST_TIMING_LOG'];
  if (file === undefined || file === '') return;
  try {
    appendFileSync(file, `${JSON.stringify(entry)}\n`);
  } catch {
    /* a log that cannot be written changes no verdict */
  }
}

/** `GUARDIAN_PERF_STRICT=1`: the absolute time bounds run (a quiet machine). */
export const PERF_STRICT = process.env['GUARDIAN_PERF_STRICT'] === '1';

/** The shortest a timed chunk may be; a cheaper call is repeated inside it. */
export const MIN_CHUNK_MS = 5;

/** Chunks of each side a comparison takes, unless its calls are slow (see {@link LONG_MS}). */
export const CHUNKS = 24;

/** The longest the cheaper side's chunk is made, to match a slow call of the other. */
export const MAX_CHUNK_MS = 1000;

/** Past this much time a comparison of slow calls stops at 6 chunks a side. */
export const LONG_MS = 1000;

/** Past this much time a comparison stops at 3 chunks a side, and is not repeated. */
export const SLOW_MS = 10_000;

/** How many times a comparison that reads over its bound is measured in all. */
const ATTEMPTS = 3;

/**
 * A full garbage collection. `--expose-gc` is not on the workers' command
 * line, so the flag is set here and `gc` taken from a new context, where V8
 * installs it; a no-op if that ever stops working.
 */
const collectGarbage: () => void = (() => {
  try {
    setFlagsFromString('--expose-gc');
    const gc: unknown = runInNewContext('gc');
    if (typeof gc === 'function') return () => void gc();
  } catch {
    /* no gc: chunks keep whatever collections land in them */
  }
  return () => {};
})();

/** The time of `calls` calls of `run`, per call, ms. */
function chunk(run: () => void, calls: number): number {
  const t0 = performance.now();
  for (let k = 0; k < calls; k += 1) run();
  return (performance.now() - t0) / calls;
}

/**
 * One call's cost, to size the chunks: the cheapest of up to four calls (the
 * first also warms `run` up), fewer when a call is slow.
 */
function calibrate(run: () => void): number {
  let best = chunk(run, 1);
  for (let i = 1; i < 4 && best * i < 200; i += 1) best = Math.min(best, chunk(run, 1));
  return Math.max(best, 0.0005);
}

/**
 * One comparison: the cheapest chunk of each side, per call, the sides
 * alternated in chunks of equal duration; `ms`, how long it took.
 */
function measure(a: () => void, b: () => void): { a: number; b: number; ms: number } {
  const t0 = performance.now();
  const onceA = calibrate(a);
  const onceB = calibrate(b);
  const duration = Math.max(MIN_CHUNK_MS, Math.min(MAX_CHUNK_MS, Math.max(onceA, onceB)));
  const callsA = Math.max(1, Math.round(duration / onceA));
  const callsB = Math.max(1, Math.round(duration / onceB));
  collectGarbage();
  let bestA = Number.POSITIVE_INFINITY;
  let bestB = Number.POSITIVE_INFINITY;
  const start = performance.now();
  for (let c = 0; c < CHUNKS; c += 1) {
    const elapsed = performance.now() - start;
    if ((c >= 6 && elapsed > LONG_MS) || (c >= 3 && elapsed > SLOW_MS)) break;
    bestA = Math.min(bestA, chunk(a, callsA));
    bestB = Math.min(bestB, chunk(b, callsB));
  }
  return { a: bestA, b: bestB, ms: performance.now() - t0 };
}

/**
 * The per-call costs of `a` and `b` and the ratio b / a, measured again while
 * it reads `bound` or more — up to {@link ATTEMPTS} comparisons, none after
 * one that took over {@link SLOW_MS} — and the cheapest reading kept.
 * `readings`: every comparison's ratio, in order.
 */
function compare(a: () => void, b: () => void, bound: number): { a: number; b: number; ratio: number; readings: number[] } {
  let best = { a: Number.NaN, b: Number.NaN, ratio: Number.POSITIVE_INFINITY };
  const readings: number[] = [];
  for (let i = 0; i < ATTEMPTS; i += 1) {
    const m = measure(a, b);
    const ratio = m.b / m.a;
    readings.push(ratio);
    if (ratio < best.ratio) best = { a: m.a, b: m.b, ratio };
    if (ratio < bound || m.ms > SLOW_MS) break;
  }
  return { ...best, readings };
}

const ms = (x: number): string => (x < 1 ? x.toFixed(3) : x.toFixed(1));
const list = (xs: readonly number[]): string => xs.map((x) => x.toFixed(1)).join(', ');

export interface LinearityOptions {
  /** How much larger the second input is. Default 8: linear ~8x, quadratic ~64x. */
  readonly factor?: number;
  /** The ratio the larger input must stay under. Default factor^1.5 (22.6 for 8x): the geometric middle. */
  readonly maxRatio?: number;
}

/**
 * Asserts that `run(n * factor)` costs well under `maxRatio` times `run(n)` —
 * not superlinear. See the module comment for why the default bound is
 * factor^1.5 and why a capped cost needs {@link expectNearReference} as well.
 */
export function expectLinear(
  label: string,
  run: (size: number) => void,
  n: number,
  opts: LinearityOptions = {},
): { small: number; large: number; ratio: number } {
  const factor = opts.factor ?? 8;
  const maxRatio = opts.maxRatio ?? factor ** 1.5;
  const { a: small, b: large, ratio, readings } = compare(() => run(n), () => run(n * factor), maxRatio);
  record({ kind: 'linear', label, n, factor, small, large, ratio, readings, bound: maxRatio });
  expect(
    ratio,
    `${label}: ${String(factor)}x the input cost ${ms(large)} ms a call against ${ms(small)} ms — ` +
      `ratio ${ratio.toFixed(2)}, bound ${maxRatio.toFixed(1)} (linear ~${String(factor)}, quadratic ~${String(factor ** 2)}; ` +
      `readings ${list(readings)})`,
  ).toBeLessThan(maxRatio);
  return { small, large, ratio };
}

export interface ReferenceOptions {
  /** How many times the reference's cost `run` may take. */
  readonly maxRatio: number;
}

/**
 * Asserts that `run` costs at most `maxRatio` times `reference` — the same
 * function over an input of the same size with nothing pathological in it,
 * measured alternately in the same process. For a cost a cap keeps linear in
 * the input (a quadratic rule inside each 16 KB window): no ratio of sizes
 * sees it, and an absolute ceiling measures the machine; this ceiling moves
 * with the machine and the instrumentation, because the reference does.
 */
export function expectNearReference(
  label: string,
  run: () => void,
  reference: () => void,
  opts: ReferenceOptions,
): { cost: number; reference: number; ratio: number } {
  const { a: ref, b: cost, ratio, readings } = compare(reference, run, opts.maxRatio);
  record({ kind: 'reference', label, cost, reference: ref, ratio, readings, bound: opts.maxRatio });
  expect(
    ratio,
    `${label}: ${ms(cost)} ms a call against ${ms(ref)} ms for the reference input of the same size — ` +
      `ratio ${ratio.toFixed(2)}, bound ${String(opts.maxRatio)} (readings ${list(readings)})`,
  ).toBeLessThan(opts.maxRatio);
  return { cost, reference: ref, ratio };
}

/**
 * The per-call cost of `run`, ms, for a strict absolute bound: its cheapest
 * of 8 chunks, or of 3 once they have taken {@link LONG_MS}.
 */
export function costOf(run: () => void): number {
  const once = calibrate(run);
  const calls = Math.max(1, Math.round(MIN_CHUNK_MS / once));
  collectGarbage();
  let best = once;
  const start = performance.now();
  for (let c = 0; c < 8; c += 1) {
    if (c >= 3 && performance.now() - start > LONG_MS) break;
    best = Math.min(best, chunk(run, calls));
  }
  return best;
}
