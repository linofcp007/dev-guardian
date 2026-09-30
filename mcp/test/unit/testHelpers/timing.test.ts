/**
 * `test/helpers/timing.ts` — positive controls: each assertion fails on the
 * shape of the defects it exists for, and passes on a linear one (review 3.0,
 * R7 round 2). Without them a timing assertion that stopped being able to fail
 * would look exactly like fast, correct code.
 *
 * The shapes are those of the defects the suite's timing tests were written
 * for: quadratic (a search restarted at every occurrence — rawReport,
 * parseCommand), n^1.8 (the here-string openers rescanned, bashGuard, which
 * read 8.8 at 4x and passed the old 12 bound), and a quadratic cost capped per
 * 16 KB window (the JWT finder, secretScan: 4.09 at 4x across windows) —
 * including that finder's real pre-fix pattern.
 *
 * A synthetic control that must FAIL is sized so that a call of its larger
 * side takes under ~5 ms: its chunks are then as short as they get and
 * nearly always clean, so it reads the true ratio even at 100% CPU. Measured
 * with 11 ms calls, a quadratic read as low as 13.8 in 1 comparison of 20
 * under load; the retry that keeps a linear shape from failing on such a
 * reading would make a control pass on it.
 */

import { describe, expect, it, vi } from 'vitest';
import { costOf, expectLinear, expectNearReference } from '../../helpers/timing.js';

vi.setConfig({ testTimeout: 60_000 });

let sink = 0;
/** Matches no `a`: over a run of them it reads every character and finds nothing. */
const NOT_A = /[^a]/;
const RUNS = new Map<number, string>();
/**
 * ~`k` units of linear work: a regular expression reading `k` characters
 * (0.75-0.9 ns each, from 8 000 to 3 200 000 of them). Irregexp compiles it
 * once, to native code every caller shares, so a unit costs the same whoever
 * calls it. A JavaScript loop did not: inlined into different callers it ran
 * at 0.75 or 4.3 ns an iteration, and a control whose two sides got
 * different versions read 3.5 where it reads 16.
 */
function spin(k: number): void {
  let run = RUNS.get(k);
  if (run === undefined) {
    run = 'a'.repeat(k);
    RUNS.set(k, run);
  }
  if (NOT_A.test(run)) sink += 1;
}
const linear = (n: number): void => spin(n * 64);
const quadratic = (n: number): void => spin(n * n);
const power18 = (n: number): void => spin(Math.round(n ** 1.8) | 0);
const power125 = (n: number): void => spin(Math.round(n ** 1.25) | 0);
const WINDOW = 1024;
/** Quadratic inside each window of WINDOW, windows back to back: linear in n, ~16x the cost of `linear`. */
const windowedQuadratic = (n: number): void => {
  for (let w = 0; w < n; w += WINDOW) {
    const m = Math.min(WINDOW, n - w);
    spin(m * m);
  }
};

describe('expectLinear', () => {
  it('passes a linear cost', () => {
    const { ratio } = expectLinear('linear', linear, 4_000);
    expect(ratio).toBeGreaterThan(4);
  });

  it('fails a quadratic cost by its assertion', () => {
    expect(() => expectLinear('quadratic', quadratic, 200)).toThrow(/ratio \d+\.\d+, bound 22\.6/);
  });

  it('fails an n^1.8 cost (8x reads ~42; the old 4x read ~12 against a bound of 12)', () => {
    expect(() => expectLinear('n^1.8', power18, 500)).toThrow(/bound 22\.6/);
  });

  it('passes a mildly superlinear n^1.25 cost (8x reads ~13.5)', () => {
    expect(expectLinear('n^1.25', power125, 20_000).ratio).toBeLessThan(22.6);
  });

  it('cannot see a quadratic cost capped per window across windows — and sees it inside one', () => {
    expect(expectLinear('across windows', windowedQuadratic, 2 * WINDOW).ratio).toBeLessThan(22.6);
    expect(() => expectLinear('inside a window', windowedQuadratic, WINDOW / 8)).toThrow(/bound 22\.6/);
  });
});

describe('expectNearReference', () => {
  it('passes a cost that is a small multiple of the reference', () => {
    expectNearReference('3x linear', () => spin(3 * 64 * 2 * WINDOW), () => linear(2 * WINDOW), { maxRatio: 6 });
  });

  it('fails a per-window quadratic cost that no ratio of sizes sees', () => {
    expect(() =>
      expectNearReference('windowed quadratic', () => windowedQuadratic(2 * WINDOW), () => linear(2 * WINDOW), {
        maxRatio: 6,
      }),
    ).toThrow(/bound 6/);
  });
});

// The JWT finder's own pre-fix defect (secretScan, review I3): its pattern,
// run window by window, backtracks up to 2 000 characters at every `eyJ`.
describe('the real pre-fix JWT pattern, windowed at 16 KB', () => {
  const OLD_JWT = /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\b/;
  const scanWindows = (text: string): void => {
    for (let s = 0; s < text.length; s += 14 * 1024) sink ^= OLD_JWT.test(text.slice(s, s + 16 * 1024)) ? 1 : 0;
  };
  const eyj = (n: number): string => 'eyJ-'.repeat(n);
  const plain = (n: number): string => 'eyJ.'.repeat(n);

  it('reads linear across windows (the blind spot)', () => {
    expect(expectLinear('across windows', (n) => scanWindows(eyj(n)), 2_000).ratio).toBeLessThan(22.6);
  });

  it('fails a ratio inside one window', () => {
    expect(() => expectLinear('inside a window', (n) => scanWindows(eyj(n)), 62)).toThrow(/bound 22\.6/);
  });

  it('fails a ceiling against the same scan of an input with nothing to backtrack over', () => {
    expect(() =>
      expectNearReference('eyJ- x 4 K', () => scanWindows(eyj(4_000)), () => scanWindows(plain(4_000)), { maxRatio: 20 }),
    ).toThrow(/bound 20/);
  });
});

describe('costOf', () => {
  it('reports a per-call cost that grows with the work', () => {
    expect(costOf(() => linear(64_000))).toBeGreaterThan(costOf(() => linear(1_000)));
  });
});
