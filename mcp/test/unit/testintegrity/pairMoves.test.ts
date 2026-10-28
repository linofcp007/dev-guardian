/**
 * Pairing an unstaged move (`testintegrity/gitChanges.ts#pairMoves`): the
 * deleted file an untracked one was moved from. Fix round 2 of the review,
 * item 2: it compared every new file with every deleted one, re-splitting the
 * old text each time — a 500-file directory move was ~250 000 comparisons and
 * held the MCP server 25–50 s. Each text is counted once now, same-name
 * candidates go first, an identical file ends the search, and the cross-name
 * comparisons are capped.
 */

import { describe, expect, it } from 'vitest';
import { pairMoves } from '../../../src/testintegrity/gitChanges.js';
import { expectLinear } from '../../helpers/timing.js';

/** A test file of `lines` lines, distinct for each `seed`. */
const testText = (seed: number, lines = 20): string =>
  Array.from({ length: lines }, (_, i) => `  it('case ${seed}-${i}', () => { expect(f(${seed}, ${i})).toBe(${seed * 31 + i}); });`).join('\n');

describe('pairMoves', () => {
  it('a moved directory: each file paired with its same-name original', () => {
    const old = new Map([0, 1, 2].map((i) => [`src/old/t${i}.test.ts`, testText(i)] as [string, string]));
    const fresh = [2, 0, 1].map((i) => ({ path: `src/new/t${i}.test.ts`, text: testText(i) }));
    const { pairs, capped } = pairMoves(old, fresh);
    expect([...pairs].sort()).toEqual([
      ['src/new/t0.test.ts', 'src/old/t0.test.ts'],
      ['src/new/t1.test.ts', 'src/old/t1.test.ts'],
      ['src/new/t2.test.ts', 'src/old/t2.test.ts'],
    ]);
    expect(capped).toBe(0);
  });

  it('a rename with edits: the best match over half the lines; under half, no pair', () => {
    const old = new Map([
      ['src/a.test.ts', testText(1)],
      ['src/b.test.ts', testText(2)],
    ]);
    const edited = testText(2).split('\n');
    edited.splice(0, 5, ...Array.from({ length: 5 }, (_, i) => `  it.skip('new ${i}', () => {});`));
    expect([...pairMoves(old, [{ path: 'src/renamed.spec.ts', text: edited.join('\n') }]).pairs]).toEqual([['src/renamed.spec.ts', 'src/b.test.ts']]);
    expect(pairMoves(old, [{ path: 'src/unrelated.test.ts', text: testText(9) }]).pairs.size).toBe(0);
  });

  it('a deleted file is paired once', () => {
    const old = new Map([['src/a.test.ts', testText(1)]]);
    const fresh = [
      { path: 'src/x.test.ts', text: testText(1) },
      { path: 'src/y.test.ts', text: testText(1) },
    ];
    expect(pairMoves(old, fresh).pairs.size).toBe(1);
  });

  it('caps the cross-name comparisons, and says how many files were left to same-name ones', () => {
    // 300 new files with no counterpart against 300 deletions of other names:
    // 90 000 comparisons uncapped.
    const old = new Map(Array.from({ length: 300 }, (_, i) => [`src/old/o${i}.test.ts`, testText(i)] as [string, string]));
    const fresh = Array.from({ length: 300 }, (_, i) => ({ path: `src/new/n${i}.test.ts`, text: testText(10_000 + i) }));
    const { pairs, capped } = pairMoves(old, fresh);
    expect(pairs.size).toBe(0);
    expect(capped).toBeGreaterThan(0);
  });

  it('linear in a moved directory (same names): 8x the files costs ~8x, never ~64x', () => {
    const inputs = new Map<number, { old: Map<string, string>; fresh: Array<{ path: string; text: string }> }>();
    const input = (n: number) => {
      let x = inputs.get(n);
      if (x === undefined) {
        x = {
          old: new Map(Array.from({ length: n }, (_, i) => [`src/old/t${i}.test.ts`, testText(i)] as [string, string])),
          fresh: Array.from({ length: n }, (_, i) => ({ path: `src/new/t${i}.test.ts`, text: testText(i) })),
        };
        inputs.set(n, x);
      }
      return x;
    };
    expectLinear('pairMoves: a directory of n test files moved without git mv', (n) => {
      const { old, fresh } = input(n);
      pairMoves(old, fresh);
    }, 40);
  });
});
