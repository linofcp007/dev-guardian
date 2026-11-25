/**
 * The suppressions pass's cost is linear in what it reads, for EVERY row of
 * its table and every lexer (CRIT_G1 #7: the prototype's C# `#pragma` grammar
 * cost 17.7 s on a 128 KiB line, and a guard over a few hand-picked rows did
 * not see it). One comparison per row: a file of the row's own directive
 * followed by hostile tails — a run of blanks, a comma list, a run of words,
 * a run of the lexer's own markers, an unclosed reason field — 16 KiB against
 * 128 KiB, through `detectSuppressions` on both sides (`expectLinear`). A
 * removed line is read by the same functions (the lexer, the rows, the
 * carry key), so the added side times them all.
 *
 * What must STILL hold: `suppressions.test.ts` (the outcomes these lines are
 * built from).
 */

import { describe, it, vi } from 'vitest';
import { detectSuppressions, mayHoldSuppression, SUPPRESSION_ROWS } from '../../../src/testintegrity/suppressions.js';
import { SUPPRESSION_CASES as CASES } from '../../helpers/suppressionCases.js';
import { expectLinear } from '../../helpers/timing.js';

// 35 rows, each a comparison of about a second on a quiet machine.
vi.setConfig({ testTimeout: 60_000 });

const TAILS: ReadonlyArray<(n: number) => string> = [
  (n) => ` a${' '.repeat(n)}x`,
  (n) => ` a${' , a'.repeat(Math.floor(n / 4))} ;`,
  (n) => `${' a'.repeat(Math.floor(n / 2))}(`,
  (n) => ` ${'#'.repeat(n)}`,
  (n) => ` ${'/*'.repeat(Math.floor(n / 2))}`,
  (n) => ` ${`'"${String.fromCharCode(96)}`.repeat(Math.floor(n / 3))}`,
  (n) => ` ${'<<'.repeat(Math.floor(n / 2))}`,
  (n) => ` reason = "${'1'.repeat(n)}`,
];

/** A row's first directive line, from its first case that reads one. */
function directiveOf(row: string): { path: string; line: string } {
  const c = CASES.find((x) => x.row === row && /[MLNR]/.test(x.out));
  if (c === undefined) throw new Error(`no case reads ${row}`);
  const line = (c.added ?? c.lines.map((_, i) => i + 1)).map((n) => c.lines[n - 1] ?? '').find((l) => mayHoldSuppression(l));
  if (line === undefined) throw new Error(`no line of ${row} holds a token`);
  return { path: c.path, line };
}

describe('the suppressions pass is linear in its input, row by row', () => {
  it.each(SUPPRESSION_ROWS.map((r) => [r.id] as const))('%s', (id) => {
    const { path, line } = directiveOf(id);
    const run = (size: number): void => {
      // And a code line before a run of `#`: each `#` is a marker to try where the line is code (a Dockerfile's only at its start).
      const lines = [...TAILS.map((t) => `${line}${t(size)}`), `x ${'#'.repeat(size)}`];
      detectSuppressions([{ path, added: lines.map((text, i) => ({ line: i + 1, text })), removed: [], after: lines.join('\n') }]);
    };
    expectLinear(`suppressions row ${id}`, run, 16 * 1024);
  });
});
