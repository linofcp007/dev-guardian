/**
 * `scan_skill` reads files of up to 2 MB, and a minified script or a
 * generated document is one line that long. A rule whose regex is quadratic
 * on a line — an unbounded `[^…]*` before an alternation, a per-match rescan
 * of the line — is a scan that does not finish. Measured in wave 2 of the 3.0
 * review, on a 50 KB line: a `sed -i` rule did not finish in ten minutes; on
 * 500 KB, a Markdown line full of backtick spans took 6.8 s and one full of
 * quoted phrases 1.6 s, both growing with the square of the length.
 *
 * Each case is a 1 MB line built to hand the slow shape as many starting
 * points as it can. The budget is generous — linear code takes well under a
 * second — so that a loaded machine does not fail it and a quadratic one
 * still does.
 */

import { describe, expect, it, vi } from 'vitest';

import { scanContent } from '../../../src/skillaudit/patterns.js';

vi.setConfig({ testTimeout: 120_000 });

const SIZE = 1_000_000;
const BUDGET_MS = 4_000;

const line = (chunk: string): string => chunk.repeat(Math.ceil(SIZE / chunk.length)).slice(0, SIZE);

describe('every rule stays linear on a 1 MB line', () => {
  it.each([
    ['backtick spans', 'var nc=`a${b}`;nc(x);'],
    ['quoted injection phrases', '"ignore previous instructions" and '],
    ['sed -i', 'sed -i s x '],
    ['copies and installs', 'cp a b install x y '],
    ['PowerShell content cmdlets', 'Add-Content x y z '],
    ['env pipelines', 'env | x | env | y '],
    ['redirects', 'a > b >> c > d '],
    ['download words and URLs', 'download get fetch https://x.invalid/a '],
  ])('%s', (_label, chunk) => {
    const text = line(chunk);
    for (const isCode of [true, false]) {
      const started = performance.now();
      scanContent(text, isCode);
      const elapsed = performance.now() - started;
      expect(elapsed, `${isCode ? 'code' : 'instruction'} file: ${Math.round(elapsed)} ms`).toBeLessThan(BUDGET_MS);
    }
  });
});
