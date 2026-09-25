/**
 * Splitting a file list across several scanner invocations.
 *
 * `review-scan.sh` piped the diff through `xargs`, whose batches (~19.8 KB on
 * Git Bash) each ran Semgrep with the SAME `--output=sast.json`: every batch
 * overwrote the last, and the review kept whichever batch finished last. A
 * long command line has to be split, and each piece has to be accounted for.
 */

import { describe, expect, it } from 'vitest';
import { ARG_CHAR_BUDGET, batchArgs, commandLineLength } from '../../../src/runners/argBatches.js';

describe('batchArgs', () => {
  it('keeps a short list in one batch', () => {
    expect(batchArgs(['a.py', 'b.py'], { fixedArgs: ['--json'] })).toEqual([['a.py', 'b.py']]);
  });

  it('returns no batch at all for no items', () => {
    expect(batchArgs([], { fixedArgs: ['--json'] })).toEqual([]);
  });

  it('splits more than 24 000 characters of paths so every command line stays under the budget', () => {
    const files = Array.from({ length: 800 }, (_, i) => `src/some directory/module_${i}/file with spaces ${i}.py`);
    const total = files.reduce((n, f) => n + f.length, 0);
    expect(total).toBeGreaterThan(24_000);
    const fixedArgs = ['--config=auto', '--json', '--quiet', '--output', 'C:/x/y/sast-1.json', '--'];
    const batches = batchArgs(files, { command: 'semgrep', fixedArgs });
    expect(batches.length).toBeGreaterThan(1);
    // Nothing lost, nothing duplicated, order kept.
    expect(batches.flat()).toEqual(files);
    for (const batch of batches) {
      expect(commandLineLength('semgrep', [...fixedArgs, ...batch])).toBeLessThanOrEqual(ARG_CHAR_BUDGET);
    }
  });

  it('gives an item longer than the budget a batch of its own instead of dropping it', () => {
    const huge = 'x'.repeat(30_000);
    const batches = batchArgs(['a', huge, 'b'], { fixedArgs: [], maxChars: 1_000 });
    expect(batches).toEqual([['a'], [huge], ['b']]);
  });

  it('counts the quoting a path with spaces or quotes needs on a command line', () => {
    expect(commandLineLength('x', ['a b'])).toBeGreaterThan(commandLineLength('x', ['ab_']));
    expect(commandLineLength('x', ['a"b'])).toBeGreaterThan(commandLineLength('x', ['a_b']));
  });
});
