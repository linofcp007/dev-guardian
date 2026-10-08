/**
 * Bandit's report, judged the way Semgrep's is (bugfix
 * sast-partial-parse-as-failed). Bandit lists the files it could not analyse
 * under `errors`; measured on OWASP Juice Shop, two Python test fixtures with
 * syntax errors (`test/files/decrypt.py`, `decrypt_bruteforce.py`) made the
 * whole Bandit run `failed`, and with Semgrep failing too, scan_sast reported
 * coverage `none` — "no scanner ran" — over a run that analysed every other
 * file. A per-file error on a clean exit that analysed files is a partial
 * gap, the file named, as it is for Semgrep.
 */

import { describe, expect, it } from 'vitest';
import { checkBanditReport } from '../../../src/runners/fileBatchScan.js';

const SYNTAX = 'syntax error while parsing AST from file';

function report(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    errors: [],
    results: [],
    metrics: { 'app/a.py': { loc: 12 }, 'test/files/decrypt.py': { loc: 0 }, _totals: { loc: 12 } },
    ...over,
  });
}

const judge = (raw: string | null, exitCode: number | null = 1, outcome: 'completed' | 'failed' | 'timed_out' = 'failed') =>
  checkBanditReport({ raw, exitCode, outcome });

describe('checkBanditReport', () => {
  it('T-02 partial: per-file syntax errors on a clean exit that analysed files — ok, the files named', () => {
    const r = judge(
      report({
        errors: [
          { filename: 'test/files/decrypt.py', reason: SYNTAX },
          { filename: 'test/files/decrypt_bruteforce.py', reason: SYNTAX },
        ],
      }),
    );
    expect(r.ok).toBe(true);
    expect(r.partial).toEqual([
      { file: 'test/files/decrypt.py', type: 'Syntax error', message: SYNTAX },
      { file: 'test/files/decrypt_bruteforce.py', type: 'Syntax error', message: SYNTAX },
    ]);
    expect(r.scanned).toBe(2);
  });

  it('T-02 another reason is still per file, under its own type (EC-1)', () => {
    const r = judge(report({ errors: [{ filename: 'app/b.py', reason: 'exception while scanning file' }] }), 0, 'completed');
    expect(r.ok).toBe(true);
    expect(r.partial).toEqual([{ file: 'app/b.py', type: 'Bandit error', message: 'exception while scanning file' }]);
  });

  it('T-03 failed: errors on a run that analysed nothing, an error naming no file, an unclean exit, no report, a run that did not finish', () => {
    const nothing = report({ metrics: { _totals: { loc: 0 } }, errors: [{ filename: 'a.py', reason: SYNTAX }] });
    expect(judge(nothing).ok).toBe(false);
    expect(judge(report({ errors: [{ reason: SYNTAX }] })).ok).toBe(false);
    expect(judge(report({ errors: [{ filename: 'a.py', reason: SYNTAX }] }), 2).ok).toBe(false);
    expect(judge(null).ok).toBe(false);
    expect(judge(report(), null, 'timed_out').ok).toBe(false);
  });

  it('a clean report is ok with nothing partial', () => {
    const r = judge(report(), 0, 'completed');
    expect(r.ok).toBe(true);
    expect(r.partial ?? []).toEqual([]);
  });
});
