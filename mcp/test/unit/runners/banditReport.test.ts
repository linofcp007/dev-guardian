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
import { checkBanditReport, rewriteBanditReportPaths } from '../../../src/runners/fileBatchScan.js';
import { windowsPathKey } from '../../../src/runners/semgrepLongDirs.js';

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

/**
 * Review 3.6.1, finding 4: Bandit applies its own exclusion list
 * (`.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg`) as a SUBSTRING test
 * to files handed by name too. Measured on Bandit 1.9.4: `src/CVSImport.py`,
 * `lib/x.tox_util.py`, `pkg/my.eggs_helper.py`, `a/.hg_tools.py` — and,
 * with no `.git` in the working directory, `.github/…` and `.gitlab/…` — were
 * left out of `metrics` with no error, and the batch read complete.
 */
describe('checkBanditReport: every file handed to it', () => {
  const raw = report();
  it('a handed file the report neither analysed nor named is a partial gap, named', () => {
    const r = checkBanditReport({ raw, exitCode: 1, outcome: 'failed', handed: ['app/a.py', 'src/CVSImport.py', './test/files/decrypt.py'] });
    expect(r.ok).toBe(true);
    expect(r.partial).toEqual([expect.objectContaining({ file: 'src/CVSImport.py', type: 'Not analysed' })]);
    expect(r.partial?.[0]?.message).toMatch(/Bandit left it out/);
  });

  it('none of them analysed: the batch failed, never "scanned"', () => {
    const r = checkBanditReport({ raw: report({ metrics: { _totals: {} } }), exitCode: 0, outcome: 'completed', handed: ['src/CVSImport.py'] });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^bandit analysed none of the 1 file\(s\) it was handed: src\/CVSImport\.py/);
  });

  it('every one analysed, or named by an error: as before', () => {
    expect(checkBanditReport({ raw, exitCode: 1, outcome: 'failed', handed: ['app/a.py', 'test/files/decrypt.py'] })).toEqual({ ok: true, scanned: 2 });
  });
});

describe('rewriteBanditReportPaths', () => {
  it("the results' and errors' filename and the metrics keys rewritten, _totals kept; one the map does not know kept", () => {
    const L = '\\\\?\\C:\\p\\deep\\a.py';
    const raw = {
      results: [{ filename: L, test_id: 'B301' }, { filename: 'short.py', test_id: 'B301' }],
      errors: [{ filename: L, reason: SYNTAX }, { reason: 'no file' }],
      metrics: { [L]: { loc: 3 }, 'short.py': { loc: 1 }, _totals: { loc: 4 } },
    };
    const out = rewriteBanditReportPaths(raw, (p) => (windowsPathKey(p) === 'c:\\p\\deep\\a.py' ? 'deep/a.py' : null)) as typeof raw;
    expect(out.results.map((r) => r.filename)).toEqual(['deep/a.py', 'short.py']);
    expect(out.errors).toEqual([{ filename: 'deep/a.py', reason: SYNTAX }, { reason: 'no file' }]);
    expect(Object.keys(out.metrics)).toEqual(['deep/a.py', 'short.py', '_totals']);
  });

  it('windowsPathKey: the extended-length prefix off (a share back to \\\\host), one separator, lower case', () => {
    expect(windowsPathKey('\\\\?\\C:\\P\\A.py')).toBe('c:\\p\\a.py');
    expect(windowsPathKey('C:/P/A.py')).toBe('c:\\p\\a.py');
    expect(windowsPathKey('\\\\?\\UNC\\host\\share\\a.py')).toBe(windowsPathKey('\\\\host\\share\\a.py'));
  });
});
