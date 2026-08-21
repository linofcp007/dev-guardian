/**
 * Unit tests for axis 3's comparison, and for the abort accounting it rests
 * on.
 *
 * These exist because of a measurement, not a hypothesis. `bugfix-cs.yml` over
 * `dotnet/runtime` returned 793 findings on one run and 798 on the next --
 * `paths.scanned` 11 800 both times -- and the report attributed 14 findings
 * to clauses of a rule that had not produced a single one of them. The two
 * defects are separable and both are asserted here:
 *
 *  - a clause of rule A cannot move rule B's count, so the comparison is
 *    scoped to the ablated rule;
 *  - the per-rule timeout drops whole FILES once it trips often enough, and
 *    the rules that go down with the file are named nowhere, so the exclusion
 *    is by file rather than by (rule, file).
 */

import { describe, expect, it } from 'vitest';
import {
  axis3Verdict,
  comparable,
  comparableAll,
  noiseFloorByRule,
  noisyRules,
  scopeOf,
  worstFloor,
} from './axis3.js';
import { SemgrepFailure, isAbortError, parseScan } from './semgrep.js';
import type { Finding, ScanResult } from './semgrep.js';

function f(ruleId: string, file: string, line: number): Finding {
  return { ruleId, file, line, col: 1, endLine: line, endCol: 2 };
}

function scanResult(over: Partial<ScanResult> = {}): ScanResult {
  return { findings: [], scanned: 10, errors: [], abortedFiles: [], unscopedAborts: 0, ...over };
}

describe('scopeOf', () => {
  it('unions the aborted files of every scan in the comparison', () => {
    // Union, not intersection: a file only ONE side lost is precisely the file
    // that would otherwise show up as a delta.
    const scope = scopeOf([
      scanResult({ abortedFiles: ['a.cs'] }),
      scanResult({ abortedFiles: ['b.cs'] }),
      scanResult({ abortedFiles: ['a.cs', 'c.cs'] }),
    ]);
    expect([...scope.excluded].sort()).toEqual(['a.cs', 'b.cs', 'c.cs']);
    expect(scope.excludedFiles).toBe(3);
  });

  it('carries the aborts that named no file, which nothing can exclude', () => {
    const scope = scopeOf([scanResult({ unscopedAborts: 2 }), scanResult({ unscopedAborts: 1 })]);
    expect(scope.unscopedAborts).toBe(3);
    expect(scope.excludedFiles).toBe(0);
  });
});

describe('comparable', () => {
  const findings = [
    f('empty-catch', 'WMIGenerator.cs', 10),
    f('empty-catch', 'Other.cs', 20),
    f('modify-during-iteration', 'Other.cs', 30),
  ];

  it('keeps only the ablated rule -- the cross-rule attribution defect', () => {
    // The recorded defect: 14 findings reported against clauses of
    // `modify-during-iteration`, every one of them an `empty-catch` finding.
    const scope = scopeOf([]);
    expect(comparable(findings, 'modify-during-iteration', scope)).toEqual([
      f('modify-during-iteration', 'Other.cs', 30),
    ]);
  });

  it('drops findings in files no scan could be trusted on', () => {
    const scope = scopeOf([scanResult({ abortedFiles: ['WMIGenerator.cs'] })]);
    expect(comparable(findings, 'empty-catch', scope)).toEqual([f('empty-catch', 'Other.cs', 20)]);
  });

  it('makes the delta zero whichever side lost the file', () => {
    // Baseline saw 2 findings there, the ablated scan timed out and saw none.
    // Excluding the union means the pair contributes nothing either way round,
    // which is what makes the verdict repeatable across runs.
    const base = [f('r', 'slow.cs', 1), f('r', 'slow.cs', 2), f('r', 'fast.cs', 3)];
    const ablated = [f('r', 'fast.cs', 3)];
    const scope = scopeOf([scanResult({ abortedFiles: ['slow.cs'] }), scanResult()]);
    expect(comparable(base, 'r', scope).length - comparable(ablated, 'r', scope).length).toBe(0);
    // ... and the mirror image, where the baseline is the side that timed out.
    const mirror = scopeOf([scanResult(), scanResult({ abortedFiles: ['slow.cs'] })]);
    expect(comparable(ablated, 'r', mirror).length - comparable(base, 'r', mirror).length).toBe(0);
  });

  it('comparableAll keeps every rule but still drops the excluded files', () => {
    const scope = scopeOf([scanResult({ abortedFiles: ['Other.cs'] })]);
    expect(comparableAll(findings, scope)).toEqual([f('empty-catch', 'WMIGenerator.cs', 10)]);
  });
});

describe('noiseFloorByRule', () => {
  it('is zero for every rule when two scans of the same pack agree', () => {
    const a = [f('r1', 'x.cs', 1), f('r2', 'y.cs', 2)];
    const floor = noiseFloorByRule(a, [...a], ['r1', 'r2'], scopeOf([]));
    expect(worstFloor(floor)).toBe(0);
    expect(noisyRules(floor)).toEqual([]);
  });

  it('counts the symmetric difference, so a swap is not netted to zero', () => {
    // One finding gained and one lost is a drift of 2, not of 0. Counting the
    // difference of the totals would call this a clean measurement.
    const a = [f('r1', 'x.cs', 1)];
    const b = [f('r1', 'x.cs', 99)];
    const floor = noiseFloorByRule(a, b, ['r1'], scopeOf([]));
    expect(floor.get('r1')).toBe(2);
    expect(worstFloor(floor)).toBe(2);
  });

  it('reports the worst rule, not the sum, and names every rule that drifted', () => {
    const a = [f('r1', 'x.cs', 1), f('r2', 'y.cs', 2), f('r2', 'y.cs', 3)];
    const b = [f('r2', 'y.cs', 2)];
    const floor = noiseFloorByRule(a, b, ['r1', 'r2', 'r3'], scopeOf([]));
    expect(worstFloor(floor)).toBe(1);
    expect(noisyRules(floor)).toEqual([
      { ruleId: 'r1', drift: 1 },
      { ruleId: 'r2', drift: 1 },
    ]);
    expect(floor.get('r3')).toBe(0);
  });

  it('does not count drift inside the excluded files', () => {
    const a = [f('r1', 'slow.cs', 1)];
    const floor = noiseFloorByRule(a, [], ['r1'], scopeOf([scanResult({ abortedFiles: ['slow.cs'] })]));
    expect(worstFloor(floor)).toBe(0);
  });
});

describe('axis3Verdict', () => {
  it('passes only on an exactly zero delta', () => {
    expect(axis3Verdict(0, 0)).toBe('PASS');
    expect(axis3Verdict(0, 5)).toBe('PASS');
  });

  it('flags a delta that clears the floor', () => {
    expect(axis3Verdict(13, 0)).toBe('FAIL');
    expect(axis3Verdict(6, 5)).toBe('FAIL');
  });

  it('refuses to call a delta inside the floor either way', () => {
    // "+2 when the measurement error is +-5" is the verdict this exists to
    // stop being printed as a finding -- or as a pass.
    expect(axis3Verdict(2, 5)).toBe('INCONCLUSIVE');
    expect(axis3Verdict(5, 5)).toBe('INCONCLUSIVE');
  });
});

describe('isAbortError', () => {
  it('matches the abort types by substring, across wordings', () => {
    for (const t of [
      'Timeout',
      'Timeout during interfile analysis',
      'Out of memory',
      'Out of memory during interfile analysis',
    ]) {
      expect(isAbortError(t)).toBe(true);
    }
  });

  it('does not match parse failures, which are deterministic', () => {
    // A file that does not parse fails to parse identically on every run, so
    // excluding it would only shrink the corpus for nothing.
    for (const t of ['Syntax error', 'PartialParsing', 'Lexical error', 'SemgrepMatchFound']) {
      expect(isAbortError(t)).toBe(false);
    }
  });
});

describe('parseScan', () => {
  const doc = (over: Record<string, unknown> = {}): unknown => ({
    results: [],
    paths: { scanned: ['/corpus/a.cs'] },
    errors: [],
    ...over,
  });

  it('collects timed-out files, relative to the scan root', () => {
    const parsed = parseScan(
      doc({
        errors: [
          { type: 'Timeout', rule_id: 'p.slow-rule', path: '/corpus/sub/slow.cs', message: 'Timeout' },
          { type: 'Syntax error', path: '/corpus/sub/broken.cs', message: 'nope' },
        ],
      }),
      '/corpus',
      '/corpus',
    );
    expect(parsed.abortedFiles).toEqual(['sub/slow.cs']);
    expect(parsed.unscopedAborts).toBe(0);
    // The parse failure is reported like any other error, just not excluded.
    expect(parsed.errors).toHaveLength(2);
  });

  it('deduplicates the file when several rules time out on it', () => {
    // This is the threshold case: three rule timeouts on one file, after which
    // Semgrep drops the file for every rule still to run and names none of
    // them. One file excluded, not three pairs.
    const errors = ['r1', 'r2', 'r3'].map((r) => ({
      type: 'Timeout',
      rule_id: r,
      path: '/corpus/WMIGenerator.cs',
      message: `Timeout when running ${r}`,
    }));
    expect(parseScan(doc({ errors }), '/corpus', '/corpus').abortedFiles).toEqual([
      'WMIGenerator.cs',
    ]);
  });

  it('counts an abort with no path instead of silently ignoring it', () => {
    const parsed = parseScan(
      doc({ errors: [{ type: 'Timeout', message: 'Timeout' }] }),
      '/corpus',
      '/corpus',
    );
    expect(parsed.abortedFiles).toEqual([]);
    expect(parsed.unscopedAborts).toBe(1);
  });

  it('still treats zero scanned files as an exception, not a result', () => {
    expect(() => parseScan(doc({ paths: { scanned: [] } }), '/corpus', '/corpus')).toThrow(
      SemgrepFailure,
    );
  });
});
