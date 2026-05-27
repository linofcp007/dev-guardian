import { describe, expect, it } from 'vitest';
import { filterFindings, passes } from '../../../src/severity/filter.js';
import type { Severity } from '../../../src/types.js';

describe('severity.passes', () => {
  it('passes everything when min is undefined', () => {
    for (const s of ['info', 'low', 'medium', 'high', 'critical'] as Severity[]) {
      expect(passes(s)).toBe(true);
    }
  });

  it('respects the monotonic ordering info < low < medium < high < critical', () => {
    expect(passes('info', 'medium')).toBe(false);
    expect(passes('low', 'medium')).toBe(false);
    expect(passes('medium', 'medium')).toBe(true);
    expect(passes('high', 'medium')).toBe(true);
    expect(passes('critical', 'medium')).toBe(true);
  });

  it('treats critical as the most restrictive minimum', () => {
    expect(passes('critical', 'critical')).toBe(true);
    expect(passes('high', 'critical')).toBe(false);
  });
});

describe('severity.filterFindings', () => {
  const findings = [
    { id: 'a', severity: 'info' as Severity },
    { id: 'b', severity: 'low' as Severity },
    { id: 'c', severity: 'medium' as Severity },
    { id: 'd', severity: 'high' as Severity },
    { id: 'e', severity: 'critical' as Severity },
  ];

  it('returns input unchanged when min is undefined', () => {
    expect(filterFindings(findings)).toHaveLength(5);
  });

  it('filters by the floor inclusive', () => {
    const r = filterFindings(findings, 'high');
    expect(r.map((f) => f.id)).toEqual(['d', 'e']);
  });

  it('returns an empty array when nothing matches', () => {
    const r = filterFindings([{ id: 'x', severity: 'low' as Severity }], 'critical');
    expect(r).toEqual([]);
  });
});
