import { describe, expect, it } from 'vitest';
import { severityShortfall } from '../../../src/severity/breakdown.js';
import type { Severity } from '../../../src/types.js';

function items(...severities: Severity[]): { severity: Severity }[] {
  return severities.map((severity) => ({ severity }));
}

describe('severityShortfall', () => {
  it('counts only what sits strictly below the floor', () => {
    const s = severityShortfall(items('critical', 'high', 'medium', 'low', 'info'), 'high');
    expect(s.total).toBe(3);
    expect(s.by_severity).toEqual({ critical: 0, high: 0, medium: 1, low: 1, info: 1 });
  });

  it('is empty, and suggests nothing, when the floor excludes nothing', () => {
    const s = severityShortfall(items('critical', 'high'), 'high');
    expect(s.total).toBe(0);
    expect(s.suggested_severity_min).toBeNull();
    expect(s.recovered_by_suggestion).toBe(0);
  });

  it('suggests the highest excluded tier — the smallest step down that recovers anything', () => {
    // 37 medium + 3 low, the shape the report exists for. 'medium' is the
    // smallest change that recovers anything at all, and it recovers 37 of
    // the 40 — never all of them, which is exactly why the count travels
    // with the suggestion instead of being left to be assumed.
    const s = severityShortfall(
      items(...Array<Severity>(37).fill('medium'), ...Array<Severity>(3).fill('low')),
      'high',
    );
    expect(s.suggested_severity_min).toBe('medium');
    expect(s.recovered_by_suggestion).toBe(37);
    expect(s.total).toBe(40);
  });

  it('orders by SEVERITY_ORDER, never alphabetically', () => {
    // 'low' > 'info' alphabetically but ranks below it in no ordering that
    // matters here; 'info' < 'low' < 'medium' is the only correct answer.
    const s = severityShortfall(items('info', 'low'), 'medium');
    expect(s.suggested_severity_min).toBe('low');
    expect(s.recovered_by_suggestion).toBe(1);
  });

  it("treats a floor of 'info' as excluding nothing at all", () => {
    const s = severityShortfall(items('info', 'low', 'critical'), 'info');
    expect(s.total).toBe(0);
  });
});
