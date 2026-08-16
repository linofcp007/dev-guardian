import { describe, expect, it } from 'vitest';
import { compareFindings } from '../../../src/dashboard/delta.js';
import type { Finding } from '../../../src/types.js';

function f(fingerprint: string): Finding {
  return {
    fingerprint, tool: 'semgrep', rule_id: 'r', severity: 'high',
    category: 'security', subcategory: null, title: 't', message: 'm',
    file_path: 'a.ts', line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

describe('compareFindings', () => {
  it('splits by fingerprint into new, resolved and unchanged', () => {
    const r = compareFindings(
      { scan_id: 'from', findings: [f('a'), f('b')] },
      { scan_id: 'to', findings: [f('b'), f('c')] },
      100,
    );
    expect(r.delta.new_count).toBe(1);        // c
    expect(r.delta.resolved_count).toBe(1);   // a
    expect(r.delta.unchanged_count).toBe(1);  // b
    expect(r.delta.new_findings.map((x) => x.fingerprint)).toEqual(['c']);
    expect(r.delta.from_scan_id).toBe('from');
    expect(r.delta.to_scan_id).toBe('to');
  });

  it('reports a truncation notice rather than silently capping new findings', () => {
    // The wrong implementation slices to the cap and returns null. A reader
    // then sees 2 rows and believes there were 2. Counts must stay TRUE even
    // when the list is cut.
    const to = Array.from({ length: 5 }, (_, i) => f(`n${i}`));
    const r = compareFindings({ scan_id: 'a', findings: [] }, { scan_id: 'b', findings: to }, 2);
    expect(r.delta.new_count).toBe(5);          // the COUNT is not capped
    expect(r.delta.new_findings).toHaveLength(2);
    expect(r.truncation).toEqual({
      what: 'new_findings', shown: 2, total: 5,
      reason: expect.stringContaining('cap'),
    });
  });

  it('returns no truncation notice when nothing was cut', () => {
    const r = compareFindings({ scan_id: 'a', findings: [] },
      { scan_id: 'b', findings: [f('x')] }, 100);
    expect(r.truncation).toBeNull();
  });

  it('is empty-safe on both sides', () => {
    const r = compareFindings({ scan_id: 'a', findings: [] },
      { scan_id: 'b', findings: [] }, 10);
    expect(r.delta.new_count).toBe(0);
    expect(r.delta.resolved_count).toBe(0);
    expect(r.delta.unchanged_count).toBe(0);
  });

  it('counts a fingerprint appearing twice on one side once', () => {
    // Findings are keyed (fingerprint, scan_id), so one scan cannot hold a
    // duplicate — but a caller merging two scans could. Set semantics, not
    // array arithmetic, is what keeps the three counts summing correctly.
    const r = compareFindings(
      { scan_id: 'a', findings: [f('x'), f('x')] },
      { scan_id: 'b', findings: [f('x')] },
      10,
    );
    expect(r.delta.unchanged_count).toBe(1);
    expect(r.delta.resolved_count).toBe(0);
  });

  it('counts a fingerprint appearing twice among new findings once too', () => {
    // Symmetric to the case above, on the `to` side this time: a caller
    // merging scans could hand in `to.findings` with a repeated fingerprint
    // that is genuinely new. It must still count and list once, not twice.
    const r = compareFindings(
      { scan_id: 'a', findings: [] },
      { scan_id: 'b', findings: [f('x'), f('x')] },
      10,
    );
    expect(r.delta.new_count).toBe(1);
    expect(r.delta.new_findings).toHaveLength(1);
  });
});
