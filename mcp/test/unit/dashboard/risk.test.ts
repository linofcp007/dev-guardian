import { describe, expect, it } from 'vitest';
import { scoreRisk } from '../../../src/dashboard/risk.js';
import type { RiskInput } from '../../../src/dashboard/types.js';
import type { Finding, Cve } from '../../../src/types.js';

const NOW = Date.parse('2026-08-15T12:00:00.000Z');

function finding(severity: string): Finding {
  return {
    fingerprint: `fp-${severity}-${Math.random()}`,
    tool: 'semgrep', rule_id: 'r', severity,
    category: 'security', subcategory: null,
    title: 't', message: 'm', file_path: 'a.ts',
    line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

function cve(severity: string): Cve {
  return {
    cve_id: `CVE-${severity}`, package_name: 'p', installed_version: '1',
    fixed_version: '2', severity,
    first_seen_scan_id: 's', last_seen_scan_id: 's',
  } as unknown as Cve;
}

function base(over: Partial<RiskInput> = {}): RiskInput {
  return {
    findings: [], cves: [], policies_missing: 0,
    dependency_bot_configured: true, baseline_set_at: null,
    coverage_partial: false, now: NOW, ...over,
  };
}

describe('scoreRisk', () => {
  it('weights findings 10/5/2/1 by severity', () => {
    const r = scoreRisk(base({
      findings: [finding('critical'), finding('high'), finding('medium'), finding('low')],
      baseline_set_at: '2026-08-14T12:00:00.000Z',   // fresh: contributes 0
    }));
    expect(r.components.findings.score).toBe(18);      // 10+5+2+1
    expect(r.components.findings.open_findings).toBe(4);
  });

  it('caps the findings component at 40, not the whole score', () => {
    const many = Array.from({ length: 20 }, () => finding('critical'));  // raw 200
    const r = scoreRisk(base({ findings: many, baseline_set_at: '2026-08-14T12:00:00.000Z' }));
    expect(r.components.findings.score).toBe(40);
  });

  it('weights CVEs 8/4/1.5/0.5 and caps at 30', () => {
    const r = scoreRisk(base({
      cves: [cve('critical'), cve('high'), cve('medium'), cve('unknown')],
      baseline_set_at: '2026-08-14T12:00:00.000Z',
    }));
    expect(r.components.cves.score).toBe(14);          // 8+4+1.5+0.5 → rounded
    expect(r.components.cves.active_cves).toBe(4);
  });

  it('penalises a never-set baseline by 8, a >30d baseline by 8, a >90d baseline by 15', () => {
    const day = 24 * 60 * 60 * 1000;
    expect(scoreRisk(base({ baseline_set_at: null })).components.baseline.score).toBe(8);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 40 * day).toISOString() }))
      .components.baseline.score).toBe(8);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 100 * day).toISOString() }))
      .components.baseline.score).toBe(15);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 5 * day).toISOString() }))
      .components.baseline.score).toBe(0);
  });

  it('takes its clock from the input, never the ambient one', () => {
    // The wrong implementation calls Date.now() and this test passes today,
    // fails in 2027, and nobody knows why. Two different injected clocks over
    // the SAME baseline must produce two different staleness scores.
    const day = 24 * 60 * 60 * 1000;
    const setAt = new Date(NOW - 40 * day).toISOString();
    const fresh = scoreRisk(base({ baseline_set_at: setAt, now: NOW }));
    const later = scoreRisk(base({ baseline_set_at: setAt, now: NOW + 60 * day }));
    expect(fresh.components.baseline.score).toBe(8);
    expect(later.components.baseline.score).toBe(15);
  });

  it('bands at 70 / 40 / 15', () => {
    const crit = Array.from({ length: 7 }, () => finding('critical'));  // 40 cap
    expect(scoreRisk(base({ findings: crit, cves: [cve('critical'), cve('critical'),
      cve('critical'), cve('critical')], policies_missing: 3,
      dependency_bot_configured: false })).band).toBe('critical');
    expect(scoreRisk(base()).band).toBe('low');
  });

  it('sets coverage_caveat straight through from the input', () => {
    expect(scoreRisk(base({ coverage_partial: true })).coverage_caveat).toBe(true);
    expect(scoreRisk(base({ coverage_partial: false })).coverage_caveat).toBe(false);
  });

  it('never returns a score above 100 or below 0', () => {
    const many = Array.from({ length: 200 }, () => finding('critical'));
    const cves = Array.from({ length: 200 }, () => cve('critical'));
    const r = scoreRisk(base({ findings: many, cves, policies_missing: 3,
      dependency_bot_configured: false, baseline_set_at: null }));
    expect(r.score).toBeLessThanOrEqual(100);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });
});
