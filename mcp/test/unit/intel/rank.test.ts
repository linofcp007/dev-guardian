import { describe, expect, it } from 'vitest';
import { exploitabilitySignal, findingCveIds, isUncorrelatedFinding, rankByExploitability } from '../../../src/intel/rank.js';
import type { CveIntelResult } from '../../../src/intel/types.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: `fp-${Math.random()}`,
    tool: 'trivy',
    severity: 'high',
    category: 'security',
    title: 'a vulnerability',
    fix_available: false,
    ...over,
  };
}

function ok(over: Partial<CveIntelResult> = {}): CveIntelResult {
  return { cve_id: 'CVE-0', status: 'ok', kev: false, ...over };
}

describe('findingCveIds', () => {
  it('reads a rule_id that is itself a CVE id (Trivy, always)', () => {
    expect(findingCveIds(finding({ rule_id: 'CVE-2021-44228' }))).toEqual(['CVE-2021-44228']);
  });

  it('is case-insensitive on rule_id and normalises to upper case', () => {
    expect(findingCveIds(finding({ rule_id: 'cve-2021-44228' }))).toEqual(['CVE-2021-44228']);
  });

  // Deliberately reversed (3.0 additions, review of part C, C1): this used
  // to read CVE ids out of the title and message, which tied a finding to
  // every CVE its description MENTIONS — CVE-2026-4800's lodash advisory
  // mentions CVE-2021-23337, and inherited its EPSS boost. A finding is tied
  // to a CVE only by its own ids now: the rule id, and the aliases its
  // scanner recorded (`intel/vulnIds.ts`).
  it('never reads a CVE id the title or message merely mentions', () => {
    expect(
      findingCveIds(finding({ rule_id: 'GHSA-35jh-r3h4-6jhm', title: 'lodash prototype pollution (CVE-2020-8203)' })),
    ).toEqual([]);
    expect(
      findingCveIds(finding({ rule_id: 'CVE-2026-4800', message: 'an incomplete fix for CVE-2021-23337' })),
    ).toEqual(['CVE-2026-4800']);
  });

  it('reads the CVE ids among the aliases the scanner recorded', () => {
    expect(
      findingCveIds(finding({ tool: 'pip-audit', rule_id: 'PYSEC-2021-142', vuln_aliases: ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'] })),
    ).toEqual(['CVE-2020-14343']);
  });

  it('dedupes when the same CVE is both the rule id and an alias', () => {
    expect(findingCveIds(finding({ rule_id: 'CVE-2021-1', vuln_aliases: ['cve-2021-1'] }))).toEqual(['CVE-2021-1']);
  });

  it('returns nothing for a finding with no CVE association at all (a plain Semgrep finding)', () => {
    expect(findingCveIds(finding({ rule_id: 'no-eval', title: 'Use of eval()' }))).toEqual([]);
  });
});

describe('exploitabilitySignal', () => {
  it('is KEV when any correlated CVE is KEV-listed', () => {
    const intel = new Map([['CVE-1', ok({ cve_id: 'CVE-1', kev: true })]]);
    expect(exploitabilitySignal(['CVE-1'], intel)).toEqual({ kev: true, max_epss: null, cve_ids: ['CVE-1'] });
  });

  it('takes the highest EPSS score across correlated CVEs', () => {
    const intel = new Map([
      ['CVE-1', ok({ cve_id: 'CVE-1', epss_score: 0.2 })],
      ['CVE-2', ok({ cve_id: 'CVE-2', epss_score: 0.8 })],
    ]);
    expect(exploitabilitySignal(['CVE-1', 'CVE-2'], intel)).toEqual({ kev: false, max_epss: 0.8, cve_ids: ['CVE-1', 'CVE-2'] });
  });

  it('ignores a CVE with no intel entry (never correlated) or status: unavailable (not measured)', () => {
    const intel = new Map([['CVE-2', { cve_id: 'CVE-2', status: 'unavailable', kev: false } as CveIntelResult]]);
    expect(exploitabilitySignal(['CVE-1', 'CVE-2'], intel)).toEqual({ kev: false, max_epss: null, cve_ids: [] });
  });

  it('returns no signal for no CVE ids', () => {
    expect(exploitabilitySignal([], new Map())).toEqual({ kev: false, max_epss: null, cve_ids: [] });
  });
});

describe('rankByExploitability', () => {
  const cveIdsOf = (f: Finding): string[] => (f.rule_id ? [f.rule_id] : []);

  it('puts a KEV-listed item ahead of a non-KEV item, regardless of input order', () => {
    const plain = finding({ fingerprint: 'plain', rule_id: 'CVE-PLAIN' });
    const kev = finding({ fingerprint: 'kev', rule_id: 'CVE-KEV' });
    const intel = new Map([
      ['CVE-PLAIN', ok({ cve_id: 'CVE-PLAIN' })],
      ['CVE-KEV', ok({ cve_id: 'CVE-KEV', kev: true })],
    ]);
    const ranked = rankByExploitability([plain, kev], cveIdsOf, intel);
    expect(ranked.map((f) => f.fingerprint)).toEqual(['kev', 'plain']);
  });

  it('among non-KEV items, ranks higher EPSS first', () => {
    const low = finding({ fingerprint: 'low', rule_id: 'CVE-LOW' });
    const high = finding({ fingerprint: 'high', rule_id: 'CVE-HIGH' });
    const intel = new Map([
      ['CVE-LOW', ok({ cve_id: 'CVE-LOW', epss_score: 0.1 })],
      ['CVE-HIGH', ok({ cve_id: 'CVE-HIGH', epss_score: 0.9 })],
    ]);
    const ranked = rankByExploitability([low, high], cveIdsOf, intel);
    expect(ranked.map((f) => f.fingerprint)).toEqual(['high', 'low']);
  });

  it('is a stable sort: items with no exploitability signal keep their relative (input) order', () => {
    const a = finding({ fingerprint: 'a' });
    const b = finding({ fingerprint: 'b' });
    const c = finding({ fingerprint: 'c' });
    const ranked = rankByExploitability([a, b, c], cveIdsOf, new Map());
    expect(ranked.map((f) => f.fingerprint)).toEqual(['a', 'b', 'c']);
  });

  it('never mutates the input array', () => {
    const items = [finding({ fingerprint: 'x' }), finding({ fingerprint: 'y' })];
    const copy = [...items];
    rankByExploitability(items, cveIdsOf, new Map());
    expect(items).toEqual(copy);
  });
});

describe('isUncorrelatedFinding (review round 1, Important #2)', () => {
  it('is true for a dependency-scanner finding with an advisory id but no extractable CVE', () => {
    // npm-audit v2's own defect (runners/scannerParsers/npmAudit.ts
    // mapV2Advisory): rule_id is a GHSA/advisory url or id, never a CVE, and
    // no CVE is recorded anywhere else on the finding either.
    expect(isUncorrelatedFinding(finding({ tool: 'npm-audit', rule_id: 'GHSA-xxxx-yyyy-zzzz', title: 'Prototype pollution in lodash' }))).toBe(true);
  });

  it('is false once a CVE IS extractable, even from the same tool', () => {
    expect(isUncorrelatedFinding(finding({ tool: 'npm-audit', rule_id: 'CVE-2020-8203' }))).toBe(false);
    expect(isUncorrelatedFinding(finding({ tool: 'trivy', rule_id: 'CVE-2021-44228' }))).toBe(false);
  });

  it('is false for a tool that was never expected to carry a CVE (an ordinary Semgrep finding)', () => {
    expect(isUncorrelatedFinding(finding({ tool: 'semgrep', rule_id: 'no-eval', title: 'Use of eval()' }))).toBe(false);
  });

  it('covers every CVE-capable scanner: trivy, npm-audit, wpscan, pip-audit', () => {
    for (const tool of ['trivy', 'npm-audit', 'wpscan', 'pip-audit']) {
      expect(isUncorrelatedFinding(finding({ tool, rule_id: 'advisory-only-id', title: 'no cve here' }))).toBe(true);
    }
  });
});
