/**
 * OWASP Top 10:2025 coverage: a category is claimed only when a scanner
 * able to detect it ran `ok` in the scans a report covers. Zero findings
 * from a scanner that did not run — or ran rules that cannot see the
 * category — is "not tested", never a clean bill.
 */

import { describe, expect, it } from 'vitest';
import {
  coverageRunsOf,
  OWASP_DETECTORS,
  owaspCoverage,
  type CoverageRun,
} from '../../../src/frameworks/coverage.js';
import { OWASP_2025_IDS, type Owasp2025Id } from '../../../src/frameworks/owaspTop10_2025.js';
import type { ToolRun } from '../../../src/types.js';

function run(scan_type: string, tools_run: ToolRun[], extra: Partial<CoverageRun> = {}): CoverageRun {
  return { scan_id: `${scan_type}-1`, scan_type, tools_run, missing_tools: [], ...extra };
}

function statusOf(cov: ReturnType<typeof owaspCoverage>): Record<string, string> {
  return Object.fromEntries(cov.categories.map((c) => [c.id, c.status]));
}

function tested(cov: ReturnType<typeof owaspCoverage>): Owasp2025Id[] {
  return cov.categories.filter((c) => c.status === 'tested').map((c) => c.id);
}

describe('owaspCoverage', () => {
  it('claims nothing when nothing ran, and says what could test each category', () => {
    const cov = owaspCoverage([], []);
    expect(cov.categories.map((c) => c.id)).toEqual([...OWASP_2025_IDS]);
    expect(cov.categories.every((c) => c.status === 'not_tested')).toBe(true);
    for (const c of cov.categories) expect(c.could_be_tested_by.length).toBeGreaterThan(0);
    expect(cov.findings_total).toBe(0);
    expect(cov.findings_unmapped).toBe(0);
  });

  it('a registry Semgrep run that finished ok covers what the registry rules can see — and nothing else', () => {
    const cov = owaspCoverage([run('sast', [{ name: 'semgrep', status: 'ok' }])], []);
    expect(tested(cov)).toEqual(['A01:2025', 'A02:2025', 'A04:2025', 'A05:2025', 'A06:2025', 'A07:2025', 'A08:2025']);
    expect(statusOf(cov)['A03:2025']).toBe('not_tested');
    expect(statusOf(cov)['A09:2025']).toBe('not_tested');
    expect(statusOf(cov)['A10:2025']).toBe('not_tested');
    const a05 = cov.categories.find((c) => c.id === 'A05:2025');
    expect(a05?.tested_by).toEqual([
      { scan_id: 'sast-1', scan_type: 'sast', tool: 'semgrep', detector: 'semgrep-registry' },
    ]);
  });

  it('a local_only Semgrep run claims nothing: the rules on disk are not the registry', () => {
    const cov = owaspCoverage([run('sast', [{ name: 'semgrep', status: 'ok' }], { meta: { local_only: true } })], []);
    expect(tested(cov)).toEqual([]);
  });

  it.each(['failed', 'skipped'] as const)('a Semgrep that %s claims nothing', (status) => {
    const cov = owaspCoverage([run('sast', [{ name: 'semgrep', status, reason: 'x' }])], []);
    expect(tested(cov)).toEqual([]);
    expect(cov.categories.every((c) => c.status === 'not_tested')).toBe(true);
  });

  // The same tools_run name, a different rule set: bug_hunt's Semgrep runs
  // the bugfix packs, which look for exception handling, not injection.
  it('Semgrep in a bug_hunt scan claims only what the bugfix packs detect', () => {
    const cov = owaspCoverage([run('bugs', [{ name: 'semgrep', status: 'ok' }])], []);
    expect(tested(cov)).toEqual(['A10:2025']);
  });

  it("compliance_check's Trivy is a license pass and claims no supply-chain coverage", () => {
    const cov = owaspCoverage([run('compliance', [{ name: 'trivy', status: 'ok' }, { name: 'semgrep-rgpd', status: 'ok' }])], []);
    expect(statusOf(cov)['A03:2025']).toBe('not_tested');
    expect(tested(cov)).toEqual(['A01:2025', 'A09:2025']);
  });

  it("scan_deps' Trivy covers A03; a per-ecosystem gap makes it partial", () => {
    expect(tested(owaspCoverage([run('deps', [{ name: 'trivy', status: 'ok' }])], []))).toEqual(['A03:2025']);
    const partial = owaspCoverage(
      [run('deps', [{ name: 'trivy', status: 'ok' }], { missing_tools: ['trivy:npm'] })],
      [],
    );
    expect(statusOf(partial)['A03:2025']).toBe('partial');
    expect(partial.categories.find((c) => c.id === 'A03:2025')?.tested_by[0]?.partial).toMatch(/trivy:npm/);
  });

  it('a run that was ok but partly parsed, or lost rules, or is also listed missing, is partial', () => {
    const partlyParsed = owaspCoverage(
      [run('sast', [{ name: 'semgrep', status: 'ok', partially_parsed: [{ file: 'a.js', type: 'PartialParsing', message: 'm' }] }])],
      [],
    );
    expect(statusOf(partlyParsed)['A05:2025']).toBe('partial');
    const lostRules = owaspCoverage(
      [run('sast', [{ name: 'semgrep', status: 'ok', failed_rules: [{ rule_id: 'r', message: 'm' }] }])],
      [],
    );
    expect(statusOf(lostRules)['A05:2025']).toBe('partial');
    const listedMissing = owaspCoverage(
      [run('sast', [{ name: 'semgrep', status: 'ok' }], { missing_tools: ['semgrep'] })],
      [],
    );
    expect(statusOf(listedMissing)['A05:2025']).toBe('partial');
  });

  it('a scan scoped to part of the project, or a diff review, is partial', () => {
    const scoped = owaspCoverage([run('sast', [{ name: 'semgrep', status: 'ok' }], { meta: { scope: { kind: 'diff' } } })], []);
    expect(statusOf(scoped)['A05:2025']).toBe('partial');
    const review = owaspCoverage([run('review_pr', [{ name: 'semgrep', status: 'ok' }])], []);
    expect(statusOf(review)['A05:2025']).toBe('partial');
  });

  it('one complete run beats a partial one for the same category', () => {
    const cov = owaspCoverage(
      [
        run('sast', [{ name: 'semgrep', status: 'ok' }], { scan_id: 'a', missing_tools: ['semgrep'] }),
        run('sast', [{ name: 'bandit', status: 'ok' }], { scan_id: 'b' }),
      ],
      [],
    );
    expect(statusOf(cov)['A05:2025']).toBe('tested');
    expect(statusOf(cov)['A02:2025']).toBe('partial'); // only Semgrep sees A02
  });

  // An orchestrated security_full row's own bookkeeping merges its children,
  // and does not record whether scan_sast ran local_only: its children say.
  it('an orchestrated security_full row claims no registry coverage on its own', () => {
    const cov = owaspCoverage(
      [run('security_full', [{ name: 'semgrep', status: 'ok' }, { name: 'trivy', status: 'ok' }], { meta: { child_scans: [] } })],
      [],
    );
    expect(tested(cov)).toEqual(['A03:2025']);
  });

  it('secrets: gitleaks covers A07', () => {
    expect(tested(owaspCoverage([run('secrets', [{ name: 'gitleaks', status: 'ok' }])], []))).toEqual(['A07:2025']);
  });

  it('counts findings per category, once per category they carry, and the unmapped ones apart', () => {
    const cov = owaspCoverage(
      [],
      [
        { owasp: ['A05:2025'] },
        { owasp: ['A04:2025', 'A07:2025'] },
        { owasp: [] },
        {},
        { owasp: ['A05:2025'] },
      ],
    );
    const byId = Object.fromEntries(cov.categories.map((c) => [c.id, c.findings]));
    expect(byId['A05:2025']).toBe(2);
    expect(byId['A04:2025']).toBe(1);
    expect(byId['A07:2025']).toBe(1);
    expect(cov.findings_total).toBe(5);
    expect(cov.findings_unmapped).toBe(2);
    // Findings are facts; coverage is a separate claim: A05 has findings
    // and was still not tested by a scanner the report covers.
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });
});

describe('OWASP_DETECTORS', () => {
  it('gives every 2025 category at least one detector', () => {
    for (const id of OWASP_2025_IDS) {
      expect(OWASP_DETECTORS.some((d) => d.categories.includes(id)), id).toBe(true);
    }
  });

  it('has unique ids and a stated basis for each claim', () => {
    expect(new Set(OWASP_DETECTORS.map((d) => d.id)).size).toBe(OWASP_DETECTORS.length);
    for (const d of OWASP_DETECTORS) expect(d.basis.length).toBeGreaterThan(20);
  });
});

describe('coverageRunsOf', () => {
  it('joins each bookkeeping view to its scan, and drops a view whose scan is unknown', () => {
    const runs = coverageRunsOf(
      [
        { scan_id: 's1', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] },
        { scan_id: 'gone', tools_run: [{ name: 'gitleaks', status: 'ok' }], missing_tools: [] },
      ],
      [{ scan_id: 's1', scan_type: 'sast', meta: { local_only: false } }],
    );
    expect(runs).toEqual([
      { scan_id: 's1', scan_type: 'sast', meta: { local_only: false }, tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] },
    ]);
  });
});
