/**
 * CISA SSVC — the decision table, and how each decision point is derived.
 *
 * `CISA_TABLE_9` below is Table 9 ("Table Representing Vulnerability
 * Prioritization") of the CISA Stakeholder-Specific Vulnerability
 * Categorization Guide, November 2022, copied row by row — the same 36 rows
 * CERT/CC publishes as `data/csv/cisa/cisa_coordinator_2_0_3.csv` in
 * github.com/CERTCC/SSVC (checked against both on 2026-09-28). It is kept
 * here, in the guide's own flat form, rather than derived from the module's
 * nested table, so a transcription slip in either one fails this test.
 */
import { describe, expect, it } from 'vitest';
import {
  EPSS_POC_THRESHOLD,
  assessSsvc,
  automatablePoint,
  exploitationPoint,
  missionWellbeingPoint,
  ssvcDecision,
  technicalImpactPoint,
  type Automatable,
  type Exploitation,
  type MissionWellbeing,
  type SsvcDecision,
  type TechnicalImpact,
} from '../../../src/intel/ssvc.js';
import type { CveIntelResult } from '../../../src/intel/types.js';
import type { DependencyAssessment } from '../../../src/validate/dependencyProvider.js';

type Row = readonly [Exploitation, Automatable, TechnicalImpact, MissionWellbeing, SsvcDecision];

const CISA_TABLE_9: readonly Row[] = [
  ['none', 'no', 'partial', 'low', 'Track'],
  ['none', 'no', 'partial', 'medium', 'Track'],
  ['none', 'no', 'partial', 'high', 'Track'],
  ['none', 'no', 'total', 'low', 'Track'],
  ['none', 'no', 'total', 'medium', 'Track'],
  ['none', 'no', 'total', 'high', 'Track*'],
  ['none', 'yes', 'partial', 'low', 'Track'],
  ['none', 'yes', 'partial', 'medium', 'Track'],
  ['none', 'yes', 'partial', 'high', 'Attend'],
  ['none', 'yes', 'total', 'low', 'Track'],
  ['none', 'yes', 'total', 'medium', 'Track'],
  ['none', 'yes', 'total', 'high', 'Attend'],
  ['poc', 'no', 'partial', 'low', 'Track'],
  ['poc', 'no', 'partial', 'medium', 'Track'],
  ['poc', 'no', 'partial', 'high', 'Track*'],
  ['poc', 'no', 'total', 'low', 'Track'],
  ['poc', 'no', 'total', 'medium', 'Track*'],
  ['poc', 'no', 'total', 'high', 'Attend'],
  ['poc', 'yes', 'partial', 'low', 'Track'],
  ['poc', 'yes', 'partial', 'medium', 'Track'],
  ['poc', 'yes', 'partial', 'high', 'Attend'],
  ['poc', 'yes', 'total', 'low', 'Track'],
  ['poc', 'yes', 'total', 'medium', 'Track*'],
  ['poc', 'yes', 'total', 'high', 'Attend'],
  ['active', 'no', 'partial', 'low', 'Track'],
  ['active', 'no', 'partial', 'medium', 'Track'],
  ['active', 'no', 'partial', 'high', 'Attend'],
  ['active', 'no', 'total', 'low', 'Track'],
  ['active', 'no', 'total', 'medium', 'Attend'],
  ['active', 'no', 'total', 'high', 'Act'],
  ['active', 'yes', 'partial', 'low', 'Attend'],
  ['active', 'yes', 'partial', 'medium', 'Attend'],
  ['active', 'yes', 'partial', 'high', 'Act'],
  ['active', 'yes', 'total', 'low', 'Attend'],
  ['active', 'yes', 'total', 'medium', 'Act'],
  ['active', 'yes', 'total', 'high', 'Act'],
];

describe('ssvcDecision — CISA Table 9', () => {
  it('has all 36 combinations', () => {
    expect(new Set(CISA_TABLE_9.map((r) => r.slice(0, 4).join('|'))).size).toBe(36);
  });

  it.each(CISA_TABLE_9)('%s / automatable %s / %s / %s -> %s', (e, a, t, m, decision) => {
    expect(
      ssvcDecision({ exploitation: e, automatable: a, technical_impact: t, mission_wellbeing: m }),
    ).toBe(decision);
  });
});

function intel(entries: CveIntelResult[]): Map<string, CveIntelResult> {
  return new Map(entries.map((e) => [e.cve_id, e]));
}

const measured = (cve_id: string, over: Partial<CveIntelResult> = {}): CveIntelResult => ({
  cve_id, status: 'ok', kev: false, fetched_at: '2026-09-28T00:00:00.000Z', ...over,
});
const unavailable = (cve_id: string): CveIntelResult => ({
  cve_id, status: 'unavailable', kev: false, reason: 'offline',
});

describe('exploitationPoint', () => {
  it('reads active from a CISA KEV listing, as data', () => {
    const p = exploitationPoint(['CVE-1'], intel([measured('CVE-1', { kev: true })]));
    expect(p).toMatchObject({ value: 'active', assumed: false });
    expect(p.basis).toMatch(/KEV/);
  });

  it('assumes active, and says so, when a CVE has no intel at all', () => {
    const p = exploitationPoint(['CVE-1'], intel([unavailable('CVE-1')]));
    expect(p).toMatchObject({ value: 'active', assumed: true });
    expect(p.basis).toMatch(/CVE-1/);
  });

  it('assumes active when one of two CVEs is unmeasured, even if the other is measured and low', () => {
    const p = exploitationPoint(['CVE-1', 'CVE-2'], intel([measured('CVE-1', { epss_score: 0.01 })]));
    expect(p).toMatchObject({ value: 'active', assumed: true });
  });

  it(`approximates poc from an EPSS score of at least ${EPSS_POC_THRESHOLD}`, () => {
    const p = exploitationPoint(['CVE-1'], intel([measured('CVE-1', { epss_score: EPSS_POC_THRESHOLD })]));
    expect(p).toMatchObject({ value: 'poc', assumed: false });
    expect(p.basis).toMatch(/EPSS/);
  });

  it('approximates none from a measured, non-KEV CVE with a low EPSS score', () => {
    const p = exploitationPoint(['CVE-1'], intel([measured('CVE-1', { epss_score: 0.02 })]));
    expect(p).toMatchObject({ value: 'none', assumed: false });
  });

  it('assumes poc — the worse of the two KEV leaves open — when FIRST has not scored the CVE', () => {
    const p = exploitationPoint(['CVE-1'], intel([measured('CVE-1')]));
    expect(p).toMatchObject({ value: 'poc', assumed: true });
  });

  it('a KEV listing on any correlated CVE wins over an unmeasured sibling', () => {
    const p = exploitationPoint(['CVE-1', 'CVE-2'], intel([measured('CVE-1', { kev: true })]));
    expect(p).toMatchObject({ value: 'active', assumed: false });
  });
});

describe('technicalImpactPoint', () => {
  it('approximates total from critical and high, partial from the rest, never as an assumption', () => {
    expect(technicalImpactPoint('critical')).toMatchObject({ value: 'total', assumed: false });
    expect(technicalImpactPoint('high')).toMatchObject({ value: 'total', assumed: false });
    expect(technicalImpactPoint('medium')).toMatchObject({ value: 'partial', assumed: false });
    expect(technicalImpactPoint('low')).toMatchObject({ value: 'partial', assumed: false });
    expect(technicalImpactPoint('info').basis).toMatch(/severity/);
  });
});

function dep(verdict: DependencyAssessment['verdict']): DependencyAssessment {
  return {
    verdict,
    confidence: 'medium',
    evidence: [{ detail: 'src/app.ts imports x and is reachable in 0 hops via GET /' }],
    coverage_gaps: [],
    importing_files: verdict === 'unknown' ? [] : ['src/app.ts'],
  };
}

describe('automatablePoint', () => {
  it('reads yes from exposure when a route reaches a file that imports the package', () => {
    const p = automatablePoint(dep('reachable'), null);
    expect(p).toMatchObject({ value: 'yes', assumed: false });
  });

  it('assumes yes when the package is only imported, or its use is unknown — never no from absence', () => {
    expect(automatablePoint(dep('imported'), null)).toMatchObject({ value: 'yes', assumed: true });
    expect(automatablePoint(dep('unknown'), null)).toMatchObject({ value: 'yes', assumed: true });
  });

  it('assumes yes, naming why, when there was nothing to assess against', () => {
    const p = automatablePoint(null, 'no attack-surface snapshot for this project');
    expect(p).toMatchObject({ value: 'yes', assumed: true });
    expect(p.basis).toMatch(/no attack-surface snapshot/);
  });
});

describe('missionWellbeingPoint and assessSsvc', () => {
  it('uses the caller value as given, and marks the default as assumed', () => {
    expect(missionWellbeingPoint('high')).toMatchObject({ value: 'high', assumed: false });
    expect(missionWellbeingPoint(undefined)).toMatchObject({ value: 'medium', assumed: true });
  });

  it('decides from the four points and lists the assumed ones', () => {
    const a = assessSsvc({
      exploitation: exploitationPoint(['CVE-1'], intel([measured('CVE-1', { kev: true })])),
      automatable: automatablePoint(dep('reachable'), null),
      technical_impact: technicalImpactPoint('critical'),
      mission_wellbeing: missionWellbeingPoint(undefined),
    });
    expect(a.decision).toBe('Act');
    expect(a.assumed).toEqual(['mission_wellbeing']);
  });
});
