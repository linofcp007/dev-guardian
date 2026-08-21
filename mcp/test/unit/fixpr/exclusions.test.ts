import { describe, expect, it } from 'vitest';
import { buildGroups } from '../../../src/fixpr/candidates.js';
import { describeExclusions, summariseExclusions } from '../../../src/fixpr/exclusions.js';
import type { FixSource, UpgradeStep } from '../../../src/fixpr/types.js';
import type { Finding, Severity } from '../../../src/types.js';

let counter = 0;
function finding(over: Partial<Finding> = {}): Finding {
  counter += 1;
  return {
    fingerprint: `fp-${counter}`, tool: 'semgrep', rule_id: 'r.1',
    severity: 'high', category: 'security', subcategory: null,
    title: 'a bug', message: 'm', file_path: 'src/a.ts',
    line_start: 1, line_end: 1, snippet: null,
    fix_available: true, fix_applied: false, raw: {},
    ...over,
  } as unknown as Finding;
}

function step(over: Partial<UpgradeStep> = {}): UpgradeStep {
  return {
    package_name: 'lodash', installed_version: '4.17.20', latest_version: '4.17.21',
    classification: 'security', ecosystem: 'npm',
    upgrade_command: 'npm install lodash@4.17.21',
    ...over,
  };
}

/** Runs the real `buildGroups`, then summarises against its real output —
 *  the coverage half of the report is measured from the groups that were
 *  actually produced, never re-derived, so the two can never disagree. */
function report(input: {
  findings: readonly Finding[];
  upgradeSteps?: readonly UpgradeStep[];
  sources?: readonly FixSource[];
  severityMin?: Severity;
}) {
  const upgradeSteps = input.upgradeSteps ?? [];
  const sources = input.sources ?? ['deps', 'semgrep'];
  const severityMin = input.severityMin ?? 'high';
  const groups = buildGroups({ findings: input.findings, upgradeSteps, sources, severityMin });
  const exclusions = summariseExclusions({ findings: input.findings, groups, severityMin });
  return { exclusions, reason: describeExclusions(exclusions, severityMin, sources) };
}

describe('summariseExclusions', () => {
  it('says nothing when nothing was excluded', () => {
    const { exclusions, reason } = report({ findings: [finding()] });
    expect(exclusions.considered).toBe(1);
    expect(exclusions.candidates).toBe(1);
    expect(exclusions.excluded).toBe(0);
    expect(reason).toBeNull();
  });

  it('always partitions: considered === candidates + excluded, and the reasons sum to excluded', () => {
    const findings = [
      finding(),                                    // candidate
      finding({ severity: 'medium' }),              // below the floor
      finding({ fix_available: false }),            // no fix
      finding({ tool: 'gitleaks' }),                // no fix source
    ];
    const { exclusions } = report({ findings });
    expect(exclusions.considered).toBe(4);
    expect(exclusions.candidates).toBe(1);
    expect(exclusions.excluded).toBe(3);
    const summed = Object.values(exclusions.by_reason).reduce((a, b) => a + b, 0);
    expect(summed).toBe(exclusions.excluded);
  });

  it('reports the severity breakdown and an actionable floor when the floor is what excluded them', () => {
    const findings = [
      ...Array.from({ length: 37 }, () => finding({ severity: 'medium' })),
      ...Array.from({ length: 3 }, () => finding({ severity: 'low' })),
    ];
    const { exclusions, reason } = report({ findings, sources: ['semgrep'] });
    expect(exclusions.candidates).toBe(0);
    expect(exclusions.excluded).toBe(40);
    expect(exclusions.by_reason.below_severity_min).toBe(40);
    expect(exclusions.below_severity_min.by_severity.medium).toBe(37);
    expect(exclusions.below_severity_min.by_severity.low).toBe(3);
    expect(exclusions.below_severity_min.suggested_severity_min).toBe('medium');
    expect(reason).toContain('40');
    expect(reason).toContain('37 medium');
    expect(reason).toContain('3 low');
    expect(reason).toContain('severity_min "medium"');
  });

  it('never suggests a lower floor for findings a lower floor would not recover', () => {
    // The local Semgrep packs carry no `fix:` at all, so every finding they
    // produce has fix_available === false and is excluded at ANY floor.
    // Telling that caller to pass severity_min "medium" would be a lie that
    // costs them a second run to discover.
    const findings = Array.from({ length: 40 }, () =>
      finding({ severity: 'medium', fix_available: false }),
    );
    const { exclusions, reason } = report({ findings, sources: ['semgrep'] });
    expect(exclusions.by_reason.no_fix_available).toBe(40);
    expect(exclusions.by_reason.below_severity_min).toBe(0);
    expect(exclusions.below_severity_min.suggested_severity_min).toBeNull();
    expect(reason).not.toContain('severity_min "medium"');
    expect(reason).toContain('no scanner-produced fix');
  });

  it('names the sources when a finding cleared both gates but no source covers it', () => {
    const { exclusions, reason } = report({
      findings: [finding({ tool: 'gitleaks' })],
      sources: ['semgrep'],
    });
    expect(exclusions.by_reason.no_fix_source).toBe(1);
    expect(reason).toContain('semgrep');
  });

  it('counts an eligible deps finding with no matching upgrade step as no_fix_source, not as a candidate', () => {
    // It passes fix_available and the floor, and `deps` IS a requested
    // source — buildGroups still cannot act on it, because deps_update_plan
    // offered no upgrade for that package. Silence here reads as "nothing
    // was wrong", which is the whole defect this report closes.
    const { exclusions } = report({
      findings: [finding({ tool: 'trivy', title: 'axios vulnerable' })],
      upgradeSteps: [step()],
      sources: ['deps'],
    });
    expect(exclusions.candidates).toBe(0);
    expect(exclusions.by_reason.no_fix_source).toBe(1);
  });

  it('reports a partial run, not only an empty one', () => {
    // A run that fixes 2 of 42 is nearly as opaque as one that fixes 0.
    const findings = [
      finding({ tool: 'trivy', title: 'lodash vulnerable' }),
      ...Array.from({ length: 40 }, () => finding({ severity: 'low' })),
    ];
    const { exclusions, reason } = report({ findings, upgradeSteps: [step()], sources: ['deps'] });
    expect(exclusions.candidates).toBe(1);
    expect(exclusions.excluded).toBe(40);
    expect(reason).not.toBeNull();
  });

  it('counts findings, not fingerprints, when two groups share none', () => {
    const findings = [
      finding({ tool: 'trivy', title: 'lodash vulnerable' }),
      finding({ tool: 'semgrep' }),
    ];
    const { exclusions } = report({ findings, upgradeSteps: [step()] });
    expect(exclusions.candidates).toBe(2);
    expect(exclusions.excluded).toBe(0);
  });
});
