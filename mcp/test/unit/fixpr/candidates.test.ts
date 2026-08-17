import { describe, expect, it } from 'vitest';
import { buildGroups, selectGroups } from '../../../src/fixpr/candidates.js';
import type { UpgradeStep } from '../../../src/fixpr/types.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'f'.repeat(64), tool: 'trivy', rule_id: 'CVE-2021-1',
    severity: 'high', category: 'security', subcategory: null,
    title: 'lodash vulnerable', message: 'm', file_path: 'package.json',
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

describe('buildGroups', () => {
  it('pairs a dependency finding with its upgrade step and keeps the pinned command verbatim', () => {
    const groups = buildGroups({
      findings: [finding({ title: 'lodash vulnerable' })],
      upgradeSteps: [step()],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.key).toBe('npm');
    expect(groups[0]?.candidates[0]?.command).toBe('npm install lodash@4.17.21');
  });

  it('drops a finding with no fix_available rather than inventing a fix for it', () => {
    // The wrong implementation groups everything and then fails at apply time,
    // which is a much later and much more confusing place to find out.
    const groups = buildGroups({
      findings: [finding({ fix_available: false })],
      upgradeSteps: [step()], sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('honours severityMin against SEVERITY_ORDER, not alphabetically', () => {
    const groups = buildGroups({
      findings: [finding({ severity: 'medium' })],
      upgradeSteps: [step()], sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('honours the sources filter', () => {
    const groups = buildGroups({
      findings: [finding()], upgradeSteps: [step()],
      sources: ['semgrep'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('puts each ecosystem in its own group, so one revert cannot drag another', () => {
    const groups = buildGroups({
      findings: [
        finding({ fingerprint: 'a'.repeat(64), title: 'lodash vulnerable' }),
        finding({ fingerprint: 'b'.repeat(64), title: 'requests vulnerable' }),
      ],
      upgradeSteps: [
        step(),
        step({ package_name: 'requests', ecosystem: 'pip',
          upgrade_command: 'pip install -U requests==2.32.0' }),
      ],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups.map((g) => g.key).sort()).toEqual(['npm', 'pip']);
  });

  // --- Word-boundary pairing: a substring match would apply the WRONG
  // package's fix, not just miss a pairing — e.g. "npm install request@x"
  // for a vulnerability that is actually in "requests". Each case below is
  // confusable under plain `.includes()` but must not pair.

  it('does not pair "request" with a finding about the different package "requests"', () => {
    const groups = buildGroups({
      findings: [finding({ title: 'requests vulnerable', fingerprint: 'a'.repeat(64) })],
      upgradeSteps: [step({ package_name: 'request', ecosystem: 'npm',
        upgrade_command: 'npm install request@2.88.2' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('does not pair "lodash" with a finding about the different package "lodash.merge"', () => {
    const groups = buildGroups({
      findings: [finding({ title: 'lodash.merge vulnerable', fingerprint: 'a'.repeat(64) })],
      upgradeSteps: [step()], // package_name: 'lodash'
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('does not pair "axios" with a finding about the different package "axios-retry"', () => {
    const groups = buildGroups({
      findings: [finding({ title: 'axios-retry vulnerable', fingerprint: 'a'.repeat(64) })],
      upgradeSteps: [step({ package_name: 'axios', ecosystem: 'npm',
        upgrade_command: 'npm install axios@1.7.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('matches a scoped npm package name as one whole token', () => {
    // '@' and '/' are non-word characters, so a naive \b boundary would
    // already treat "@babel/core" as containing a boundary-delimited
    // "core" — this must still match the FULL scoped name exactly.
    const groups = buildGroups({
      findings: [finding({ title: '@babel/core vulnerable', fingerprint: 'a'.repeat(64) })],
      upgradeSteps: [step({ package_name: '@babel/core', ecosystem: 'npm',
        upgrade_command: 'npm install @babel/core@7.24.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.candidates[0]?.command).toBe('npm install @babel/core@7.24.0');
  });

  it('does not pair the unscoped "core" with a finding naming the scoped "@babel/core"', () => {
    // The mirror image of the scoped-match test: '/' must count as
    // continuing the token, not as a boundary that exposes "core" on its own.
    const groups = buildGroups({
      findings: [finding({ title: '@babel/core vulnerable', fingerprint: 'a'.repeat(64) })],
      upgradeSteps: [step({ package_name: 'core', ecosystem: 'npm',
        upgrade_command: 'npm install core@1.0.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('builds deps and semgrep groups together — the tool\'s actual default sources', () => {
    // No test above exercises sources: ['deps', 'semgrep'] together, which is
    // exactly what create_fix_pr passes when the caller does not override it.
    const groups = buildGroups({
      findings: [
        finding({ fingerprint: 'a'.repeat(64), title: 'lodash vulnerable' }),
        finding({ fingerprint: 'd'.repeat(64), tool: 'semgrep', rule_id: 'rule.one' }),
      ],
      upgradeSteps: [step()],
      sources: ['deps', 'semgrep'], severityMin: 'high',
    });
    expect(groups.map((g) => g.key).sort()).toEqual(['npm', 'semgrep']);
    const npmGroup = groups.find((g) => g.key === 'npm');
    const semgrepGroup = groups.find((g) => g.key === 'semgrep');
    expect(npmGroup?.candidates).toHaveLength(1);
    expect(semgrepGroup?.candidates).toHaveLength(1);
  });

  it('gives the same findings the same hash across runs, and different findings a different one', () => {
    // The branch name is derived from this. An unstable hash means a repeat run
    // cannot recognise its own earlier branch, and idempotency is gone.
    const args = {
      upgradeSteps: [step()], sources: ['deps'] as const, severityMin: 'high' as const,
    };
    const a = buildGroups({ findings: [finding({ fingerprint: 'a'.repeat(64) })], ...args });
    const b = buildGroups({ findings: [finding({ fingerprint: 'a'.repeat(64) })], ...args });
    const c = buildGroups({ findings: [finding({ fingerprint: 'c'.repeat(64) })], ...args });
    expect(a[0]?.hash).toBe(b[0]?.hash);
    expect(a[0]?.hash).not.toBe(c[0]?.hash);
    expect(a[0]?.hash).toMatch(/^[0-9a-f]{12}$/);
  });

  it('hashes the fingerprint SET, so ordering does not change the branch name', () => {
    const two = (order: string[]) => buildGroups({
      findings: order.map((f) => finding({ fingerprint: f })),
      upgradeSteps: [step(), step({ package_name: 'axios',
        upgrade_command: 'npm install axios@1.7.0' })],
      sources: ['deps'], severityMin: 'high',
    })[0]?.hash;
    expect(two(['a'.repeat(64), 'b'.repeat(64)]))
      .toBe(two(['b'.repeat(64), 'a'.repeat(64)]));
  });

  // --- Additional coverage: the semgrep path is exercised by none of the
  // tests above (`honours the sources filter` only proves a non-semgrep
  // finding is excluded when sources=['semgrep']; it never proves a real
  // semgrep finding is included). Design §2 and the brief's Step 4 both
  // describe this path explicitly, so it gets the same rigor as the deps path.

  it('groups semgrep findings into one group keyed "semgrep", with a null command', () => {
    const groups = buildGroups({
      findings: [finding({
        fingerprint: 'd'.repeat(64), tool: 'semgrep', rule_id: 'javascript.eqeq',
        title: 'use of ==', severity: 'medium',
      })],
      upgradeSteps: [],
      sources: ['semgrep'], severityMin: 'low',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.source).toBe('semgrep');
    expect(groups[0]?.key).toBe('semgrep');
    expect(groups[0]?.candidates[0]?.command).toBeNull();
    expect(groups[0]?.candidates[0]?.label).toBe('javascript.eqeq');
  });

  it('combines findings from different semgrep rules into one group, since one autofix pass covers all', () => {
    // The wrong implementation keys the group by rule id and produces one
    // group per rule, which would open one PR per rule instead of one per scanner.
    const groups = buildGroups({
      findings: [
        finding({ fingerprint: 'd'.repeat(64), tool: 'semgrep', rule_id: 'rule.one', severity: 'high' }),
        finding({ fingerprint: 'e'.repeat(64), tool: 'semgrep', rule_id: 'rule.two', severity: 'medium' }),
      ],
      upgradeSteps: [],
      sources: ['semgrep'], severityMin: 'low',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.candidates).toHaveLength(2);
    expect(groups[0]?.severity).toBe('high');
  });

  it('falls back to the title when rule_id is empty, not just when it is absent', () => {
    // `??` would let a '' rule_id through untouched, silently producing a
    // blank label. `||` treats an empty string the same as a missing one.
    const groups = buildGroups({
      findings: [finding({
        fingerprint: 'd'.repeat(64), tool: 'semgrep', rule_id: '',
        title: 'unsafe eval() call',
      })],
      upgradeSteps: [],
      sources: ['semgrep'], severityMin: 'low',
    });
    expect(groups[0]?.candidates[0]?.label).toBe('unsafe eval() call');
  });

  it('excludes a semgrep finding with fix_available false, even when other semgrep findings qualify', () => {
    // Guards the semgrep path independently of the deps-path equivalent test
    // above: fix_available === false must never reach a group, on either path.
    const groups = buildGroups({
      findings: [
        finding({ fingerprint: 'd'.repeat(64), tool: 'semgrep', rule_id: 'rule.one', fix_available: true }),
        finding({ fingerprint: 'e'.repeat(64), tool: 'semgrep', rule_id: 'rule.two', fix_available: false }),
      ],
      upgradeSteps: [],
      sources: ['semgrep'], severityMin: 'low',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.candidates).toHaveLength(1);
    expect(groups[0]?.candidates[0]?.fingerprints).toEqual(['d'.repeat(64)]);
  });
});

describe('selectGroups', () => {
  function group(key: string, severity: Finding['severity']) {
    return buildGroups({
      findings: [finding({ severity, fingerprint: key.padEnd(64, '0') })],
      upgradeSteps: [step({ ecosystem: key as UpgradeStep['ecosystem'] })],
      sources: ['deps'], severityMin: 'info',
    })[0];
  }

  it('orders by severity so the cap drops the least urgent, not an arbitrary slice', () => {
    const groups = [group('npm', 'low'), group('pip', 'critical')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 1);
    expect(sel.selected[0]?.key).toBe('pip');
  });

  it('names what the cap excluded instead of dropping it silently', () => {
    // A bounded output that does not say it is bounded reads as "this is
    // everything". The wrong implementation returns `selected` and nothing else.
    const groups = [group('npm', 'critical'), group('pip', 'high')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 1);
    expect(sel.deferred).toHaveLength(1);
    expect(sel.deferred[0]?.key).toBe('pip');
    expect(sel.deferred_reason).toMatch(/max_prs/);
  });

  it('reports no deferral when nothing was cut', () => {
    const groups = [group('npm', 'high')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 5);
    expect(sel.deferred).toEqual([]);
    expect(sel.deferred_reason).toBeNull();
  });
});
