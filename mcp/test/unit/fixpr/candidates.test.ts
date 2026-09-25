import { describe, expect, it } from 'vitest';
import { buildGroups, selectGroups } from '../../../src/fixpr/candidates.js';
import type { UpgradeStep } from '../../../src/fixpr/types.js';
import type { Finding } from '../../../src/types.js';

/**
 * A dependency finding shaped the way the scanners write one: Trivy's
 * `pkg@installed->fixed` snippet, no line, the lockfile as its file. That
 * snippet is the STRUCTURED package field (`dependencyCoordinates`) pairing
 * reads — never the title or the advisory text.
 */
function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'f'.repeat(64), tool: 'trivy', rule_id: 'CVE-2021-1',
    severity: 'high', category: 'security', subcategory: 'cve',
    title: 'lodash vulnerable', message: 'm', file_path: 'package-lock.json',
    snippet: 'lodash@4.17.20->4.17.21',
    fix_available: true, fix_applied: false, raw: {},
    ...over,
  } as unknown as Finding;
}

function dep(pkg: string, over: Partial<Finding> = {}): Finding {
  return finding({ title: `${pkg} vulnerable`, snippet: `${pkg}@1.0.0->1.0.1`, ...over });
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
  it('pairs a dependency finding with its upgrade step and carries the step itself', () => {
    const groups = buildGroups({
      findings: [finding()],
      upgradeSteps: [step()],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.key).toBe('npm');
    expect(groups[0]?.candidates[0]?.command).toBe('npm install lodash@4.17.21');
    expect(groups[0]?.candidates[0]?.steps).toEqual([step()]);
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
        dep('lodash', { fingerprint: 'a'.repeat(64) }),
        dep('requests', { fingerprint: 'b'.repeat(64), file_path: 'requirements.txt' }),
      ],
      upgradeSteps: [
        step(),
        step({ package_name: 'requests', ecosystem: 'pip', file: 'requirements.txt',
          upgrade_command: 'pip-pin requirements.txt requests==2.32.0' }),
      ],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups.map((g) => g.key).sort()).toEqual(['npm', 'pip']);
  });

  // --- Structured pairing (Task 11 item 3). Pairing by whole-word matches in
  // titles and NVD text applied the WRONG package's upgrade: npm advisories
  // routinely name other packages ("…like `ms`…", "…`once`…"), and the first
  // step whose name appeared anywhere in the text won.

  it('never pairs by the advisory text: a `send` finding whose text mentions ms and once gets send\'s step only', () => {
    const f = dep('send', {
      title: 'send vulnerable to template injection (ms, once) — CVE-2024-43799',
      message: 'Passing untrusted input to SendStream.redirect() may execute code; ms and once are unaffected.',
    });
    const groups = buildGroups({
      findings: [f],
      upgradeSteps: [
        step({ package_name: 'ms', upgrade_command: 'npm install ms@2.1.3' }),
        step({ package_name: 'once', upgrade_command: 'npm install once@1.4.0' }),
        step({ package_name: 'send', upgrade_command: 'npm install send@0.19.0' }),
      ],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.candidates.map((c) => c.command)).toEqual(['npm install send@0.19.0']);
  });

  it('never pairs a finding whose title names the package but whose structured package is another', () => {
    const groups = buildGroups({
      findings: [dep('lodash.merge', { title: 'lodash vulnerable' })],
      upgradeSteps: [step()], // package_name: 'lodash'
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('does not pair "request" with a finding about the different package "requests"', () => {
    const groups = buildGroups({
      findings: [dep('requests')],
      upgradeSteps: [step({ package_name: 'request', upgrade_command: 'npm install request@2.88.2' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('does not pair "axios" with a finding about the different package "axios-retry"', () => {
    const groups = buildGroups({
      findings: [dep('axios-retry')],
      upgradeSteps: [step({ package_name: 'axios', upgrade_command: 'npm install axios@1.7.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('matches a scoped npm package name whole, and never its unscoped tail', () => {
    const scoped = buildGroups({
      findings: [dep('@babel/core')],
      upgradeSteps: [step({ package_name: '@babel/core', upgrade_command: 'npm install @babel/core@7.24.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(scoped[0]?.candidates[0]?.command).toBe('npm install @babel/core@7.24.0');
    const tail = buildGroups({
      findings: [dep('@babel/core')],
      upgradeSteps: [step({ package_name: 'core', upgrade_command: 'npm install core@1.0.0' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(tail).toEqual([]);
  });

  it('never pairs across ecosystems: a pip `debug` finding does not take the npm `debug` step', () => {
    const groups = buildGroups({
      findings: [dep('debug', { file_path: 'requirements.txt' })],
      upgradeSteps: [step({ package_name: 'debug', upgrade_command: 'npm install debug@4.3.7' })],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('compares pip names the way pip does (PEP 503), and applies every step planned for the package', () => {
    const groups = buildGroups({
      findings: [dep('PyYAML', { file_path: 'requirements.txt', tool: 'pip-audit', subcategory: 'dependency', snippet: 'PyYAML@5.3' })],
      upgradeSteps: [
        step({ package_name: 'pyyaml', ecosystem: 'pip', file: 'requirements.txt', installed_version: '5.3',
          latest_version: '5.4', upgrade_command: 'pip-pin requirements.txt pyyaml==5.4' }),
        step({ package_name: 'PyYaml', ecosystem: 'pip', file: 'requirements-dev.txt', installed_version: '5.3',
          latest_version: '5.4', upgrade_command: 'pip-pin requirements-dev.txt PyYaml==5.4' }),
      ],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups[0]?.key).toBe('pip');
    expect(groups[0]?.candidates[0]?.steps?.map((s) => s.file)).toEqual(['requirements.txt', 'requirements-dev.txt']);
  });

  it('never pairs a WPScan component (no package ecosystem this tool can upgrade)', () => {
    const groups = buildGroups({
      findings: [finding({ tool: 'wpscan', subcategory: 'wordpress-plugin', snippet: 'component:lodash@1.0', file_path: 'lodash' })],
      upgradeSteps: [step()],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('leaves out a finding the verification cannot re-scan, when told which those are', () => {
    const groups = buildGroups({
      findings: [finding()],
      upgradeSteps: [step()],
      sources: ['deps'], severityMin: 'high',
      rescannable: () => false,
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
      findings: [finding({
        severity, fingerprint: key.padEnd(64, '0'),
        file_path: key === 'pip' ? 'requirements.txt' : 'package-lock.json',
      })],
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
