/**
 * `fixpr/raise.ts` — what `create_fix_pr` does when the version it applied
 * resolves its targets and brings an advisory of its own.
 *
 * The plan installs the MINIMUM version that clears the active advisories of
 * a package. When that version has an advisory of its own, the verification
 * sees a new finding and refuses the pull request — rightly: trading one CVE
 * for another is not a fix. But the new finding says which version clears it
 * (`lodash@4.18.0->4.18.1`), and until this spec the answer was `not_verified`
 * with two counts. Measured 2026-11-14 with the real Trivy: lodash 4.17.20 →
 * 4.18.0 → refused; from 4.18.0 the same command opens the pull request for
 * 4.18.1.
 *
 * Two things are tested here, both without git, npm or a scanner: the
 * decision (`decideRaise`, pure) and the cycle (`verifyWithRaises`), which is
 * handed "run one round of this group" and "plan again with these fixed
 * versions" as functions.
 */
import { describe, expect, it } from 'vitest';

import { decideRaise, describeStop, MAX_RAISES, verifyWithRaises, type Round } from '../../../src/fixpr/raise.js';
import type { FixGroup, ScanVerdict, UpgradeStep } from '../../../src/fixpr/types.js';
import type { Finding } from '../../../src/types.js';

function step(name: string, from: string, to: string, ecosystem: UpgradeStep['ecosystem'] = 'npm'): UpgradeStep {
  return {
    package_name: name,
    installed_version: from,
    latest_version: to,
    classification: 'security',
    ecosystem,
    upgrade_command: `npm install ${name}@${to} --ignore-scripts --package-lock-only`,
  };
}

/** A deps group of one candidate per step; its hash is a function of the fingerprints, as `candidates.ts` makes it. */
function group(steps: readonly UpgradeStep[], fingerprints: readonly string[] = ['fp-target-1']): FixGroup {
  return {
    source: 'deps',
    key: 'npm',
    severity: 'high',
    hash: `hash-of-${[...fingerprints].sort().join('+')}`,
    candidates: steps.map((s, i) => ({
      source: 'deps',
      fingerprints: i === 0 ? [...fingerprints] : [],
      severity: 'high',
      command: s.upgrade_command,
      label: `${s.package_name} ${s.installed_version} -> ${s.latest_version}`,
      steps: [s],
    })),
  };
}

/** A dependency finding as Trivy's parser writes it: the package, its version and the fixed version in the snippet, no line. */
function dep(fingerprint: string, advisory: string, pkg: string, version: string, fixed: string, over: Partial<Finding> = {}): Finding {
  return {
    fingerprint,
    tool: 'trivy',
    rule_id: advisory,
    severity: 'medium',
    category: 'security',
    subcategory: 'cve',
    title: `${pkg}: ${advisory}`,
    message: advisory,
    file_path: 'package-lock.json',
    snippet: `${pkg}@${version}->${fixed}`,
    fix_available: fixed !== '',
    ...over,
  };
}

const failed = (after: readonly Finding[], still: readonly string[] = []): ScanVerdict => ({
  passed: false,
  resolved: still.length === 0 ? ['fp-target-1'] : [],
  still_present: [...still],
  new_findings: after.map((f) => ({ fingerprint: f.fingerprint, severity: f.severity, title: f.title })),
});
const passed: ScanVerdict = { passed: true, resolved: ['fp-target-1'], still_present: [], new_findings: [] };

const LODASH_4180 = group([step('lodash', '4.17.20', '4.18.0')]);
const NEW_IN_4180 = dep('fp-new-1', 'CVE-2026-2950', 'lodash', '4.18.0', '4.18.1');

describe('decideRaise — whether the new findings of a failed verification justify a higher target', () => {
  it('T-01 no target left and one new dependency finding on the package at the version applied, with a fixed version: raise that package', () => {
    const d = decideRaise({ group: LODASH_4180, verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] });
    expect(d).toEqual({
      kind: 'raise',
      raises: [{ package_name: 'lodash', planned_version: '4.18.0', fixed_versions: ['4.18.1'], advisories: ['CVE-2026-2950'] }],
    });
  });

  it.each<[string, Finding, readonly string[], RegExp]>([
    ['a target is still present', NEW_IN_4180, ['fp-target-1'], /still present/],
    ['a new finding in source code (it has a line)', { ...NEW_IN_4180, tool: 'semgrep', subcategory: 'injection', line_start: 12, file_path: 'src/a.js', snippet: 'eval(x)' }, [], /not a dependency/],
    ['a new dependency finding on ANOTHER package', dep('fp-new-2', 'CVE-2026-1111', 'minimist', '1.2.5', '1.2.6'), [], /minimist.*not (?:one )?this fix upgraded/],
    ['a new finding on the package at a version that is not the one applied', dep('fp-new-3', 'CVE-2026-2222', 'lodash', '4.17.20', '4.17.21'), [], /lodash@4\.17\.20.*not the version/],
    ['an advisory with no fixed version', dep('fp-new-4', 'CVE-2026-3333', 'lodash', '4.18.0', ''), [], /no fixed version/],
  ])('T-02 no raise when %s, and the reason says so', (_what, finding, still, reason) => {
    const d = decideRaise({ group: LODASH_4180, verdict: failed([finding], still), after: [finding] });
    expect(d.kind).toBe('stop');
    expect(d.kind === 'stop' ? d.reason : '').toMatch(reason);
  });

  it('T-02 one raisable finding beside one that is not: no raise at all, and both are named for the note', () => {
    const other = dep('fp-new-2', 'CVE-2026-1111', 'minimist', '1.2.5', '1.2.6');
    const d = decideRaise({ group: LODASH_4180, verdict: failed([NEW_IN_4180, other]), after: [NEW_IN_4180, other] });
    expect(d.kind).toBe('stop');
    expect(d.kind === 'stop' ? d.blocking : []).toEqual([
      { package_name: 'lodash', version: '4.18.0', advisory: 'CVE-2026-2950', fixed_version: '4.18.1' },
      { package_name: 'minimist', version: '1.2.5', advisory: 'CVE-2026-1111', fixed_version: '1.2.6' },
    ]);
  });

  it('T-03 the version that clears it is in the next major: no raise, and the reason names the package, that version and the advisory', () => {
    const next = dep('fp-new-5', 'CVE-2026-4444', 'lodash', '4.18.0', '5.0.1');
    const d = decideRaise({ group: LODASH_4180, verdict: failed([next]), after: [next] });
    expect(d.kind).toBe('stop');
    const reason = d.kind === 'stop' ? d.reason : '';
    expect(reason).toMatch(/lodash/);
    expect(reason).toMatch(/5\.0\.1/);
    expect(reason).toMatch(/CVE-2026-4444/);
    expect(reason).toMatch(/major/);
  });

  it('T-04 two packages of the group with a new finding each: both raised in one decision; two advisories on one package: one raise, both named', () => {
    const two = group([step('lodash', '4.17.20', '4.18.0'), step('minimist', '1.2.0', '1.2.5')]);
    const a = NEW_IN_4180;
    const b = dep('fp-new-2', 'CVE-2026-1111', 'minimist', '1.2.5', '1.2.6');
    const c = dep('fp-new-6', 'CVE-2026-5555', 'lodash', '4.18.0', '4.18.2');
    const d = decideRaise({ group: two, verdict: failed([a, b, c]), after: [a, b, c] });
    expect(d).toEqual({
      kind: 'raise',
      raises: [
        { package_name: 'lodash', planned_version: '4.18.0', fixed_versions: ['4.18.1', '4.18.2'], advisories: ['CVE-2026-2950', 'CVE-2026-5555'] },
        { package_name: 'minimist', planned_version: '1.2.5', fixed_versions: ['1.2.6'], advisories: ['CVE-2026-1111'] },
      ],
    });
  });

  it.each(['4.17.12, 5.0.0', '>=4.18.1', 'latest'])('T-04 a fixed version that is no single installable version (%s) is read as the plan reads it: no version, no raise', (fixed) => {
    const messy = dep('fp-new-7', 'CVE-2026-6666', 'lodash', '4.18.0', fixed);
    const d = decideRaise({ group: LODASH_4180, verdict: failed([messy]), after: [messy] });
    expect(d.kind).toBe('stop');
    expect(d.kind === 'stop' ? d.reason : '').toMatch(/no (?:installable|single) version/);
  });

  it('T-05 whatever else the verification found, one finding that cannot be raised means no raise (200 generated sets)', () => {
    // A small generator with a fixed seed: every set has at least one finding of a kind that never justifies a raise.
    let seed = 20261115;
    const next = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const raisable = (i: number): Finding => dep(`fp-ok-${i}`, `CVE-2026-9${i}`, 'lodash', '4.18.0', `4.18.${1 + next(5)}`);
    const never: Array<(i: number) => Finding> = [
      (i) => dep(`fp-other-${i}`, `CVE-2026-8${i}`, `other-${next(9)}`, '1.0.0', '1.0.1'),
      (i) => dep(`fp-old-${i}`, `CVE-2026-7${i}`, 'lodash', '4.17.20', '4.17.21'),
      (i) => dep(`fp-nofix-${i}`, `CVE-2026-6${i}`, 'lodash', '4.18.0', ''),
      (i) => dep(`fp-major-${i}`, `CVE-2026-5${i}`, 'lodash', '4.18.0', `${5 + next(3)}.0.0`),
      (i) => ({ ...dep(`fp-src-${i}`, 'js.rule', 'lodash', '4.18.0', '4.18.1'), tool: 'semgrep', line_start: 1 + next(90), snippet: 'x' }),
    ];
    for (let run = 0; run < 200; run += 1) {
      const set: Finding[] = Array.from({ length: next(4) }, (_, i) => raisable(i));
      const bad = never[next(never.length)];
      if (bad === undefined) throw new Error('unreachable');
      set.splice(next(set.length + 1), 0, bad(run));
      const d = decideRaise({ group: LODASH_4180, verdict: failed(set), after: set });
      expect({ run, kind: d.kind }).toEqual({ run, kind: 'stop' });
    }
  });
});

/** A scripted round runner: answers the rounds in order and records the groups it was handed. */
function rounds(script: ReadonlyArray<Round<string>>): { run: (g: FixGroup) => Promise<Round<string>>; seen: FixGroup[] } {
  const seen: FixGroup[] = [];
  let i = 0;
  const run = async (g: FixGroup): Promise<Round<string>> => {
    seen.push(g);
    const r = script[i];
    i += 1;
    if (r === undefined) throw new Error(`round ${i} was not scripted`);
    return r;
  };
  return { run, seen };
}

/** A re-planner that raises lodash to the highest fixed version it is given, keeping the group's identity. */
function replanner(base: FixGroup): { replan: (extra: ReadonlyMap<string, readonly string[]>) => Promise<FixGroup>; asked: Array<Record<string, readonly string[]>> } {
  const asked: Array<Record<string, readonly string[]>> = [];
  const replan = async (extra: ReadonlyMap<string, readonly string[]>): Promise<FixGroup> => {
    asked.push(Object.fromEntries(extra));
    const top = [...(extra.get('lodash') ?? [])].sort().at(-1) ?? '4.18.0';
    return { ...group([step('lodash', '4.17.20', top)]), hash: base.hash };
  };
  return { replan, asked };
}

describe('verifyWithRaises — the cycle: at most two raises, and the last round\'s result', () => {
  it('T-07 the first round fails with a raisable finding and the second passes: the SECOND round\'s result, what was raised and why, one re-plan', async () => {
    const script = rounds([
      { result: 'round 1: not_verified', verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] },
      { result: 'round 2: verified', verdict: passed, after: [] },
    ]);
    const plan = replanner(LODASH_4180);
    const out = await verifyWithRaises({ group: LODASH_4180, runRound: script.run, replan: plan.replan });
    expect(out.result).toBe('round 2: verified');
    expect(out.rounds).toBe(2);
    expect(out.stopped).toBeNull();
    expect(out.raised).toEqual([{ package_name: 'lodash', planned_version: '4.18.0', applied_version: '4.18.1', advisories: ['CVE-2026-2950'] }]);
    expect(plan.asked).toEqual([{ lodash: ['4.18.1'] }]);
    // The second round ran the re-planned group, not the first one again.
    expect(script.seen.map((g) => g.candidates[0]?.steps?.[0]?.latest_version)).toEqual(['4.18.0', '4.18.1']);
  });

  it('T-08 a raisable finding in every round: two raises and no third — the THIRD round\'s result, the limit said, and the finding that is left', async () => {
    expect(MAX_RAISES).toBe(2);
    const second = dep('fp-new-8', 'CVE-2026-7777', 'lodash', '4.18.1', '4.18.2');
    const third = dep('fp-new-9', 'CVE-2026-8888', 'lodash', '4.18.2', '4.18.3');
    const script = rounds([
      { result: 'round 1', verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] },
      { result: 'round 2', verdict: failed([second]), after: [second] },
      { result: 'round 3', verdict: failed([third]), after: [third] },
    ]);
    const plan = replanner(LODASH_4180);
    const out = await verifyWithRaises({ group: LODASH_4180, runRound: script.run, replan: plan.replan });
    expect(out.result).toBe('round 3');
    expect(out.rounds).toBe(3);
    expect(out.stopped).toMatch(/2 raises/);
    expect(out.blocking).toEqual([{ package_name: 'lodash', version: '4.18.2', advisory: 'CVE-2026-8888', fixed_version: '4.18.3' }]);
    // Each re-plan is told everything learned so far, not only the last round's.
    expect(plan.asked).toEqual([{ lodash: ['4.18.1'] }, { lodash: ['4.18.1', '4.18.2'] }]);
    expect(out.raised).toEqual([]);
    // What the group's note adds: the finding by package, version, advisory and fixed version, then why it stopped.
    expect(describeStop(out, true)).toBe(`. New: lodash@4.18.2: CVE-2026-8888 (fixed in 4.18.3). Target not raised: ${out.stopped ?? ''}`);
  });

  it('T-09 a new finding that cannot be raised, and the major boundary: one round, no re-plan, and the reason and the finding are handed back', async () => {
    const other = dep('fp-new-2', 'CVE-2026-1111', 'minimist', '1.2.5', '1.2.6');
    const major = dep('fp-new-5', 'CVE-2026-4444', 'lodash', '4.18.0', '5.0.1');
    for (const finding of [other, major]) {
      const script = rounds([{ result: 'round 1', verdict: failed([finding]), after: [finding] }]);
      const plan = replanner(LODASH_4180);
      const out = await verifyWithRaises({ group: LODASH_4180, runRound: script.run, replan: plan.replan });
      expect(out.result).toBe('round 1');
      expect(out.rounds).toBe(1);
      expect(plan.asked).toEqual([]);
      expect(out.stopped).not.toBeNull();
      expect(out.blocking).toHaveLength(1);
      expect(out.blocking[0]?.advisory).toBe(finding.rule_id);
      const said = describeStop(out, true);
      expect(said).toContain(finding === other ? 'minimist@1.2.5: CVE-2026-1111 (fixed in 1.2.6)' : 'lodash@4.18.0: CVE-2026-4444 (fixed in 5.0.1)');
      expect(said).toContain(`Target not raised: ${out.stopped ?? ''}`);
      if (finding === major) expect(said).toMatch(/major/);
    }
    // An advisory with no fix is named without one.
    const noFix = dep('fp-new-4', 'CVE-2026-3333', 'lodash', '4.18.0', '');
    const out = await verifyWithRaises({
      group: LODASH_4180,
      runRound: rounds([{ result: 'round 1', verdict: failed([noFix]), after: [noFix] }]).run,
      replan: replanner(LODASH_4180).replan,
    });
    expect(describeStop(out, true).startsWith('. New: lodash@4.18.0: CVE-2026-3333. Target not raised: ')).toBe(true);
  });

  it('T-10 the re-planned group must be the same group — same hash, which is a function of the fingerprints and not of the steps: another one is refused', async () => {
    const script = rounds([
      { result: 'round 1', verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] },
      { result: 'round 2', verdict: passed, after: [] },
    ]);
    const out = await verifyWithRaises({
      group: LODASH_4180,
      runRound: script.run,
      replan: async () => ({ ...group([step('lodash', '4.17.20', '4.18.1')]), hash: 'another-group' }),
    });
    expect(out.result).toBe('round 1');
    expect(out.rounds).toBe(1);
    expect(out.stopped).toMatch(/not the same group/);
  });

  it('T-11 a second round that ends before the differential, a re-plan that fails, and a round that throws', async () => {
    // The raised round could not be applied: ITS result, and the raise it was trying is said.
    const applyFailed = rounds([
      { result: 'round 1', verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] },
      { result: 'round 2: apply_failed', verdict: null, after: [] },
    ]);
    const a = await verifyWithRaises({ group: LODASH_4180, runRound: applyFailed.run, replan: replanner(LODASH_4180).replan });
    expect(a.result).toBe('round 2: apply_failed');
    expect(a.stopped).toMatch(/lodash.*4\.18\.1/);
    expect(a.raised).toEqual([]);
    expect(describeStop(a, false)).toBe(` (${a.stopped ?? ''})`);

    // The plan could not be made again: the round before stands, with why.
    const noPlan = rounds([{ result: 'round 1', verdict: failed([NEW_IN_4180]), after: [NEW_IN_4180] }]);
    const b = await verifyWithRaises({ group: LODASH_4180, runRound: noPlan.run, replan: async () => ({ failed: 'npm outdated timed out' }) });
    expect(b.result).toBe('round 1');
    expect(b.rounds).toBe(1);
    expect(b.stopped).toMatch(/npm outdated timed out/);

    // A round that throws (a cancelled request) is not run again.
    let calls = 0;
    const thrown = verifyWithRaises({
      group: LODASH_4180,
      runRound: async () => {
        calls += 1;
        throw new Error('cancelled');
      },
      replan: replanner(LODASH_4180).replan,
    });
    await expect(thrown).rejects.toThrow('cancelled');
    expect(calls).toBe(1);
  });

  it('T-12 a first round that passes: one round, no re-plan, its result as it is, nothing raised', async () => {
    const script = rounds([{ result: 'round 1: verified', verdict: passed, after: [] }]);
    const plan = replanner(LODASH_4180);
    const out = await verifyWithRaises({ group: LODASH_4180, runRound: script.run, replan: plan.replan });
    expect(out).toEqual({ result: 'round 1: verified', raised: [], stopped: null, blocking: [], rounds: 1 });
    expect(describeStop(out, true)).toBe('');
    expect(plan.asked).toEqual([]);
    expect(script.seen).toEqual([LODASH_4180]);
  });

  it('T-12 a first round that ends before the differential (refused, apply_failed): its result, and no decision is attempted', async () => {
    const script = rounds([{ result: 'round 1: refused', verdict: null, after: [] }]);
    const out = await verifyWithRaises({ group: LODASH_4180, runRound: script.run, replan: replanner(LODASH_4180).replan });
    expect(out).toEqual({ result: 'round 1: refused', raised: [], stopped: null, blocking: [], rounds: 1 });
    expect(describeStop(out, false)).toBe('');
  });
});
