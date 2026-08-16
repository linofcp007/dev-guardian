import { describe, expect, it } from 'vitest';
import { judgeScan, judgeTests, mayOpenPr } from '../../../src/fixpr/verify.js';
import type { Finding } from '../../../src/types.js';

function f(fingerprint: string, over: Partial<Finding> = {}): Finding {
  return {
    fingerprint, tool: 'trivy', rule_id: 'r', severity: 'high', category: 'security',
    subcategory: null, title: 't', message: 'm', file_path: 'p', line_start: 1,
    line_end: 1, snippet: null, fix_available: true, fix_applied: false, raw: {},
    ...over,
  } as unknown as Finding;
}

const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64);

describe('judgeScan', () => {
  it('passes when the target is gone and nothing new appeared', () => {
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A), f(B)] },
      { scan_id: 'after', findings: [f(B)] });
    expect(v.passed).toBe(true);
    expect(v.resolved).toEqual([A]);
    expect(v.new_findings).toEqual([]);
  });

  it('FAILS when the target went away but something new arrived', () => {
    // The heart of the design. A bump that trades CVE-A for CVE-B is not a fix,
    // and the wrong implementation only checks that the target is resolved.
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A)] },
      { scan_id: 'after', findings: [f(C, { title: 'new CVE' })] });
    expect(v.passed).toBe(false);
    expect(v.new_findings).toEqual([
      { fingerprint: C, severity: 'high', title: 'new CVE' },
    ]);
  });

  it('fails when the target is still present', () => {
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A)] },
      { scan_id: 'after', findings: [f(A)] });
    expect(v.passed).toBe(false);
    expect(v.still_present).toEqual([A]);
  });

  it('requires every target to be resolved, not just one of them', () => {
    const v = judgeScan([A, B],
      { scan_id: 'before', findings: [f(A), f(B)] },
      { scan_id: 'after', findings: [f(B)] });
    expect(v.passed).toBe(false);
    expect(v.still_present).toEqual([B]);
  });

  // --- Additional coverage beyond the brief -------------------------------
  //
  // The brief's own fixtures never separate "disappeared" from "was a
  // target": in every one of its four cases, the only fingerprint that goes
  // away is also the only target. That leaves scoping and the truncation cap
  // untested — both real gaps given design §4.1's insistence that this
  // differential must never quietly understate what it finds.

  it('scopes `resolved` to the given targets, not every fingerprint that disappeared', () => {
    // A wrong implementation might report every fingerprint present in
    // `before` but absent from `after` — mirroring compareFindings's own
    // resolved_count — instead of filtering that by `targets`. C disappears
    // here too but was never a target, so it must not show up in `resolved`.
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A), f(B), f(C)] },
      { scan_id: 'after', findings: [f(B)] });
    expect(v.resolved).toEqual([A]);
  });

  it('never truncates new_findings, however many appear', () => {
    // compareFindings supports a cap (the dashboard caps at 500); the brief's
    // own "something new arrived" test uses exactly one new finding, which
    // cannot tell an uncapped call apart from one accidentally capped at 1.
    // judgeScan must call compareFindings with an effectively infinite cap —
    // the scan differential's whole point is to never understate new findings.
    const news = [
      f('1'.repeat(64), { title: 'n1' }),
      f('2'.repeat(64), { title: 'n2' }),
      f('3'.repeat(64), { title: 'n3' }),
      f('4'.repeat(64), { title: 'n4' }),
    ];
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A)] },
      { scan_id: 'after', findings: news });
    expect(v.new_findings.map((n) => n.fingerprint)).toEqual([
      '1'.repeat(64), '2'.repeat(64), '3'.repeat(64), '4'.repeat(64),
    ]);
    expect(v.passed).toBe(false);
  });
});

describe('judgeTests', () => {
  function fakeRun(results: { outcome: string; exitCode: number | null; stdout?: string }[]) {
    const calls: string[] = [];
    let i = 0;
    const run = async (opts: { command: string; cwd: string }) => {
      calls.push(opts.cwd);
      const next = results[i++] ?? { outcome: 'completed', exitCode: 0 };
      return { outcome: next.outcome, exitCode: next.exitCode,
        stdout: next.stdout ?? '', stderr: '', truncated: false };
    };
    return { run: run as never, calls };
  }

  const derived = { command: 'npm', args: ['test', '--silent'],
    origin: 'package.json scripts.test' };

  it('is not_run when no command could be derived', async () => {
    const v = await judgeTests({ derived: null, worktreePath: '/w',
      projectPath: '/p', run: fakeRun([]).run });
    expect(v.outcome).toBe('not_run');
    expect(v.command).toBeNull();
  });

  it('passes without ever touching the base commit', async () => {
    // The laziness is the point: the second run costs minutes and is only
    // needed to assign blame for a failure that has not happened.
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('passed');
    expect(calls).toEqual(['/w']);
  });

  it('blames the fix only after checking the base commit was green', async () => {
    const { run, calls } = fakeRun([
      { outcome: 'failed', exitCode: 1, stdout: '3 failing\n' },   // worktree
      { outcome: 'completed', exitCode: 0 },                        // base
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('broken_by_fix');
    expect(calls).toEqual(['/w', '/p']);
    expect(v.output_head).toContain('3 failing');
  });

  it('does NOT blame the fix when the base commit was already red', async () => {
    // Otherwise every project with a pre-existing failure has our fix blamed
    // for it, and the report is worse than useless.
    const { run } = fakeRun([
      { outcome: 'failed', exitCode: 1 },
      { outcome: 'failed', exitCode: 1 },
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('already_failing');
  });

  it('treats a timed-out suite as broken_by_fix only if the base completed', async () => {
    const { run } = fakeRun([
      { outcome: 'timed_out', exitCode: null },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('broken_by_fix');
  });

  // --- Additional coverage beyond the brief -------------------------------
  //
  // The brief's own failing-worktree fixtures all set outcome: 'failed'
  // explicitly, never outcome: 'completed' with a non-zero exitCode, and its
  // not_run test never asserts that `run` was left untouched or that `origin`
  // is nulled out alongside `command`. Those are exactly the falsy-vs-absent
  // and outcome-vs-exitCode shapes this project has been bitten by before
  // ("exitCode of 0 is exactly that shape" — five prior `??` incidents).

  it('never calls run at all when no command was derived', async () => {
    const { run, calls } = fakeRun([]);
    const v = await judgeTests({ derived: null, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('not_run');
    expect(calls).toEqual([]);
  });

  it('nulls out origin too, not just command, when not_run', async () => {
    const v = await judgeTests({ derived: null, worktreePath: '/w',
      projectPath: '/p', run: fakeRun([]).run });
    expect(v.origin).toBeNull();
    expect(v.output_head).toBeNull();
  });

  it('treats a completed run with a non-zero exit code as a failure, not just a non-completed outcome', async () => {
    // A wrong implementation might gate the base-commit check on
    // `outcome !== 'completed'` alone (or on `!exitCode`, which is also wrong
    // since 0 is falsy) and miss a test runner that exits non-zero while
    // runProcess still reports 'completed'. Every scripted failure in the
    // brief's own tests already carries outcome: 'failed', so that mistake
    // would sail through unnoticed there.
    const { run, calls } = fakeRun([
      { outcome: 'completed', exitCode: 2, stdout: '2 failing\n' },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('broken_by_fix');
    expect(calls).toEqual(['/w', '/p']);
  });

  it('leaves command/origin populated and output_head null on a passing run', async () => {
    const { run } = fakeRun([{ outcome: 'completed', exitCode: 0, stdout: 'ok\n' }]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.command).toBe('npm test --silent');
    expect(v.origin).toBe('package.json scripts.test');
    expect(v.output_head).toBeNull();
  });

  it('forwards timeoutMs to every run call, not only the worktree one', async () => {
    const seen: (number | undefined)[] = [];
    const run = async (opts: { command: string; args?: string[]; cwd: string; timeoutMs?: number }) => {
      seen.push(opts.timeoutMs);
      return seen.length === 1
        ? { outcome: 'failed', exitCode: 1, stdout: '', stderr: '', truncated: false }
        : { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    };
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p',
      run: run as never, timeoutMs: 5_000 });
    expect(v.outcome).toBe('broken_by_fix');
    expect(seen).toEqual([5_000, 5_000]);
  });
});

describe('mayOpenPr', () => {
  const okScan = { passed: true, resolved: [A], still_present: [], new_findings: [] };
  const badScan = { passed: false, resolved: [], still_present: [A], new_findings: [] };
  const t = (outcome: 'passed'|'broken_by_fix'|'already_failing'|'not_run') =>
    ({ outcome, command: null, origin: null, output_head: null });

  it('opens on a passing scan with passing, absent, or pre-existing-failing tests', () => {
    expect(mayOpenPr(okScan, t('passed'))).toBe(true);
    expect(mayOpenPr(okScan, t('not_run'))).toBe(true);
    expect(mayOpenPr(okScan, t('already_failing'))).toBe(true);
  });

  it('never opens when the fix broke the tests', () => {
    expect(mayOpenPr(okScan, t('broken_by_fix'))).toBe(false);
  });

  it('never opens when the scan differential failed, whatever the tests say', () => {
    expect(mayOpenPr(badScan, t('passed'))).toBe(false);
    expect(mayOpenPr(badScan, t('not_run'))).toBe(false);
  });

  // --- Additional coverage beyond the brief -------------------------------

  it('still refuses when a new finding appeared even though every target resolved', () => {
    // Guards a `mayOpenPr` that inlines `still_present.length === 0` instead
    // of reading `scan.passed` — in okScan/badScan above the two always
    // agree, so neither existing fixture can catch that substitution. This
    // is the "traded CVE-A for CVE-B" case reaching the gate itself, not
    // just judgeScan.
    const newFindingScan = { passed: false, resolved: [A], still_present: [],
      new_findings: [{ fingerprint: C, severity: 'high', title: 'new CVE' }] };
    expect(mayOpenPr(newFindingScan, t('passed'))).toBe(false);
  });

  it('never opens when the scan failed AND the tests broke, whatever order you check them in', () => {
    expect(mayOpenPr(badScan, t('broken_by_fix'))).toBe(false);
    expect(mayOpenPr(badScan, t('already_failing'))).toBe(false);
  });
});
