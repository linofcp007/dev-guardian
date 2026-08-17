import { describe, expect, it } from 'vitest';
import { applyGroup } from '../../../src/fixpr/apply.js';
import type { FixGroup } from '../../../src/fixpr/types.js';

function group(over: Partial<FixGroup> = {}): FixGroup {
  return {
    source: 'deps', key: 'npm', severity: 'high', hash: 'abc123def456',
    candidates: [{ source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
      command: 'npm install lodash@4.17.21', label: 'lodash 4.17.20 -> 4.17.21' }],
    ...over,
  };
}

function fakeRun(script: { outcome: string; exitCode: number | null; stderr?: string }[]) {
  // `cwd` is captured alongside `command`/`args` — it is the entire isolation
  // mechanism (worktreePath, never the real project directory), not
  // incidental plumbing, so every call site's test can assert it.
  const calls: { command: string; args: string[]; cwd: string }[] = [];
  let i = 0;
  const run = async (opts: { command: string; args?: string[]; cwd: string }) => {
    calls.push({ command: opts.command, args: opts.args ?? [], cwd: opts.cwd });
    const next = script[i++] ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: next.outcome, exitCode: next.exitCode,
      stdout: '', stderr: next.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('applyGroup', () => {
  it('splits the pinned upgrade command into argv — never through a shell', () => {
    // `runProcess` is shell:false, so a command string must be split. A version
    // string is attacker-influenced input in the sense that it comes from a
    // registry; it must never be interpolated into a command line.
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    return applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false })
      .then((r) => {
        expect(r.applied).toBe(true);
        expect(calls[0]?.command).toBe('npm');
        expect(calls[0]?.args).toEqual(['install', 'lodash@4.17.21']);
        // The isolation property, not incidental plumbing: this MUST run in
        // the worktree, never in the caller's real project directory. Nothing
        // else in this file asserted it before now.
        expect(calls[0]?.cwd).toBe('/w');
      });
  });

  it('adds --package-lock-only when no test command exists, and not otherwise', async () => {
    const a = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: a.run, lockfileOnly: true });
    expect(a.calls[0]?.args).toContain('--package-lock-only');

    const b = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: b.run, lockfileOnly: false });
    expect(b.calls[0]?.args).not.toContain('--package-lock-only');
  });

  it('runs one semgrep --autofix pass for the whole group, not one per finding', async () => {
    const g = group({
      source: 'semgrep', key: 'semgrep',
      candidates: [
        { source: 'semgrep', fingerprints: ['a'.repeat(64)], severity: 'high',
          command: null, label: 'rule.one' },
        { source: 'semgrep', fingerprints: ['b'.repeat(64)], severity: 'high',
          command: null, label: 'rule.two' },
      ],
    });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toBe('semgrep');
    expect(calls[0]?.args).toContain('--autofix');
    // Same isolation property as the deps call site, asserted independently:
    // `--autofix` rewrites files in place, so running it anywhere but the
    // worktree would rewrite the user's real project.
    expect(calls[0]?.cwd).toBe('/w');
  });

  it('reports the failing command, not just "failed"', async () => {
    // "The fix failed" sends the reader nowhere. The command, the outcome, the
    // exit code and the first stderr line send them somewhere.
    const { run } = fakeRun([{ outcome: 'failed', exitCode: 1,
      stderr: 'npm ERR! 404 Not Found\nnpm ERR! more\n' }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.command).toBe('npm install lodash@4.17.21');
    expect(r.failure?.exit_code).toBe(1);
    expect(r.failure?.stderr_head).toBe('npm ERR! 404 Not Found');
  });

  it('stops at the first failure instead of running the rest', async () => {
    const g = group({ candidates: [
      { source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
        command: 'npm install a@1', label: 'a' },
      { source: 'deps', fingerprints: ['b'.repeat(64)], severity: 'high',
        command: 'npm install b@2', label: 'b' },
    ] });
    const { run, calls } = fakeRun([
      { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('treats a timeout as a failure and says so', async () => {
    const { run } = fakeRun([{ outcome: 'timed_out', exitCode: null }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.outcome).toBe('timed_out');
  });

  // --- Additional coverage: the brief's six tests leave three real gaps —
  // `commands` (the PR-body transcript) is never asserted at all; the npm-only
  // SCOPE of `--package-lock-only` is only exercised against an npm command, so
  // a version that inserts the flag unconditionally on any `lockfileOnly: true`
  // call would still pass; and the brief names `timed_out` but `runProcess` has
  // a second non-'completed', non-'failed' outcome (`output_too_large`) that a
  // narrower `outcome === 'failed' || outcome === 'timed_out'` check would miss.

  it('records the exact commands run, in order, for the PR body', async () => {
    // The wrong implementation reports commands: [] always, or records the
    // candidate's human label instead of the literal invoked command line.
    const g = group({ candidates: [
      { source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
        command: 'npm install a@1', label: 'a upgrade' },
      { source: 'deps', fingerprints: ['b'.repeat(64)], severity: 'high',
        command: 'npm install b@2', label: 'b upgrade' },
    ] });
    const { run } = fakeRun([
      { outcome: 'completed', exitCode: 0 },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.commands).toEqual(['npm install a@1', 'npm install b@2']);
  });

  it('never adds --package-lock-only to a non-npm command, even when lockfileOnly is true', async () => {
    // The flag is meaningful only to `npm install`. Passing it to pip (or any
    // other ecosystem's installer) is not a harmless no-op — it is an
    // unrecognised flag that would make the upgrade command itself fail.
    const g = group({
      candidates: [{ source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
        command: 'pip install -U requests==2.32.0', label: 'requests -> 2.32.0' }],
    });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: true });
    expect(r.applied).toBe(true);
    expect(calls[0]?.command).toBe('pip');
    expect(calls[0]?.args).toEqual(['install', '-U', 'requests==2.32.0']);
    expect(calls[0]?.args).not.toContain('--package-lock-only');
  });

  it('treats output_too_large as a failure too, and still names the command', async () => {
    // Guards a narrower non-'completed' check (e.g. one that only recognises
    // 'failed' and 'timed_out') against the outcome runProcess uses for a
    // process killed for exceeding its stdout cap.
    const { run } = fakeRun([{ outcome: 'output_too_large', exitCode: null }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.outcome).toBe('output_too_large');
    expect(r.failure?.command).toBe('npm install lodash@4.17.21');
    expect(r.failure?.exit_code).toBeNull();
  });
});
