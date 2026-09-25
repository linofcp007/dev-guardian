import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { applyGroup } from '../../../src/fixpr/apply.js';
import type { SemgrepFixPlan } from '../../../src/fixpr/semgrepFix.js';
import type { FixCandidate, FixGroup, UpgradeStep } from '../../../src/fixpr/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function npmStep(over: Partial<UpgradeStep> = {}): UpgradeStep {
  return {
    package_name: 'lodash', installed_version: '4.17.20', latest_version: '4.17.21',
    classification: 'security', ecosystem: 'npm',
    upgrade_command: 'npm install lodash@4.17.21 --ignore-scripts',
    ...over,
  };
}

function candidate(steps: UpgradeStep[], over: Partial<FixCandidate> = {}): FixCandidate {
  return {
    source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
    command: steps[0]?.upgrade_command ?? null, label: 'lodash 4.17.20 -> 4.17.21', steps,
    ...over,
  };
}

function group(over: Partial<FixGroup> = {}): FixGroup {
  return {
    source: 'deps', key: 'npm', severity: 'high', hash: 'abc123def456',
    candidates: [candidate([npmStep()])],
    ...over,
  };
}

interface Call { command: string; args: string[]; cwd: string }

function fakeRun(
  script: { outcome: string; exitCode: number | null; stderr?: string }[],
  onCall?: (call: Call) => void,
) {
  // `cwd` is captured alongside `command`/`args` — it is the entire isolation
  // mechanism (worktreePath, never the real project directory).
  const calls: Call[] = [];
  let i = 0;
  const run = async (opts: { command: string; args?: string[]; cwd: string }) => {
    const call = { command: opts.command, args: opts.args ?? [], cwd: opts.cwd };
    calls.push(call);
    onCall?.(call);
    const next = script[i++] ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: next.outcome, exitCode: next.exitCode,
      stdout: '', stderr: next.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('applyGroup — deps', () => {
  it('splits the pinned upgrade command into argv — never through a shell — in the worktree', async () => {
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(true);
    expect(calls[0]?.command).toBe('npm');
    expect(calls[0]?.args).toEqual(['install', 'lodash@4.17.21', '--ignore-scripts']);
    expect(calls[0]?.cwd).toBe('/w');
  });

  it('Task 11 item 5: adds --ignore-scripts to an npm install that lacks it — a dependency script is arbitrary code', async () => {
    const g = group({ candidates: [candidate([npmStep({ upgrade_command: 'npm install lodash@4.17.21' })])] });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(calls[0]?.args).toEqual(['install', 'lodash@4.17.21', '--ignore-scripts']);
    const ci = group({ candidates: [candidate([npmStep({ upgrade_command: 'npm ci' })])] });
    const b = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: ci, worktreePath: '/w', run: b.run, lockfileOnly: false });
    expect(b.calls[0]?.args).toContain('--ignore-scripts');
  });

  it('adds --no-scripts to an installing composer command', async () => {
    const g = group({ key: 'composer', candidates: [candidate([npmStep({
      ecosystem: 'composer', package_name: 'guzzlehttp/guzzle', upgrade_command: 'composer require guzzlehttp/guzzle:^7.9.2',
    })])] });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(calls[0]?.args).toEqual(['require', 'guzzlehttp/guzzle:^7.9.2', '--no-scripts']);
  });

  it('a Ruby step only re-locks: `bundle update` becomes `bundle lock --update` — never a gem install into the host', async () => {
    const ruby = (cmd: string): FixGroup => group({ key: 'rubygems', candidates: [candidate([npmStep({
      ecosystem: 'rubygems', package_name: 'rack', upgrade_command: cmd,
    })])] });
    const a = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: ruby('bundle update rack'), worktreePath: '/w', run: a.run, lockfileOnly: false });
    expect(r.applied).toBe(true);
    expect(a.calls.map((c) => [c.command, ...c.args].join(' '))).toEqual(['bundle lock --update rack']);

    // Any other bundle subcommand installs or executes: refused, nothing runs.
    const b = fakeRun([]);
    const refused = await applyGroup({ group: ruby('bundle install'), worktreePath: '/w', run: b.run, lockfileOnly: false });
    expect(refused.applied).toBe(false);
    expect(refused.failure?.stderr_head).toMatch(/host/);
    expect(b.calls).toEqual([]);
  });

  it('Task 10 handoff: runs a step\'s follow_up_command, so an overrides-only fix re-resolves the lockfile', async () => {
    const override = npmStep({
      upgrade_command: 'npm pkg set overrides[minimist]=1.2.6',
      follow_up_command: 'npm install --ignore-scripts',
      package_name: 'minimist',
    });
    const { run, calls } = fakeRun([
      { outcome: 'completed', exitCode: 0 },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const r = await applyGroup({ group: group({ candidates: [candidate([override])] }), worktreePath: '/w', run, lockfileOnly: true });
    expect(r.applied).toBe(true);
    expect(calls.map((c) => [c.command, ...c.args].join(' '))).toEqual([
      'npm pkg set overrides[minimist]=1.2.6',
      'npm install --ignore-scripts --package-lock-only',
    ]);
    expect(r.commands).toHaveLength(2);
  });

  it('does not run the follow-up when the step itself failed', async () => {
    const override = npmStep({ upgrade_command: 'npm pkg set overrides[x]=1', follow_up_command: 'npm install --ignore-scripts' });
    const { run, calls } = fakeRun([{ outcome: 'failed', exitCode: 1, stderr: 'nope\n' }]);
    const r = await applyGroup({ group: group({ candidates: [candidate([override])] }), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('adds --package-lock-only when no test command exists, and not otherwise', async () => {
    const a = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: a.run, lockfileOnly: true });
    expect(a.calls[0]?.args).toContain('--package-lock-only');

    const b = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: b.run, lockfileOnly: false });
    expect(b.calls[0]?.args).not.toContain('--package-lock-only');
  });

  it('reports the failing command, not just "failed"', async () => {
    const { run } = fakeRun([{ outcome: 'failed', exitCode: 1,
      stderr: 'npm ERR! 404 Not Found\nnpm ERR! more\n' }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.command).toBe('npm install lodash@4.17.21 --ignore-scripts');
    expect(r.failure?.exit_code).toBe(1);
    expect(r.failure?.stderr_head).toBe('npm ERR! 404 Not Found');
  });

  it('stops at the first failure instead of running the rest', async () => {
    const g = group({ candidates: [
      candidate([npmStep({ upgrade_command: 'npm install a@1' })]),
      candidate([npmStep({ upgrade_command: 'npm install b@2' })], { fingerprints: ['b'.repeat(64)] }),
    ] });
    const { run, calls } = fakeRun([
      { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('treats a timeout and output_too_large as failures, and still names the command', async () => {
    for (const outcome of ['timed_out', 'output_too_large']) {
      const { run } = fakeRun([{ outcome, exitCode: null }]);
      const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
      expect(r.applied).toBe(false);
      expect(r.failure?.outcome).toBe(outcome);
      expect(r.failure?.command).toBe('npm install lodash@4.17.21 --ignore-scripts');
      expect(r.failure?.exit_code).toBeNull();
    }
  });

  it('records the exact commands run, in order, for the PR body', async () => {
    const g = group({ candidates: [
      candidate([npmStep({ upgrade_command: 'npm install a@1 --ignore-scripts' })]),
      candidate([npmStep({ upgrade_command: 'npm install b@2 --ignore-scripts' })], { fingerprints: ['b'.repeat(64)] }),
    ] });
    const { run } = fakeRun([{ outcome: 'completed', exitCode: 0 }, { outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.commands).toEqual(['npm install a@1 --ignore-scripts', 'npm install b@2 --ignore-scripts']);
  });

  it('never adds --package-lock-only to a non-npm command, even when lockfileOnly is true', async () => {
    const g = group({ key: 'cargo', candidates: [candidate([npmStep({
      ecosystem: 'cargo', package_name: 'smallvec', upgrade_command: 'cargo update -p smallvec --precise 1.13.2',
    })])] });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: true });
    expect(r.applied).toBe(true);
    expect(calls[0]?.args).toEqual(['update', '-p', 'smallvec', '--precise', '1.13.2']);
  });

  it('names a candidate that carries no step instead of reporting applied', async () => {
    const g = group({ candidates: [candidate([])] });
    const { run, calls } = fakeRun([]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe('applyGroup — pip steps edit the pin in the worktree, never pip install (Task 11 item 1)', () => {
  function pipStep(over: Partial<UpgradeStep> = {}): UpgradeStep {
    return {
      package_name: 'requests', installed_version: '2.31.0', latest_version: '2.32.0',
      classification: 'security', ecosystem: 'pip', file: 'requirements.txt',
      upgrade_command: 'pip-pin requirements.txt requests==2.32.0',
      ...over,
    };
  }

  it('edits the pin in the worktree\'s own file, runs no process at all, and leaves the project untouched', async () => {
    const project = makeTempDir('apply-pip-project-');
    const worktree = makeTempDir('apply-pip-wt-');
    const original = 'flask==3.0.0\nRequests[socks] == 2.31.0 ; python_version >= "3.8"  # pinned\nrequests-toolbelt==1.0.0\n';
    writeFileSync(join(project, 'requirements.txt'), original);
    writeFileSync(join(worktree, 'requirements.txt'), original);

    const { run, calls } = fakeRun([]);
    const r = await applyGroup({ group: group({ key: 'pip', candidates: [candidate([pipStep()])] }), worktreePath: worktree, run, lockfileOnly: false });

    expect(r.applied).toBe(true);
    expect(calls).toEqual([]);
    expect(readFileSync(join(worktree, 'requirements.txt'), 'utf8')).toBe(
      'flask==3.0.0\nRequests[socks] == 2.32.0 ; python_version >= "3.8"  # pinned\nrequests-toolbelt==1.0.0\n',
    );
    expect(readFileSync(join(project, 'requirements.txt'), 'utf8')).toBe(original);
    expect(r.commands[0]).toContain('requirements.txt');
  });

  it('edits a PEP 621 pin inside pyproject.toml', async () => {
    const worktree = makeTempDir('apply-pip-wt-');
    writeFileSync(join(worktree, 'pyproject.toml'), '[project]\ndependencies = ["requests==2.31.0", "flask>=3"]\n');
    const { run } = fakeRun([]);
    const r = await applyGroup({
      group: group({ key: 'pip', candidates: [candidate([pipStep({ file: 'pyproject.toml' })])] }),
      worktreePath: worktree, run, lockfileOnly: false,
    });
    expect(r.applied).toBe(true);
    expect(readFileSync(join(worktree, 'pyproject.toml'), 'utf8')).toContain('"requests==2.32.0"');
  });

  it('refuses a file outside the worktree', async () => {
    const worktree = makeTempDir('apply-pip-wt-');
    mkdirSync(join(worktree, 'sub'));
    const { run } = fakeRun([]);
    const r = await applyGroup({
      group: group({ key: 'pip', candidates: [candidate([pipStep({ file: '../requirements.txt' })])] }),
      worktreePath: join(worktree, 'sub'), run, lockfileOnly: false,
    });
    expect(r.applied).toBe(false);
    expect(r.failure?.stderr_head).toMatch(/not a file inside the project/);
  });

  it('fails by name when the pin is not there', async () => {
    const worktree = makeTempDir('apply-pip-wt-');
    writeFileSync(join(worktree, 'requirements.txt'), 'requests>=2.0\n');
    const { run } = fakeRun([]);
    const r = await applyGroup({ group: group({ key: 'pip', candidates: [candidate([pipStep()])] }), worktreePath: worktree, run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.stderr_head).toContain("no 'requests==2.31.0' pin");
  });
});

describe('applyGroup — semgrep applies only the target rules (Task 11 item 4)', () => {
  function plan(dir: string, over: Partial<SemgrepFixPlan> = {}): SemgrepFixPlan {
    return {
      configs: [join(dir, 'rules-000', 'bugfix-js.yml'), 'r/javascript.browser.security.eval-detected.eval-detected'],
      configLabels: ['floating-mutation from bugfix-js.yml', 'r/javascript.browser.security.eval-detected.eval-detected'],
      files: ['src/a.js'],
      dir,
      ...over,
    };
  }

  const semgrepGroup = (): FixGroup => group({
    source: 'semgrep', key: 'semgrep',
    candidates: [
      { source: 'semgrep', fingerprints: ['a'.repeat(64)], severity: 'high', command: null, label: 'rule.one', rule_id: 'rule.one', file_path: 'src/a.js' },
      { source: 'semgrep', fingerprints: ['b'.repeat(64)], severity: 'high', command: null, label: 'rule.two', rule_id: 'rule.two', file_path: 'src/a.js' },
    ],
  });

  /** A fake semgrep that writes a real-shaped report where --output points. */
  function writesReport(report: unknown) {
    return (call: Call): void => {
      const i = call.args.indexOf('--output');
      const out = i >= 0 ? call.args[i + 1] : undefined;
      if (out !== undefined) writeFileSync(out, JSON.stringify(report));
    };
  }

  it('runs ONE pass with the plan\'s configs, --metrics=off, on the target files — never --config auto', async () => {
    const worktree = makeTempDir('apply-sg-wt-');
    mkdirSync(join(worktree, 'src'));
    writeFileSync(join(worktree, 'src', 'a.js'), 'x\n');
    const dir = makeTempDir('apply-sg-plan-');
    const { run, calls } = fakeRun(
      [{ outcome: 'completed', exitCode: 0 }],
      writesReport({ results: [], errors: [], paths: { scanned: ['src/a.js'] } }),
    );
    const r = await applyGroup({ group: semgrepGroup(), worktreePath: worktree, run, lockfileOnly: false, semgrepFix: plan(dir) });
    expect(r.applied).toBe(true);
    expect(calls).toHaveLength(1);
    const args = calls[0]?.args ?? [];
    expect(calls[0]?.command).toBe('semgrep');
    expect(calls[0]?.cwd).toBe(worktree);
    expect(args).toContain('--metrics=off');
    expect(args).toContain('--autofix');
    expect(args).toContain(`--config=${join(dir, 'rules-000', 'bugfix-js.yml')}`);
    expect(args).toContain('--config=r/javascript.browser.security.eval-detected.eval-detected');
    expect(args.some((a) => a === 'auto' || a === '--config=auto')).toBe(false);
    expect(args.slice(args.indexOf('--') + 1)).toEqual(['src/a.js']);
  });

  it('refuses without a plan — there is no "apply every autofix" fallback', async () => {
    const { run, calls } = fakeRun([]);
    const r = await applyGroup({ group: semgrepGroup(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('a target file missing from the worktree (uncommitted) fails the group instead of passing unfixed', async () => {
    const worktree = makeTempDir('apply-sg-wt-');
    const { run, calls } = fakeRun([]);
    const r = await applyGroup({ group: semgrepGroup(), worktreePath: worktree, run, lockfileOnly: false, semgrepFix: plan(makeTempDir('apply-sg-plan-')) });
    expect(r.applied).toBe(false);
    expect(r.failure?.stderr_head).toContain('src/a.js');
    expect(calls).toHaveLength(0);
  });

  it('a pass that scanned nothing or reported errors did not apply the fix (Global Constraint 3)', async () => {
    const worktree = makeTempDir('apply-sg-wt-');
    mkdirSync(join(worktree, 'src'));
    writeFileSync(join(worktree, 'src', 'a.js'), 'x\n');
    for (const report of [
      { results: [], errors: [], paths: { scanned: [] } },
      { results: [], errors: [{ type: 'Rule parse error', message: 'bad rule' }], paths: { scanned: ['src/a.js'] } },
    ]) {
      const { run } = fakeRun([{ outcome: 'completed', exitCode: 0 }], writesReport(report));
      const r = await applyGroup({ group: semgrepGroup(), worktreePath: worktree, run, lockfileOnly: false, semgrepFix: plan(makeTempDir('apply-sg-plan-')) });
      expect(r.applied).toBe(false);
    }
  });
});
