import { describe, expect, it } from 'vitest';
import { branchName, prExists, openPr } from '../../../src/fixpr/pr.js';

function fakeRun(script: Record<string, { outcome: string; exitCode: number | null;
  stdout?: string; stderr?: string }>) {
  const calls: string[][] = [];
  const run = async (opts: { command: string; args?: string[] }) => {
    const args = opts.args ?? [];
    calls.push([opts.command, ...args]);
    // Match on a PREFIX, not a fixed arity: `git push -u origin b` must match
    // the key `git push`, and a three-token key like `gh pr create` must still
    // beat the two-token `gh pr`. Longest key first.
    const line = [opts.command, ...args].join(' ');
    const key = Object.keys(script)
      .sort((a, b) => b.length - a.length)
      .find((k) => line.startsWith(k));
    const hit = (key === undefined ? undefined : script[key])
      ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: hit.outcome, exitCode: hit.exitCode,
      stdout: hit.stdout ?? '', stderr: hit.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('branchName', () => {
  it('is deterministic and namespaced', () => {
    expect(branchName('deps', 'npm', 'abc123def456'))
      .toBe('dev-guardian/fix-npm-abc123def456');
  });
});

describe('prExists', () => {
  it('searches every state, not just open', async () => {
    // create_github_issues searches `gh issue list`, which defaults to OPEN, so
    // a closed issue for the same finding gets re-filed. Not repeated here.
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
    });
    await prExists({ projectPath: '/p', branch: 'b', run });
    expect(calls[0]?.join(' ')).toContain('--state all');
  });

  it('reports NOT KNOWN when the check itself fails', async () => {
    // create_github_issues returns `false` on any non-completed outcome, so a
    // network error reads as "does not exist" and creates a duplicate. Here,
    // not knowing must be distinguishable from knowing there is nothing.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'failed', exitCode: 1, stderr: 'network unreachable\n' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r.known).toBe(false);
  });

  it('reports exists when the search returns a row', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[{"number":7}]' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r).toEqual({ known: true, exists: true });
  });
});

describe('openPr', () => {
  const base = { projectPath: '/p', worktreePath: '/w', branch: 'dev-guardian/fix-npm-abc',
    title: 'T', body: 'B' };

  it('refuses rather than duplicating when existence cannot be determined', async () => {
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('refused');
    expect(calls.some((c) => c.includes('push'))).toBe(false);
  });

  it('names the pushed branch when pr create fails after a successful push', async () => {
    // The one path that leaves remote state. A report that does not name the
    // branch leaves the user with an unexplained branch on their remote.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'failed', exitCode: 1, stderr: 'no upstream repo\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('create_failed');
    expect(r.detail).toContain('dev-guardian/fix-npm-abc');
  });

  it('reports push_failed without attempting to create a PR', async () => {
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'git push': { outcome: 'failed', exitCode: 1, stderr: 'permission denied\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('push_failed');
    expect(calls.some((c) => c.join(' ').includes('pr create'))).toBe(false);
  });

  it('returns the URL on success', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0,
        stdout: 'https://github.com/o/r/pull/12\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r).toEqual({ status: 'created', url: 'https://github.com/o/r/pull/12',
      detail: null });
  });
});

// --- Additional coverage beyond the brief -------------------------------
//
// The brief's own fixtures never separate "existence known and true" from
// "existence unknown" at the `openPr` level (only `prExists` gets a direct
// `exists: true` test, never routed through `openPr`), never assert the
// ORDER calls happen in (only that specific calls are absent), never assert
// `cwd` at all (its `fakeRun` does not even capture it), and never pin down
// the exact args `gh pr list` / `gh pr create` are called with beyond a
// substring. Each gap below is a class of wrong implementation the brief's
// own five tests would let through.

function fakeRunWithCwd(script: Record<string, { outcome: string; exitCode: number | null;
  stdout?: string; stderr?: string }>) {
  // Same prefix-matching contract as the brief's own `fakeRun` (see its
  // comment), extended only to also record `cwd` per call — the brief's
  // helper does not capture it at all, so it cannot be used to assert the
  // isolation boundary between `projectPath` and `worktreePath`.
  const calls: { command: string; args: string[]; cwd: string }[] = [];
  const run = async (opts: { command: string; args?: string[]; cwd: string }) => {
    const args = opts.args ?? [];
    calls.push({ command: opts.command, args, cwd: opts.cwd });
    const line = [opts.command, ...args].join(' ');
    const key = Object.keys(script)
      .sort((a, b) => b.length - a.length)
      .find((k) => line.startsWith(k));
    const hit = (key === undefined ? undefined : script[key])
      ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: hit.outcome, exitCode: hit.exitCode,
      stdout: hit.stdout ?? '', stderr: hit.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('branchName — additional coverage', () => {
  it('ignores `source` in the formatted string — `key` already carries the ecosystem-or-scanner', () => {
    // A wrong implementation might fold `source` into the string too (e.g.
    // `dev-guardian/fix-deps-npm-<hash>`), duplicating what `key` already
    // encodes for deps groups ('npm', 'pip', …) and for the semgrep group
    // ('semgrep'). Only the brief's 'deps'+'npm' case is given; this pins
    // down the OTHER branch of FixSource so a `source`-conditional
    // implementation can't hide behind the one case that happens to look
    // right anyway.
    expect(branchName('semgrep', 'semgrep', 'deadbeefcafe'))
      .toBe('dev-guardian/fix-semgrep-deadbeefcafe');
  });
});

describe('prExists — additional coverage', () => {
  it('reports known:true, exists:false on an empty result — not just known:true on a hit', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r).toEqual({ known: true, exists: false });
  });

  it('reports NOT KNOWN when the output cannot be parsed as JSON', async () => {
    // create_github_issues' own JSON.parse is wrapped in a try/catch that
    // returns `false` (does not exist) on a parse failure — the same shape
    // of bug as trusting a non-completed outcome, just one step later in the
    // same function. Generalising the "refuse, don't guess" rule to this
    // case is this module's own choice, not spelled out by name in the
    // brief, but the same principle covers it.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: 'not json' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r.known).toBe(false);
  });

  it('reports NOT KNOWN when gh prints valid JSON that is not an array', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '{"unexpected":true}' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r.known).toBe(false);
  });

  it('runs `gh pr list` in projectPath with the exact documented args', async () => {
    // The brief's own test only checks the joined line CONTAINS '--state
    // all' — it would still pass if `--json`/`--limit`/`--head` were wrong,
    // missing, or in a different form. This pins the whole invocation down.
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
    });
    await prExists({ projectPath: '/proj', branch: 'dev-guardian/fix-npm-abc', run });
    expect(calls).toEqual([{
      command: 'gh',
      args: ['pr', 'list', '--head', 'dev-guardian/fix-npm-abc', '--state', 'all',
        '--json', 'number', '--limit', '5'],
      cwd: '/proj',
    }]);
  });
});

describe('openPr — order of operations and refusal (additional coverage)', () => {
  const base = { projectPath: '/proj', worktreePath: '/wt', branch: 'dev-guardian/fix-npm-abc',
    title: 'T', body: 'B' };

  it('performs the full sequence in order: existence check, add, commit, push, then pr create', async () => {
    // The safety property named in the task: nothing is pushed before the
    // existence check resolves. A wrong implementation might fire the push
    // and the existence check concurrently (both would still individually
    // "look right" in isolation) or commit/push before checking. This pins
    // down the actual sequence, not just which calls eventually happen.
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0,
        stdout: 'https://github.com/o/r/pull/9\n' },
    });
    await openPr({ ...base, run });
    expect(calls.map((c) => [c.command, c.args[0], c.args[1]])).toEqual([
      ['gh', 'pr', 'list'],
      ['git', 'add', '-A'],
      ['git', 'commit', '-m'],
      ['git', 'push', '-u'],
      ['gh', 'pr', 'create'],
    ]);
  });

  it('runs the existence check and pr create in projectPath, and add/commit/push in the worktree', async () => {
    // cwd is the isolation boundary (the same property apply.test.ts asserts
    // for applyGroup): git writes must land in the worktree, and gh's repo
    // resolution must use the project checkout the user's own remote and
    // auth are configured against.
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0,
        stdout: 'https://github.com/o/r/pull/9\n' },
    });
    await openPr({ ...base, run });
    const byCommand = (cmd: string, first: string) =>
      calls.find((c) => c.command === cmd && c.args[0] === first);
    expect(byCommand('gh', 'pr')?.cwd).toBe('/proj');
    expect(byCommand('git', 'add')?.cwd).toBe('/wt');
    expect(byCommand('git', 'commit')?.cwd).toBe('/wt');
    expect(byCommand('git', 'push')?.cwd).toBe('/wt');
    const createCall = calls.filter((c) => c.command === 'gh')[1];
    expect(createCall?.cwd).toBe('/proj');
  });

  it('never touches git or a second gh call when a PR already exists for the branch', async () => {
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[{"number":3}]' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('exists');
    expect(r.url).toBeNull();
    expect(r.detail).not.toBeNull();
    expect(calls).toHaveLength(1);
  });

  it('never touches git when existence is unknown — the refusal is real, not just labelled', async () => {
    // The brief's own equivalent test only checks that no call contains
    // 'push'. A wrong implementation could still run `git add`/`git commit`
    // (staging and committing locally) before stopping short of the push and
    // still pass that narrower check. Nothing at all should run past the
    // failed existence check.
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('refused');
    expect(calls).toHaveLength(1);
  });

  it('names the branch in push_failed detail too, so a local-only branch is not orphaned silently', async () => {
    // design doc §7, failure path 7: a push failure must still name the
    // branch, distinct from failure path 8 (create_failed) which the brief
    // tests directly. Neither the brief's push_failed test nor its
    // create_failed test alone would catch an implementation that names the
    // branch on ONE of the two paths and forgets the other.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'git push': { outcome: 'failed', exitCode: 1, stderr: 'permission denied\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('push_failed');
    expect(r.detail).toContain(base.branch);
  });

  it('commits with the PR title as the message, and passes head/title/body through to gh pr create', async () => {
    const { run, calls } = fakeRunWithCwd({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0,
        stdout: 'https://github.com/o/r/pull/1\n' },
    });
    await openPr({ ...base, title: 'Bump lodash', body: 'Resolves CVE-1234', run });
    const commitCall = calls.find((c) => c.command === 'git' && c.args[0] === 'commit');
    expect(commitCall?.args).toEqual(['commit', '-m', 'Bump lodash']);
    const createCall = calls.find((c) => c.command === 'gh' && c.args[1] === 'create');
    expect(createCall?.args).toEqual(['pr', 'create', '--head', base.branch,
      '--title', 'Bump lodash', '--body', 'Resolves CVE-1234']);
  });

  it('still reports created, with a null url, when gh pr create succeeds without a parseable URL line', async () => {
    // Documents a deliberate choice for a real edge case: `outcome ===
    // 'completed'` already means exit 0, so treating a missing URL line as a
    // hard failure would be inventing a failure gh itself did not report.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0, stdout: 'no url here\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r).toEqual({ status: 'created', url: null, detail: null });
  });

  it('reports push_failed, not create_failed, when git add itself fails', async () => {
    // `git add`/`git commit` failing is not one of design §7's eight named
    // paths (nothing reaches the remote either way), and PrOutcome has no
    // status of its own for it — bucketed under push_failed since that is
    // the closest existing status: the branch never reached origin.
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'git add': { outcome: 'failed', exitCode: 1, stderr: 'fatal: not a git repository\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('push_failed');
    expect(calls.some((c) => c.join(' ').includes('commit'))).toBe(false);
    expect(calls.some((c) => c.join(' ').includes('push'))).toBe(false);
  });
});
