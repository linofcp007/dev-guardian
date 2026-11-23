/**
 * deps-tools-host-other-texts, task 2, T-11 (red until the fix): the other places where `create_fix_pr` repeats the
 * first line of a program's error: the `stderr_head` of a failed step (`apply.ts#buildFailure`) and the reason of a
 * worktree `git worktree add` could not make (`worktree.ts#describeFailure`). A URL in such a line is said by the rule
 * (up to the first space or quote): without its credentials when it is well formed, `(host not shown)` when it has an
 * `@` outside the user part.
 *
 * `applyGroup` gets a fake `run`; `createWorktree` calls `runProcess` itself, so it is mocked. No package manager, no
 * `git worktree` runs. Every credential-looking value is MADE UP and built from parts.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/runners/processRunner.js')>();
  return { ...actual, runProcess: vi.fn() };
});

import { applyGroup } from '../../../src/fixpr/apply.js';
import type { FixGroup, UpgradeStep } from '../../../src/fixpr/types.js';
import { createWorktree } from '../../../src/fixpr/worktree.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../../src/runners/processRunner.js';

const FEATURE = 'deps-tools-host-other-texts';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const H = 'host.example';
const partsIn = (text: string): string[] => [T, K, U].filter((p) => text.toLowerCase().includes(p.toLowerCase()));

afterEach(() => {
  vi.mocked(runProcess).mockReset();
});

const step: UpgradeStep = {
  package_name: 'dgdep',
  installed_version: '1.0.0',
  latest_version: '1.0.1',
  ecosystem: 'npm',
  classification: 'security',
  upgrade_command: 'npm install dgdep@1.0.1',
} as UpgradeStep;
const group: FixGroup = {
  source: 'deps',
  key: 'npm',
  severity: 'high',
  hash: '000000000000',
  candidates: [{ source: 'deps', fingerprints: ['fp'], severity: 'high', command: 'npm install dgdep@1.0.1', label: 'dgdep 1.0.0 -> 1.0.1', steps: [step] }],
} as unknown as FixGroup;

describe(`${FEATURE} T-11 the first error line of a program, repeated by create_fix_pr`, () => {
  it.each([
    { id: 'https://U:T@H/x.tgz', url: `https://${U}:${T}@${H}/x.tgz`, said: `https://${H}/x.tgz` },
    { id: 'https://T/K@H/x.tgz', url: `https://${T}/${K}@${H}/x.tgz`, said: 'https://(host not shown)' },
  ])('T-11 applyGroup: the stderr_head of a failed step says $id without credentials', async ({ url, said }) => {
    const run = async (_opts: ProcessRunOptions): Promise<ProcessRunResult> => ({
      outcome: 'failed',
      exitCode: 1,
      stdout: '',
      stderr: `npm error 404 Not Found - GET ${url} - Not found\nnpm error A complete log of this run can be found in: /x/log\n`,
      truncated: false,
    });
    const r = await applyGroup({ group, worktreePath: '/w', run, lockfileOnly: true });
    expect(r.applied).toBe(false);
    const head = r.failure?.stderr_head ?? '';
    expect(partsIn(head), head).toEqual([]);
    expect(head).toContain(said);
  });

  it.each([
    { id: 'https://T/K@H/org/repo.git/', url: `https://${T}/${K}@${H}/org/repo.git/`, said: 'https://(host not shown)' },
    { id: 'https://U:T@H/org/repo.git/', url: `https://${U}:${T}@${H}/org/repo.git/`, said: `https://${H}/org/repo.git/` },
  ])('T-11 createWorktree: the reason of a failed git worktree add says $id without credentials', async ({ url, said }) => {
    vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions): Promise<ProcessRunResult> => {
      const args = opts.args ?? [];
      if (args.includes('worktree') && args.includes('add')) {
        return { outcome: 'failed', exitCode: 128, stdout: '', stderr: `Preparing worktree (detached HEAD)\nfatal: unable to access '${url}': Could not resolve host\n`, truncated: false };
      }
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = await createWorktree({ projectPath: '/does/not/matter', branch: null });
    expect(r.ok).toBe(false);
    const reason = r.ok ? '' : r.reason;
    expect(partsIn(reason), reason).toEqual([]);
    expect(reason).toContain(said);
  });
});
