/**
 * A git that did not answer is never a negative answer (review of 3.0).
 *
 * `git()` used to turn every git without an exit status into 127, the "not
 * installed" code, and `repoState` read 127 as "not a git repository". Under
 * load a `rev-parse --show-toplevel` past its timeout therefore made gitleaks
 * swap the history pass for a directory pass, reported as "not a git
 * repository" — the history unscanned, and the result saying something else.
 * A timeout on the HEAD query read as "no commits yet" the same way.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { GitExecResult } from '../../../src/platform/gitSafety.js';

const answers: Array<GitExecResult<string>> = [];
const execGit = vi.fn(async (): Promise<GitExecResult<string>> => {
  const next = answers.shift();
  if (next === undefined) throw new Error('an unexpected git call');
  return next;
});

vi.mock('../../../src/platform/gitSafety.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/platform/gitSafety.js')>()),
  execGit: () => execGit(),
}));

const { git, repoState } = await import('../../../src/runners/git.js');

const exited = (status: number, stdout = '', stderr = ''): GitExecResult<string> => ({
  status,
  stdout,
  stderr,
  failure: null,
  notApplied: [],
});
const killed = (code: 'timeout' | 'not-found' | 'spawn', message: string): GitExecResult<string> => ({
  status: null,
  stdout: '',
  stderr: '',
  failure: { code, message },
  notApplied: [],
});

beforeEach(() => {
  answers.length = 0;
  execGit.mockClear();
});

describe('git(): 127 only for a git that is not installed', () => {
  it('not installed is 127', async () => {
    answers.push(killed('not-found', 'git is not installed'));
    expect((await git('/p', ['status'])).exitCode).toBe(127);
  });

  it('a timeout or a failed spawn is 124, with the reason', async () => {
    answers.push(killed('timeout', 'git took longer than 60000 ms'));
    expect(await git('/p', ['status'])).toMatchObject({ exitCode: 124, stderr: 'git took longer than 60000 ms' });
    answers.push(killed('spawn', 'git failed to run (EAGAIN)'));
    expect((await git('/p', ['status'])).exitCode).toBe(124);
  });
});

describe('repoState: a git that did not answer is an error, named', () => {
  it('a timed-out --show-toplevel is an error, never "not a git repository"', async () => {
    answers.push(killed('timeout', 'git took longer than 60000 ms'));
    expect(await repoState('/p')).toEqual({ kind: 'error', message: 'git took longer than 60000 ms' });
  });

  it('a timed-out HEAD query is an error, never "no commits yet"', async () => {
    answers.push(exited(0, '/p\n'), killed('timeout', 'git took longer than 60000 ms'));
    expect(await repoState('/p')).toEqual({ kind: 'error', message: 'git took longer than 60000 ms' });
  });

  it('the negatives git does state still read as such', async () => {
    answers.push(exited(128, '', 'fatal: not a git repository (or any of the parent directories): .git\n'));
    expect(await repoState('/p')).toEqual({ kind: 'not_git' });
    answers.push(killed('not-found', 'git is not installed'));
    expect(await repoState('/p')).toEqual({ kind: 'not_git' });
    answers.push(exited(0, '/p\n'), exited(1));
    expect(await repoState('/p')).toEqual({ kind: 'no_commits', toplevel: '/p' });
    answers.push(exited(0, '/p\n'), exited(0, 'abc\n'));
    expect(await repoState('/p')).toEqual({ kind: 'has_commits', toplevel: '/p' });
  });
});
