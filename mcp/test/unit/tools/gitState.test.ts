/**
 * `workingTreeState` is tri-state on purpose: `auto_fix` rewrites files, and
 * the only tree it may rewrite without `allow_dirty` is one git has POSITIVELY
 * confirmed clean. "Not a git repository" and "git failed" used to read as
 * clean, which let `auto_fix` rewrite unversioned files nobody could get back.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { workingTreeState } from '../../../src/tools/gitState.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function gitRepo(): string {
  const dir = makeTempDir('gitstate-');
  execFileSync('git', ['init', '-q', dir]);
  writeFileSync(join(dir, 'a.txt'), 'a\n');
  execFileSync('git', ['-C', dir, 'add', '.']);
  execFileSync('git', [
    '-C', dir, '-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false',
    'commit', '-q', '-m', 'x',
  ]);
  return dir;
}

describe('workingTreeState', () => {
  it('is clean for a committed repo with nothing changed', async () => {
    expect(await workingTreeState(gitRepo())).toEqual({ state: 'clean' });
  });

  it('is dirty when a tracked file changed or an untracked file appeared', async () => {
    const dir = gitRepo();
    writeFileSync(join(dir, 'b.txt'), 'new\n');
    expect((await workingTreeState(dir)).state).toBe('dirty');
  });

  it('is unknown, never clean, outside a git repository', async () => {
    const state = await workingTreeState(makeTempDir('gitstate-norepo-'));
    expect(state.state).toBe('unknown');
    if (state.state === 'unknown') expect(state.reason.length).toBeGreaterThan(0);
  });

  it('is unknown, never clean, when git itself fails (a .git that points nowhere)', async () => {
    // The same shape as "dubious ownership": git refuses and exits non-zero.
    const dir = makeTempDir('gitstate-broken-');
    writeFileSync(join(dir, '.git'), 'gitdir: ./does-not-exist\n');
    writeFileSync(join(dir, 'a.txt'), 'a\n');
    const state = await workingTreeState(dir);
    expect(state.state).toBe('unknown');
  });
});
