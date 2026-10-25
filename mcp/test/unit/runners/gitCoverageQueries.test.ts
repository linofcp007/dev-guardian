/**
 * The git queries the coverage gaps are built from (`runners/git.ts`) —
 * review 3.6.1, finding 6: `initialisedSubmodules`, `gitlinksAmong` and
 * `trackedGuardianOutput` answered `[]` on ANY non-zero exit, a timeout (124)
 * or an index listing past the output cap included, and an empty answer is
 * read as "none": no submodule gap, no `.guardian/` gap. A query git could
 * not answer is now one entry that says so, and every reader names it.
 * Outside a repository the answer is still none.
 */

import { execa } from 'execa';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { submodulesNotIgnored } from '../../../src/platform/guardianIgnore.js';
import { gitlinksAmong, initialisedSubmodules, isGitUnanswered, trackedGuardianOutput } from '../../../src/runners/git.js';
import { applySemgrepCoverageGaps, semgrepCoverageGaps } from '../../../src/runners/semgrepCoverageGaps.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);

async function repo(): Promise<string> {
  const dir = makeTempDir('git-coverage-queries-');
  await execa('git', ['init', '-q'], { cwd: dir });
  writeFileSync(join(dir, 'a.py'), 'x = 1\n');
  await execa('git', ['add', 'a.py'], { cwd: dir });
  await execa('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'a'], { cwd: dir });
  return dir;
}

/** A damaged index: git exits 128, and it is not "not a git repository". */
async function corruptIndex(): Promise<string> {
  const dir = await repo();
  writeFileSync(join(dir, '.git', 'index'), 'not an index');
  return dir;
}

describe('a git query that could not be answered is never "none"', () => {
  it('initialisedSubmodules and trackedGuardianOutput: one entry naming why', async () => {
    const dir = await corruptIndex();
    for (const answer of [await initialisedSubmodules(dir), await trackedGuardianOutput(dir)]) {
      expect(answer).toHaveLength(1);
      expect(isGitUnanswered(answer[0] ?? '')).toBe(true);
      expect(answer[0]).toMatch(/^\(git could not answer: .*index/i);
    }
  });

  it('gitlinksAmong: a revision git cannot read is no answer either', async () => {
    const dir = await repo();
    const answer = await gitlinksAmong(dir, 'f'.repeat(40), ['a.py']);
    expect(answer).toHaveLength(1);
    expect(isGitUnanswered(answer[0] ?? '')).toBe(true);
  });

  it('outside a repository, and in a sound one with none: none', async () => {
    const plain = makeTempDir('git-coverage-queries-plain-');
    expect(await initialisedSubmodules(plain)).toEqual([]);
    expect(await trackedGuardianOutput(plain)).toEqual([]);
    const sound = await repo();
    expect(await initialisedSubmodules(sound)).toEqual([]);
    expect(await gitlinksAmong(sound, 'HEAD', ['a.py'])).toEqual([]);
  });

  it(".guardianignore never drops it, and the Semgrep run is partial, the reason named", async () => {
    const dir = await corruptIndex();
    writeFileSync(join(dir, '.guardianignore'), '*\n');
    expect(submodulesNotIgnored(dir, ['(git could not answer: x)', 'libs/core'])).toEqual(['(git could not answer: x)']);
    const gaps = await semgrepCoverageGaps(dir);
    const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, gaps);
    expect(r.missing).toBe(true);
    expect(r.toolRun.reason).toMatch(/git could not say which submodules hold content/);
    expect(r.toolRun.reason).toMatch(/git could not say which files it tracks in \.guardian\/'s generated output/);
  });
});
