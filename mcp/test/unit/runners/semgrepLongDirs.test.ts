/**
 * Semgrep's walk and Windows' directory limit (`runners/semgrepLongDirs.ts`):
 * a run whose walk could not list the tree is repeated with the directories
 * too long for Windows excluded (`runners/semgrepRun.ts#runSemgrep`). The real
 * Semgrep case is `e2e/sastLongPath.test.ts`; here the decisions, on any host
 * (the platform is a parameter, and Windows' path rules are `path.win32`).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { ProcessRunOptions, ProcessRunResult } from '../../../src/runners/processRunner.js';
import { failedToListTargets, longDirsUnder, semgrepExcludeForDir, WINDOWS_DIR_MAX } from '../../../src/runners/semgrepLongDirs.js';
import { longDirsNote, runSemgrep } from '../../../src/runners/semgrepRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** A project holding `a/`, a chain whose last directory passes the limit, and the chain's own child. */
function project(): { root: string; long: string } {
  const root = makeTempDir('semgrep-longdirs-');
  mkdirSync(join(root, 'a'));
  writeFileSync(join(root, 'a', 'x.js'), 'x');
  let rel = 'deep';
  while (`${root}/${rel}`.length < WINDOWS_DIR_MAX + 4) rel = `${rel}/dddddddddd`;
  mkdirSync(join(root, ...rel.split('/'), 'below'), { recursive: true });
  mkdirSync(join(root, '.git', ...rel.split('/').slice(1)), { recursive: true });
  // The first directory of the chain past the limit is the one to exclude.
  const parts = rel.split('/');
  let cut = 1;
  while (`${root}/${parts.slice(0, cut).join('/')}`.length < WINDOWS_DIR_MAX) cut++;
  return { root, long: parts.slice(0, cut).join('/') };
}

describe('failedToListTargets', () => {
  it("Semgrep's own message, in its report, stdout or stderr", () => {
    expect(failedToListTargets(null, '', '[ERROR] Failed to obtain target files from semgrep-core\n')).toBe(true);
    expect(failedToListTargets('{"errors":[{"message":"SemgrepError: Failed to obtain target files from semgrep-core"}]}')).toBe(true);
    expect(failedToListTargets('{"errors":[{"message":"Invalid rule"}]}', 'x', undefined)).toBe(false);
  });
});

describe('longDirsUnder', () => {
  it('the top-most directories at the limit or past it, never below one, never .git; nothing off Windows', () => {
    const { root, long } = project();
    expect(longDirsUnder(root, 'win32')).toEqual([long]);
    expect(longDirsUnder(root, 'linux')).toEqual([]);
  });
});

describe('semgrepExcludeForDir', () => {
  it('a project-relative --exclude with no leading /, its glob characters escaped', () => {
    expect(semgrepExcludeForDir('a/b c')).toBe('--exclude=a/b c');
    expect(semgrepExcludeForDir('x/[v1]!/#y')).toBe('--exclude=x/\\[v1\\]\\!/\\#y');
  });
});

describe('runSemgrep: the Windows retry', () => {
  const failed = (stderr: string): ProcessRunResult => ({ outcome: 'failed', exitCode: 2, stdout: '', stderr, truncated: false });
  const ok: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
  const listingFailed = failed('[ERROR] Failed to obtain target files from semgrep-core\n');

  it('a walk that could not list the tree is run once more, the long directories excluded before the target', async () => {
    const { root, long } = project();
    const run = vi.fn<(o: ProcessRunOptions) => Promise<ProcessRunResult>>().mockResolvedValueOnce(listingFailed).mockResolvedValueOnce(ok);
    const r = await runSemgrep({ args: ['--config=r.yml', '--json', root], cwd: root }, run, 'win32');
    expect(run).toHaveBeenCalledTimes(2);
    expect(run.mock.calls[1]?.[0].args).toEqual(['--config=r.yml', '--json', `--exclude=${long}`, root]);
    expect(r).toMatchObject({ exitCode: 0, excludedLongDirs: [long] });
    expect(longDirsNote(r)).toMatch(/^Semgrep could not list the project on Windows: 1 directory at a path of 248 characters or more was left out/);
  });

  it('no retry off Windows, after a run that did not fail, after another failure, or with no long directory', async () => {
    const { root } = project();
    const plain = makeTempDir('semgrep-longdirs-none-');
    const cases: Array<[ProcessRunResult, string, NodeJS.Platform]> = [
      [listingFailed, root, 'linux'],
      [ok, root, 'win32'],
      [failed('[ERROR] Invalid rule schema\n'), root, 'win32'],
      [listingFailed, plain, 'win32'],
    ];
    for (const [first, target, platform] of cases) {
      const run = vi.fn<(o: ProcessRunOptions) => Promise<ProcessRunResult>>().mockResolvedValue(first);
      const r = await runSemgrep({ args: ['--json', target], cwd: target }, run, platform);
      expect(run).toHaveBeenCalledTimes(1);
      expect(r.excludedLongDirs).toBeUndefined();
      expect(longDirsNote(r)).toBeNull();
    }
  });
});
