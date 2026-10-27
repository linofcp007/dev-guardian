/**
 * `runners/historyView.ts` over a real repository, with the git version it
 * reads mocked: on a git without remerge-diff (Ubuntu 22.04's 2.34: "fatal:
 * unknown value for --diff-merges: remerge", measured) the merges' pass is not
 * run — it would fail the whole history pass — and the run names what it did
 * not read; on one without `GIT_ATTR_SOURCE` (Debian 12's 2.39), the tree's
 * attributes still apply, named too. The scratch directory never outlives
 * `remove()`.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

const fake = vi.hoisted(() => ({ version: null as string | null }));
vi.mock('../../../src/runners/git.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/runners/git.js')>();
  return {
    ...actual,
    git: async (...args: Parameters<typeof actual.git>) => {
      const [, gitArgs] = args;
      if (fake.version !== null && gitArgs[0] === 'version') return { exitCode: 0, stdout: `git version ${fake.version}\n`, stderr: '' };
      return actual.git(...args);
    },
  };
});

import { openHistoryView, REMERGE_DIFF } from '../../../src/runners/historyView.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  fake.version = null;
});

function git(dir: string, ...args: string[]): void {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
}

/** A repository whose history has one merge. */
function withMerge(): string {
  const dir = makeTempDir('history-view-');
  git(dir, 'init', '-q', '-b', 'main');
  writeFileSync(join(dir, 'a.txt'), 'a\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
  git(dir, 'checkout', '-q', '-b', 'side');
  writeFileSync(join(dir, 'b.txt'), 'b\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'side');
  git(dir, 'checkout', '-q', 'main');
  writeFileSync(join(dir, 'c.txt'), 'c\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'main');
  git(dir, 'merge', '-q', '--no-ff', '--no-edit', 'side');
  return dir;
}

// The two cases below are about a git that has both (2.40+); the host's may
// not — Debian 12, the test:docker images, ships 2.39 — so its version is
// pinned here, and the older ones have the last case.
const MODERN_GIT = '2.47.3';

describe('the history view (runners/historyView.ts)', () => {
  it('a git with remerge-diff and GIT_ATTR_SOURCE: a merges pass, every file as text, nothing to name', async () => {
    fake.version = MODERN_GIT;
    const dir = withMerge();
    const view = await openHistoryView(dir, process.env, ['--all']);
    try {
      expect(view.merges?.count).toBe(1);
      expect(view.limits).toEqual([]);
      // The attributes file, through the environment: nothing written in the repository.
      const keys = Object.entries(view.env).filter(([k]) => /^GIT_CONFIG_KEY_\d+$/.test(k)).map(([, v]) => v);
      expect(keys).toContain('core.attributesFile');
      expect(view.env['GIT_OBJECT_DIRECTORY']).toBeUndefined();
      expect(view.merges?.env['GIT_OBJECT_DIRECTORY']).toBeDefined();
      expect(REMERGE_DIFF).toBe('--diff-merges=remerge');
    } finally {
      expect(view.remove()).toBeNull();
    }
    const scratch = view.merges?.env['GIT_OBJECT_DIRECTORY'] ?? '';
    expect(existsSync(scratch)).toBe(false);
  });

  it('no merge in the walk: no merges pass', async () => {
    fake.version = MODERN_GIT;
    const dir = makeTempDir('history-view-');
    git(dir, 'init', '-q', '-b', 'main');
    writeFileSync(join(dir, 'a.txt'), 'a\n');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'base');
    const view = await openHistoryView(dir, process.env, ['--all']);
    view.remove();
    expect(view.merges).toBeNull();
    expect(view.limits).toEqual([]);
  });

  it.each([
    ['2.34.1', ["1 merge commit(s)' own changes were not read (--diff-merges=remerge needs git 2.36; this git is 2.34)"]],
    ['2.39.5 (Apple Git-154)', []],
  ])('git %s: no merges pass on a git without remerge-diff, and the tree\'s attributes named below 2.40', async (version, mergeLimits) => {
    fake.version = version;
    const dir = withMerge();
    const view = await openHistoryView(dir, process.env, ['--all']);
    view.remove();
    expect(view.merges === null).toBe(mergeLimits.length > 0);
    expect(view.limits).toEqual([
      expect.stringContaining('GIT_ATTR_SOURCE needs git 2.40'),
      ...mergeLimits,
    ]);
  });
});
