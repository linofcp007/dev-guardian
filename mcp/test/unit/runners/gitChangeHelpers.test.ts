/**
 * The two change-listing helpers `runners/git.ts` shares (moved out of
 * `testintegrity/gitChanges.ts`, where the test-integrity and suppressions
 * passes keep using them): `mergeBase` — the commit a `base...head` change is
 * read from — and `parseNameStatus` — a `--name-status -z` listing as
 * statuses and paths. Both on a real repository and git's own listing.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { git as runGit, mergeBase, parseNameStatus, type GitResult, type NameStatusEntry } from '../../../src/runners/git.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);

function git(cwd: string, args: readonly string[], input?: string): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    encoding: 'utf8',
    ...(input !== undefined ? { input } : {}),
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, rel: string, text: string): void {
  const abs = join(dir, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

const LINES = Array.from({ length: 12 }, (_, i) => `line ${i + 1} of a file long enough to be paired`).join('\n') + '\n';

function repo(prefix: string): string {
  const dir = makeTempDir(prefix);
  git(dir, ['init', '-q']);
  git(dir, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
  return dir;
}

const byPath = (a: NameStatusEntry, b: NameStatusEntry): number => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

describe('runners/git.ts: mergeBase and parseNameStatus', () => {
  it('parseNameStatus reads every status of a real listing: M and T modified, a copy added, a rename with its old path, U left out', async () => {
    const dir = repo('git-name-status-');
    write(dir, 'keep.txt', 'one\n');
    write(dir, 'link', 'target\n');
    write(dir, 'gone.txt', 'bye\n');
    write(dir, 'old name.py', LINES);
    write(dir, 'src.txt', `${LINES}source\n`);
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-qm', 'base']);
    const base = git(dir, ['rev-parse', 'HEAD']);

    write(dir, 'keep.txt', 'one\ntwo\n');
    // A type change (a file to a symbolic link) through the index alone: no link on disk, on every platform.
    const blob = git(dir, ['hash-object', '-w', '--stdin'], 'target');
    git(dir, ['update-index', '--cacheinfo', `120000,${blob},link`]);
    git(dir, ['rm', '-q', 'gone.txt']);
    mkdirSync(join(dir, 'pkg'));
    git(dir, ['mv', 'old name.py', 'pkg/new name.py']);
    write(dir, 'copy.txt', `${LINES}source\n`);
    write(dir, 'añadido.ts', 'export const x = 1;\n');
    git(dir, ['add', 'keep.txt', 'copy.txt', 'añadido.ts']);
    git(dir, ['commit', '-qm', 'head']);
    const head = git(dir, ['rev-parse', 'HEAD']);

    const listing = await runGit(dir, ['diff', '-z', '--name-status', '-M', '-C', '--find-copies-harder', '--relative', base, head, '--']);
    expect(listing.exitCode).toBe(0);
    // git's own letters, as it printed them (an unmerged `U` only a conflicted work tree lists: appended).
    const letters = listing.stdout.split('\0').filter((p) => /^[A-Z]\d*$/.test(p)).map((c) => c.charAt(0)).sort();
    expect(letters).toEqual(['A', 'C', 'D', 'M', 'R', 'T']);

    const expected: NameStatusEntry[] = [
      { status: 'modified', path: 'keep.txt' },
      { status: 'modified', path: 'link' },
      { status: 'deleted', path: 'gone.txt' },
      { status: 'renamed', path: 'pkg/new name.py', oldPath: 'old name.py' },
      { status: 'added', path: 'copy.txt' },
      { status: 'added', path: 'añadido.ts' },
    ];
    expect([...parseNameStatus(`${listing.stdout}U\0conflicted.txt\0`)].sort(byPath)).toEqual(expected.sort(byPath));
    expect(parseNameStatus('')).toEqual([]);
  });

  it('mergeBase: the fork commit; null for no shared history, no such ref, an option-shaped ref, a failed or non-sha answer', async () => {
    const dir = repo('git-merge-base-');
    write(dir, 'a.txt', 'a\n');
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-qm', 'fork']);
    const fork = git(dir, ['rev-parse', 'HEAD']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
    write(dir, 'b.txt', 'b\n');
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-qm', 'feature']);
    git(dir, ['checkout', '-q', 'main']);
    write(dir, 'c.txt', 'c\n');
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-qm', 'main']);
    // A commit that shares no history with either branch.
    const lone = git(dir, ['commit-tree', git(dir, ['mktree'], ''), '-m', 'lone']);

    expect(await mergeBase(dir, 'main', 'feature')).toBe(fork);
    expect(await mergeBase(dir, 'main', lone)).toBeNull();
    expect(await mergeBase(dir, 'no-such-branch', 'main')).toBeNull();
    // Read as a ref, never as an option: `git merge-base --independent feature` would answer feature's own commit.
    expect(await mergeBase(dir, '--independent', 'feature')).toBeNull();

    // The runner given is the one asked, once.
    const calls: string[][] = [];
    const counting = async (cwd: string, args: readonly string[]): Promise<GitResult> => {
      calls.push([...args]);
      return runGit(cwd, args);
    };
    expect(await mergeBase(dir, 'main', 'feature', counting)).toBe(fork);
    expect(calls).toEqual([['merge-base', '--end-of-options', 'main', 'feature']]);
    expect(await mergeBase(dir, 'main', 'feature', async () => ({ exitCode: 1, stdout: `${fork}\n`, stderr: '' }))).toBeNull();
    expect(await mergeBase(dir, 'main', 'feature', async () => ({ exitCode: 0, stdout: 'not a commit\n', stderr: '' }))).toBeNull();
  });
});
