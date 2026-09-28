import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { computeTreeHash } from '../../../src/treeHash/computeTreeHash.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function fixture(): string {
  const dir = makeTempDir('dev-guardian-treehash-');
  return dir;
}

/**
 * A committed monorepo: `packages/app/` is the project a caller would pass
 * as `project_path`, one level below the repository root.
 */
function monorepo(): { repo: string; pkg: string } {
  const repo = makeTempDir('dev-guardian-treehash-git-');
  const git = (...args: string[]): void => {
    execFileSync('git', ['-C', repo, ...args], { stdio: 'ignore' });
  };
  git('init', '-q');
  git('config', 'user.email', 't@example.com');
  git('config', 'user.name', 'T');
  git('config', 'core.autocrlf', 'false');
  const pkg = join(repo, 'packages', 'app');
  mkdirSync(join(pkg, 'src'), { recursive: true });
  writeFileSync(join(pkg, 'src', 'index.js'), 'console.log(1);\n');
  writeFileSync(join(pkg, '.gitignore'), 'ignored.log\n');
  writeFileSync(join(repo, 'README.md'), 'root\n');
  git('add', '.');
  git('commit', '-q', '-m', 'first');
  return { repo, pkg };
}

describe('computeTreeHash (git listing)', () => {
  it('changes when a tracked file inside a monorepo SUBDIRECTORY changes', async () => {
    // `git ls-files --full-name` returned repo-root-relative paths, which were
    // then joined to the subdirectory: every file read as `missing`, so the
    // hash never saw content at all.
    const { pkg } = monorepo();
    const before = await computeTreeHash(pkg);
    writeFileSync(join(pkg, 'src', 'index.js'), 'console.log(2);\n');
    const after = await computeTreeHash(pkg);
    expect(after).not.toBe(before);
  });

  it('changes when an untracked, non-ignored file is added', async () => {
    const { pkg } = monorepo();
    const before = await computeTreeHash(pkg);
    writeFileSync(join(pkg, 'src', 'new.js'), 'export const x = 1;\n');
    const after = await computeTreeHash(pkg);
    expect(after).not.toBe(before);
  });

  it('does not change when an ignored file is added', async () => {
    const { pkg } = monorepo();
    const before = await computeTreeHash(pkg);
    writeFileSync(join(pkg, 'ignored.log'), 'noise\n');
    const after = await computeTreeHash(pkg);
    expect(after).toBe(before);
  });

  it('does not change when the tool writes its own .guardian/ output or an un-ignored node_modules/', async () => {
    // With untracked files now part of the hash, a scan writing its report
    // under `.guardian/` would otherwise change the hash it was cached under
    // on every run, and the cache would never hit.
    const { pkg } = monorepo();
    const before = await computeTreeHash(pkg);
    mkdirSync(join(pkg, '.guardian', 'reports', 'sast-1'), { recursive: true });
    writeFileSync(join(pkg, '.guardian', 'reports', 'sast-1', 'sast.json'), '{}');
    mkdirSync(join(pkg, 'node_modules', 'dep'), { recursive: true });
    writeFileSync(join(pkg, 'node_modules', 'dep', 'index.js'), 'x');
    const after = await computeTreeHash(pkg);
    expect(after).toBe(before);
  });

  it('is not affected by files outside the subdirectory', async () => {
    const { repo, pkg } = monorepo();
    const before = await computeTreeHash(pkg);
    writeFileSync(join(repo, 'README.md'), 'changed\n');
    writeFileSync(join(repo, 'other.txt'), 'untracked sibling\n');
    const after = await computeTreeHash(pkg);
    expect(after).toBe(before);
  });
});

describe('computeTreeHash (filesystem walk)', () => {
  it('is deterministic across two runs', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'hello');
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'sub', 'b.txt'), 'world');

    const h1 = await computeTreeHash(dir, { forceFilesystemWalk: true });
    const h2 = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when a single byte changes', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'hello');
    const before = await computeTreeHash(dir, { forceFilesystemWalk: true });

    writeFileSync(join(dir, 'a.txt'), 'hellp');
    const after = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(before).not.toBe(after);
  });

  it('excludes .guardian/, node_modules/, .git/ from the walk', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'real');

    const baseline = await computeTreeHash(dir, { forceFilesystemWalk: true });

    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'noise.json'), 'x');
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'pkg.txt'), 'y');
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git', 'HEAD'), 'z');

    const afterNoise = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(baseline).toBe(afterNoise);
  });

  it('hash depends only on contents, not on directory entry order', async () => {
    const dirA = fixture();
    writeFileSync(join(dirA, 'a.txt'), '1');
    writeFileSync(join(dirA, 'b.txt'), '2');

    const dirB = fixture();
    // Different write order
    writeFileSync(join(dirB, 'b.txt'), '2');
    writeFileSync(join(dirB, 'a.txt'), '1');

    expect(await computeTreeHash(dirA, { forceFilesystemWalk: true })).toBe(
      await computeTreeHash(dirB, { forceFilesystemWalk: true }),
    );
  });
});
