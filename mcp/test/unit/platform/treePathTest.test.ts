/**
 * "Is this path in the project?" asked of a commit's tree instead of the disk
 * (3.18.0, DG-14): `review_pr` of a head that is not checked out reads head's
 * tree while the working tree holds another commit's, so the `.guardianignore`
 * result filter takes head's top-level entries (`runners/git.ts#headTopLevel`)
 * through `platform/guardianIgnore.ts#treePathTest`. The disk's
 * `projectPathTest` and the tree's answer one question: on a working tree that
 * equals the commit, they must agree on every spelling the disk test is held
 * to (`pathCheckCost.test.ts`) — that equality is the property.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { isProjectPath, keptByExclusions, loadProjectExclusions, treePathTest } from '../../../src/platform/guardianIgnore.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { headTopLevel } from '../../../src/runners/git.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

/** Real `git` processes: a file-level ceiling for a loaded full-suite run. */
vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);

function git(cwd: string, args: readonly string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, rel: string, text = 'x = 1\n'): void {
  const abs = join(dir, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

/** `pathCheckCost.test.ts`'s tree (three directories of files, a top-level file), committed: the disk equals HEAD. */
function committedTree(): { dir: string; head: string } {
  const dir = resolveProjectPath(makeTempDir('tree-path-')).path;
  for (const d of ['bulk/d0', 'bulk/d1', 'bulk/d1/deep']) for (let n = 0; n < 3; n++) write(dir, `${d}/f${String(n)}.py`);
  write(dir, 'top.py', '');
  git(dir, ['init', '-q']);
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-qm', 'base']);
  return { dir, head: git(dir, ['rev-parse', 'HEAD']) };
}

/** `pathCheckCost.test.ts`'s spellings, and more with a `.`/`..` segment, where the disk test walks. */
const SPELLINGS = [
  'bulk/d0/f1.py', // a file
  'bulk/d0/gone.py', // deleted, its directory still here
  'bulk/gone/deeper/x.py', // deleted with its directory, an ancestor still here
  'top.py', // a top-level file
  'gone-top.py', // a deleted top-level file: nothing left to place it by
  'nowhere/x.py', // no ancestor at all
  './bulk\\d1\\f2.py', // another spelling
  'bulk/d1/', // a directory
  'bulk', // a top-level directory
  'nowhere/..', // lexically the project root
  'bulk/d0/./f1.py',
  'nowhere/../top.py',
  'nowhere/../gone-top.py', // the walk places it by `nowhere/..`, the root
  'bulk/d0/../../gone-top.py',
  'bulk/../../outside.py', // `bulk/..` is the root
  'nowhere/./x.py',
  '.',
  'alpine:3.18 (alpine 3.18.4)', // an image target
  'Node.js', // Trivy's pseudo-target
  '/etc/passwd',
  'C:/Windows/x.py',
  '../outside.py',
  '..',
  '',
];

describe('treePathTest — the disk test asked of a git tree', () => {
  it('answers exactly as the disk does when the working tree is the commit, for every spelling', async () => {
    const { dir, head } = committedTree();
    const top = await headTopLevel(dir, head);
    if (top === null) throw new Error('git listed nothing');
    const inTree = treePathTest(top);
    const answers = SPELLINGS.map((p) => [p, inTree(p)] as const);
    for (const [p, answer] of answers) expect(answer, p).toBe(isProjectPath(dir, p));
    // Both answers occur: the equality is not two constant functions.
    expect(new Set(answers.map(([, a]) => a))).toEqual(new Set([true, false]));
  });

  it("a deleted directory is not in the project, a deleted file of a kept directory is: head's tree, not the disk's", async () => {
    const { dir } = committedTree();
    git(dir, ['rm', '-rq', 'bulk/d1']);
    git(dir, ['rm', '-q', 'bulk/d0/f0.py', 'top.py']);
    git(dir, ['commit', '-qm', 'drop']);
    git(dir, ['checkout', '-q', 'HEAD~1']);
    // The disk is the parent commit again; the tree is the child's.
    const top = await headTopLevel(dir, git(dir, ['rev-parse', 'HEAD@{1}']));
    if (top === null) throw new Error('git listed nothing');
    const inTree = treePathTest(top);
    expect(inTree('bulk/d1/deep/f0.py')).toBe(true); // bulk/ is still a top-level entry
    expect(inTree('bulk/d0/f0.py')).toBe(true);
    expect(inTree('top.py')).toBe(false); // gone from head, on the disk still
    expect(isProjectPath(dir, 'top.py')).toBe(true);
  });

  it('refuses a drive-letter path as the disk test does, even where a tree holds an entry of that name', () => {
    // A POSIX repository can commit a file named `C:`; no Windows path is a project path.
    const inTree = treePathTest(new Set(['C:', 'D:x', 'src']));
    expect(inTree('C:/Windows/x.py')).toBe(false);
    expect(inTree('D:x/y.py')).toBe(false);
    expect(inTree('src/C:/x.py')).toBe(true);
  });
});

describe('keptByExclusions — the result filter', () => {
  it('with no third argument, the disk test: what 3.17 kept', async () => {
    const { dir } = committedTree();
    write(dir, '.guardianignore', 'bulk/d1/\n*.py\nNode.js\nalpine*\n');
    const ex = await loadProjectExclusions(dir);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    const kept = keptByExclusions(ex, dir);
    for (const p of SPELLINGS) expect(kept(p), p).toBe(!(ex.ignores(p) && isProjectPath(dir, p)));
  });

  it('with one, that answer: a path no tree holds is kept, one every tree holds is dropped when ignored', async () => {
    const { dir } = committedTree();
    write(dir, '.guardianignore', 'bulk/\n');
    const ex = await loadProjectExclusions(dir);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(keptByExclusions(ex, dir, () => false)('bulk/d0/f1.py')).toBe(true);
    expect(keptByExclusions(ex, dir, () => true)('bulk/d0/gone.py')).toBe(false);
    expect(keptByExclusions(ex, dir, () => true)('src/x.py')).toBe(true); // not ignored
  });
});

describe('headTopLevel — one ls-tree of the project directory', () => {
  it('the top-level entries of a commit, from the root or from a project in a subdirectory; null when git cannot answer', async () => {
    const dir = makeTempDir('head-top-');
    git(dir, ['init', '-q']);
    for (const rel of ['app/src/a.py', 'app/legacy/x.js', 'app/top.py', 'other/c.txt', 'root.txt', 'with space/a b.py', 'héllo.py']) write(dir, rel);
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-qm', 'base']);
    const first = git(dir, ['rev-parse', 'HEAD']);
    git(dir, ['rm', '-rq', 'app/legacy', 'other']);
    git(dir, ['commit', '-qm', 'drop']);
    const second = git(dir, ['rev-parse', 'HEAD']);
    write(dir, 'untracked.txt');

    expect(await headTopLevel(dir, first)).toEqual(new Set(['app', 'other', 'root.txt', 'with space', 'héllo.py']));
    expect(await headTopLevel(dir, second)).toEqual(new Set(['app', 'root.txt', 'with space', 'héllo.py']));
    const app = join(dir, 'app');
    expect(await headTopLevel(app, first)).toEqual(new Set(['legacy', 'src', 'top.py']));
    expect(await headTopLevel(app, second)).toEqual(new Set(['src', 'top.py']));
    // A project directory the commit does not have: nothing is in the project.
    expect(await headTopLevel(join(dir, 'with space'), git(dir, ['commit-tree', '-m', 'empty', git(dir, ['mktree'])]))).toEqual(new Set());
    expect(await headTopLevel(dir, 'f'.repeat(40))).toBeNull();
    // A rev spelt like an option is only ever a rev.
    expect(await headTopLevel(dir, '--full-tree')).toBeNull();
  });
});
