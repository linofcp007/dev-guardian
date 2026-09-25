/**
 * `resolveScope` — turning a `scope` input into the file set a scan reads,
 * on real git repositories.
 */

import { execa } from 'execa';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { loadProjectExclusions, type ProjectExclusions } from '../../../src/platform/guardianIgnore.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { resolveScope, ScopeError, type ScanScope } from '../../../src/platform/scope.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

/**
 * Real repositories, a dozen git commands per test: measured at 10.0 s (the
 * default ceiling) under a loaded full-suite run. A file-level ceiling, not a
 * global one — see vitest.config.ts.
 */
vi.setConfig({ testTimeout: 120_000 });

afterAll(cleanupTempDirs);

async function git(cwd: string, ...args: string[]): Promise<string> {
  return (await execa('git', args, { cwd })).stdout;
}

function write(dir: string, rel: string, content = 'x = 1\n'): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

async function repo(files: Record<string, string>): Promise<string> {
  const dir = resolveProjectPath(makeTempDir('scope-')).path;
  await git(dir, 'init', '-q');
  await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  for (const [p, c] of Object.entries(files)) write(dir, p, c);
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'base');
  return dir;
}

async function commitAll(dir: string, message = 'change'): Promise<void> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', message);
}

async function resolve(dir: string, scope: ScanScope, exclusions: ProjectExclusions | null = null) {
  return resolveScope(dir, scope, { exclusions });
}

async function refusal(dir: string, scope: ScanScope): Promise<ScopeError> {
  try {
    await resolve(dir, scope);
  } catch (e) {
    if (e instanceof ScopeError) return e;
    throw e;
  }
  throw new Error('expected a ScopeError');
}

describe('scope.paths', () => {
  it('takes files and directories relative to the project, directories expanded to their files', async () => {
    const dir = await repo({ 'a.py': '', 'src/b.py': '', 'src/deep/c.py': '', 'other/d.py': '' });
    const r = await resolve(dir, { paths: ['a.py', 'src'] });
    expect(r.kind).toBe('paths');
    expect(r.files).toEqual(['a.py', 'src/b.py', 'src/deep/c.py']);
    expect(r.member('src/new.py')).toBe(true);
    expect(r.member('other/d.py')).toBe(false);
    expect(r.history).toBeNull();
    expect(r.contentFiles).toEqual(r.files);
  });

  it('accepts an absolute path inside the project, `./` and backslashes', async () => {
    const dir = await repo({ 'src/b.py': '' });
    const r = await resolve(dir, { paths: [join(dir, 'src', 'b.py'), './src\\b.py'] });
    expect(r.files).toEqual(['src/b.py']);
  });

  it('expands a glob when no file has that literal name', async () => {
    const dir = await repo({ 'src/a.ts': '', 'src/b.py': '', 'lib/c.ts': '' });
    const r = await resolve(dir, { paths: ['**/*.ts'] });
    expect(r.files).toEqual(['lib/c.ts', 'src/a.ts']);
  });

  it('refuses a path that does not exist, and one outside the project', async () => {
    const dir = await repo({ 'a.py': '' });
    const missing = await refusal(dir, { paths: ['a.py', 'nope.py'] });
    expect(missing.code).toBe('target_not_found');
    expect(missing.message).toContain('nope.py');
    const outside = await refusal(dir, { paths: ['../elsewhere.py'] });
    expect(outside.code).toBe('unsupported_target');
    const absOutside = await refusal(dir, { paths: [join(dir, '..', 'x.py')] });
    expect(absOutside.code).toBe('unsupported_target');
  });

  it('works without git', async () => {
    const dir = resolveProjectPath(makeTempDir('scope-nogit-')).path;
    write(dir, 'x.py');
    const r = await resolve(dir, { paths: ['x.py'] });
    expect(r.files).toEqual(['x.py']);
  });

  it('drops .guardianignore-d files from the set and counts them', async () => {
    const dir = await repo({ '.guardianignore': 'fixtures/\n', 'src/a.py': '', 'src/fixtures/b.py': '' });
    const ex = await loadProjectExclusions(dir);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    const r = await resolve(dir, { paths: ['src'] }, ex);
    expect(r.files).toEqual(['src/a.py']);
    expect(r.excludedByIgnore).toBe(1);
  });
});

describe('scope.diff', () => {
  it('without base: the uncommitted changes — staged, unstaged and (by default) untracked — never a deleted file', async () => {
    const dir = await repo({ 'a.py': '', 'b.py': '', 'c.py': '', 'gone.py': '' });
    write(dir, 'a.py', 'a = 2\n'); // unstaged
    write(dir, 'b.py', 'b = 2\n');
    await git(dir, 'add', 'b.py'); // staged
    write(dir, 'new dir/n é.py'); // untracked
    rmSync(join(dir, 'gone.py'));
    const r = await resolve(dir, { diff: {} });
    expect(r.kind).toBe('diff');
    expect(r.files).toEqual(['a.py', 'b.py', 'new dir/n é.py']);
    expect(r.history).toBeNull();
    const noUntracked = await resolve(dir, { diff: { include_untracked: false } });
    expect(noUntracked.files).toEqual(['a.py', 'b.py']);
  });

  it('staged: only what is in the index', async () => {
    const dir = await repo({ 'a.py': '', 'b.py': '' });
    write(dir, 'a.py', 'a = 2\n');
    write(dir, 'b.py', 'b = 2\n');
    write(dir, 'u.py');
    await git(dir, 'add', 'b.py');
    const r = await resolve(dir, { diff: { staged: true } });
    expect(r.files).toEqual(['b.py']);
  });

  it('base: the files changed since the merge base, the commit range for history, refs resolved to ids', async () => {
    const dir = await repo({ 'a.py': '', 'b.py': '' });
    const mainSha = (await git(dir, 'rev-parse', 'HEAD')).trim();
    await git(dir, 'checkout', '-q', '-b', 'feature');
    write(dir, 'a.py', 'a = 2\n');
    write(dir, 'tmp.py');
    await commitAll(dir, 'one');
    rmSync(join(dir, 'tmp.py'));
    await commitAll(dir, 'two');
    const headSha = (await git(dir, 'rev-parse', 'HEAD')).trim();

    const r = await resolve(dir, { diff: { base: 'main' } });
    expect(r.files).toEqual(['a.py']);
    expect(r.history).toEqual({ base: mainSha, head: headSha });
    // A file touched by a commit of the range is in scope for results (a
    // secret added then deleted is still in the history), untouched files not.
    expect(r.member('tmp.py')).toBe(true);
    expect(r.member('b.py')).toBe(false);
    expect(r.meta).toMatchObject({ kind: 'diff', diff: { base: 'main', base_sha: mainSha, head_sha: headSha } });
  });

  it('refuses a base that names no commit, a head that is not checked out, staged with base, and no git', async () => {
    const dir = await repo({ 'a.py': '' });
    expect((await refusal(dir, { diff: { base: 'nope' } })).code).toBe('target_not_found');
    await git(dir, 'checkout', '-q', '-b', 'feature');
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    expect((await refusal(dir, { diff: { base: 'main', head: 'main' } })).code).toBe('unsupported_target');
    expect((await refusal(dir, { diff: { base: 'main', staged: true } })).code).toBe('unsupported_target');
    const plain = resolveProjectPath(makeTempDir('scope-plain-')).path;
    expect((await refusal(plain, { diff: {} })).code).toBe('not_a_git_repo');
  });

  it('a `--`-shaped ref is only ever a ref', async () => {
    const dir = await repo({ 'a.py': '' });
    expect((await refusal(dir, { diff: { base: '--output=/tmp/x' } })).code).toBe('target_not_found');
  });

  it('narrows to scope.paths when both are given', async () => {
    const dir = await repo({ 'src/a.py': '', 'lib/b.py': '' });
    write(dir, 'src/a.py', 'a = 2\n');
    write(dir, 'lib/b.py', 'b = 2\n');
    const r = await resolve(dir, { diff: {}, paths: ['src'] });
    expect(r.files).toEqual(['src/a.py']);
    expect(r.member('lib/b.py')).toBe(false);
  });
});

describe('scope.since', () => {
  it('a ref: the files changed since it, and exactly its commits for history', async () => {
    const dir = await repo({ 'a.py': '', 'b.py': '' });
    await git(dir, 'tag', 'v1');
    const tagSha = (await git(dir, 'rev-parse', 'HEAD')).trim();
    write(dir, 'b.py', 'b = 2\n');
    await commitAll(dir);
    const r = await resolve(dir, { since: 'v1' });
    expect(r.kind).toBe('since');
    expect(r.files).toEqual(['b.py']);
    expect(r.history).toMatchObject({ base: tagSha });
  });

  it('a date: the files of the commits since then, and --since for history', async () => {
    const dir = await repo({ 'a.py': '' });
    write(dir, 'b.py');
    await commitAll(dir);
    const r = await resolve(dir, { since: '2000-01-01' });
    expect(r.files).toEqual(['a.py', 'b.py']);
    expect(r.history).toEqual({ logOpts: '--since=2000-01-01' });
    const rel = await resolve(dir, { since: '2 weeks ago' });
    expect(rel.history).toEqual({ logOpts: '--since=2.weeks.ago' });
  });

  it('refuses something that is neither a commit nor a date, and a future date', async () => {
    const dir = await repo({ 'a.py': '' });
    expect((await refusal(dir, { since: 'banana' })).code).toBe('target_not_found');
    expect((await refusal(dir, { since: '2999-01-01' })).code).toBe('unsupported_target');
  });
});

describe('scope shape', () => {
  it('refuses an empty scope, and diff with since', async () => {
    const dir = await repo({ 'a.py': '' });
    expect((await refusal(dir, {})).code).toBe('unsupported_target');
    expect((await refusal(dir, { diff: {}, since: 'HEAD' })).code).toBe('unsupported_target');
  });
});
