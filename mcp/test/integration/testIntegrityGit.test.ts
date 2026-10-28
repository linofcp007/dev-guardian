/**
 * The test-integrity check on real git repositories
 * (`testintegrity/gitChanges.ts`): the change from a base's merge base to a
 * commit, the index or the working tree (untracked files included), with
 * renames detected, a subdirectory project, and a base that shares no
 * history — and what a scoped scan_sast reads of it (`scope.changes`).
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { resolveScope } from '../../src/platform/scope.js';
import { parseUnifiedZero, readChangeSet, runTestIntegrityCheck } from '../../src/testintegrity/gitChanges.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 120_000 });
afterAll(cleanupTempDirs);

function git(cwd: string, ...args: string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, rel: string, text: string): void {
  const abs = join(dir, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

const SUM_TEST = [
  "import { sum } from './sum';",
  '',
  "describe('sum', () => {",
  "  it('adds', () => {",
  '    expect(sum(1, 1)).toBe(2);',
  '    expect(sum(2, 2)).toBe(4);',
  '  });',
  "  it('handles zero', () => {",
  '    expect(sum(0, 0)).toBe(0);',
  '  });',
  '});',
  '',
].join('\n');

/** main with a suite, then a `feature` branch checked out. */
function repo(): { dir: string; base: string } {
  const dir = makeTempDir('test-integrity-');
  git(dir, 'init', '-q');
  git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  write(dir, 'src/sum.ts', 'export const sum = (a: number, b: number) => a + b;\n');
  write(dir, 'src/sum.test.ts', SUM_TEST);
  write(dir, 'src/old.test.ts', "it('old', () => { expect(1).toBe(1); });\n");
  write(dir, 'tests/test_api.py', 'def test_ok():\n    assert 1 == 1\n');
  write(dir, 'package.json', JSON.stringify({ name: 'app', scripts: { test: 'vitest run', build: 'tsc' } }, null, 2));
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'base');
  const base = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'checkout', '-q', '-b', 'feature');
  return { dir, base };
}

const rows = (findings: Array<{ rule_id?: string; file_path?: string; line_start?: number; severity: string }>): string[] =>
  findings.map((f) => `${f.rule_id} ${f.file_path}:${f.line_start ?? '-'} ${f.severity}`).sort();

/** The weakening an agent does to make a red suite green — committed on the branch. */
function weaken(dir: string): void {
  write(dir, 'src/sum.test.ts', SUM_TEST.replace("it('adds'", "it.only('adds'").replace('    expect(sum(2, 2)).toBe(4);\n', ''));
  rmSync(join(dir, 'src/old.test.ts'));
  write(dir, 'tests/test_api.py', 'import pytest\n\n@pytest.mark.skip(reason="later")\ndef test_ok():\n    assert 1 == 1\n');
  write(dir, 'package.json', JSON.stringify({ name: 'app', scripts: { test: 'vitest run --passWithNoTests', build: 'tsc' } }, null, 2));
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'make it green');
}

const EXPECTED = [
  'test-assertions-removed src/sum.test.ts:6 medium',
  'test-file-deleted src/old.test.ts:- medium',
  'test-focused src/sum.test.ts:4 high',
  'test-script-always-passes package.json:4 medium',
  'test-skipped tests/test_api.py:3 medium',
];

describe('runTestIntegrityCheck', () => {
  it('a branch, read at its commit: every weakening, on its line', async () => {
    const { dir } = repo();
    weaken(dir);
    const head = git(dir, 'rev-parse', 'HEAD');
    const r = await runTestIntegrityCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head } });
    expect(r?.toolRun.status).toBe('ok');
    expect(r?.toolRun.name).toBe('guardian-test-integrity');
    expect(r?.missing).toEqual([]);
    expect(rows(r?.findings ?? [])).toEqual(EXPECTED);
  });

  it('the same change uncommitted (working tree), and a new untracked test file with a focus', async () => {
    const { dir } = repo();
    write(dir, 'src/sum.test.ts', SUM_TEST.replace("it('adds'", "it.only('adds'"));
    write(dir, 'src/new.test.ts', "describe('new', () => {\n  it.only('x', () => {});\n});\n");
    const r = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rows(r?.findings ?? [])).toEqual(['test-focused src/new.test.ts:2 high', 'test-focused src/sum.test.ts:4 high']);
    const tracked = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: false } });
    expect(rows(tracked?.findings ?? [])).toEqual(['test-focused src/sum.test.ts:4 high']);
  });

  it('the index: what is staged, not what is only in the working tree', async () => {
    const { dir, base } = repo();
    write(dir, 'src/sum.test.ts', SUM_TEST.replace("it('adds'", "it.skip('adds'"));
    git(dir, 'add', 'src/sum.test.ts');
    write(dir, 'tests/test_api.py', 'import pytest\n\n@pytest.mark.skip\ndef test_ok():\n    assert 1 == 1\n');
    const r = await runTestIntegrityCheck(dir, { base, target: { kind: 'index' } });
    expect(rows(r?.findings ?? [])).toEqual(['test-skipped src/sum.test.ts:4 medium']);
  });

  it('a renamed test file is no deletion; renamed to a name no runner picks up, it is', async () => {
    const { dir } = repo();
    git(dir, 'mv', 'src/sum.test.ts', 'src/sum.spec.ts');
    git(dir, 'mv', 'src/old.test.ts', 'src/old.ts.disabled');
    git(dir, 'commit', '-qm', 'rename');
    const head = git(dir, 'rev-parse', 'HEAD');
    const r = await runTestIntegrityCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head } });
    expect(rows(r?.findings ?? [])).toEqual(['test-file-deleted src/old.test.ts:- medium']);
  });

  it('a project in a subdirectory of its repository: paths relative to the project', async () => {
    const root = makeTempDir('test-integrity-mono-');
    git(root, 'init', '-q');
    git(root, 'symbolic-ref', 'HEAD', 'refs/heads/main');
    write(root, 'apps/web/src/a.test.ts', "it('a', () => { expect(1).toBe(1); });\n");
    write(root, 'apps/api/src/b.test.ts', "it('b', () => { expect(1).toBe(1); });\n");
    git(root, 'add', '-A');
    git(root, 'commit', '-qm', 'base');
    write(root, 'apps/web/src/a.test.ts', "it.only('a', () => { expect(1).toBe(1); });\n");
    write(root, 'apps/api/src/b.test.ts', "it.only('b', () => { expect(1).toBe(1); });\n");
    const r = await runTestIntegrityCheck(join(root, 'apps', 'web'), { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rows(r?.findings ?? [])).toEqual(['test-focused src/a.test.ts:1 high']);
  });

  it('a change that touches no test file: null — the check does not apply', async () => {
    const { dir } = repo();
    write(dir, 'src/sum.ts', 'export const sum = (a: number, b: number) => b + a;\n');
    expect(await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } })).toBeNull();
  });

  it('a base that names no commit is a failed run (a gap), never a clean one', async () => {
    const { dir } = repo();
    const r = await runTestIntegrityCheck(dir, { base: 'no-such-ref', target: { kind: 'worktree', untracked: true } });
    expect(r?.toolRun.status).toBe('failed');
    expect(r?.missing).toEqual(['guardian-test-integrity']);
  });

  // Fix round 1, item 7: compared with the base's tip, the base's own changes
  // since the fork read reversed (its new test "deleted", its removed skip
  // "added") — so no merge base is not judged at all: skipped, said, no gap.
  it('a base with no merge base (unrelated history, a shallow clone): skipped with the reason, no finding, no gap', async () => {
    const { dir } = repo();
    git(dir, 'checkout', '-q', '--orphan', 'other');
    git(dir, 'rm', '-rq', '--cached', '.');
    write(dir, 'src/sum.test.ts', SUM_TEST.replace("it('adds'", "it.only('adds'"));
    git(dir, 'add', 'src/sum.test.ts');
    git(dir, 'commit', '-qm', 'orphan');
    const r = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: false } });
    expect(r?.toolRun.status).toBe('skipped');
    expect(r?.toolRun.reason).toMatch(/no merge base of main and HEAD in this clone .*not read/);
    expect(r?.findings).toEqual([]);
    expect(r?.missing).toEqual([]);
  });

  // Fix round 1, item 7: a move without `git mv` — the old path deleted, the
  // new one untracked — is a rename, and only its NEW lines are read.
  it('an unstaged move of a test file: no deletion, the old skip not re-reported, only the new focus', async () => {
    const { dir } = repo();
    write(dir, 'src/legacy.test.ts', SUM_TEST.replace("it('handles zero'", "it.skip('handles zero'"));
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'a legacy suite with a skip');
    renameSync(join(dir, 'src', 'legacy.test.ts'), join(dir, 'src', 'moved.test.ts'));
    write(dir, 'src/moved.test.ts', SUM_TEST.replace("it('handles zero'", "it.skip('handles zero'").replace("it('adds'", "it.only('adds'"));
    const r = await runTestIntegrityCheck(dir, { base: 'HEAD', target: { kind: 'worktree', untracked: true } });
    expect(rows(r?.findings ?? [])).toEqual(['test-focused src/moved.test.ts:4 high']);
    // A move to a name no runner picks up is still a deletion.
    renameSync(join(dir, 'src', 'moved.test.ts'), join(dir, 'src', 'moved.ts.bak'));
    const out = await runTestIntegrityCheck(dir, { base: 'HEAD', target: { kind: 'worktree', untracked: true } });
    expect(rows(out?.findings ?? [])).toEqual(['test-file-deleted src/legacy.test.ts:- medium']);
  });
});

describe('readChangeSet and the -U0 reader', () => {
  it('numbers added lines in the new file, removed lines where their hunk lands', () => {
    const diff = ['diff --git a/x b/x', '@@ -3,2 +3,0 @@', '-gone1', '-gone2', '@@ -8 +7,2 @@', '-old', '+new1', '+new2'].join('\n');
    expect(parseUnifiedZero(diff)).toEqual({
      added: [
        { line: 7, text: 'new1' },
        { line: 8, text: 'new2' },
      ],
      removed: [
        { line: 4, text: 'gone1' },
        { line: 4, text: 'gone2' },
        { line: 7, text: 'old' },
      ],
    });
  });

  it('member keeps a scope to its paths', async () => {
    const { dir } = repo();
    weaken(dir);
    const read = await readChangeSet(dir, git(dir, 'rev-parse', 'main'), { kind: 'worktree', untracked: false }, (p) => p.startsWith('tests/'));
    expect(read.changes.map((c) => c.path)).toEqual(['tests/test_api.py']);
  });
});

describe('scope.changes — what a diff-scoped scan reads for the check', () => {
  it('diff.base: the base to the working tree; uncommitted: HEAD to the working tree; staged: HEAD to the index; paths and a since date: none', async () => {
    const { dir, base } = repo();
    weaken(dir);
    const head = git(dir, 'rev-parse', 'HEAD');
    const opts = { exclusions: null };
    expect((await resolveScope(dir, { diff: { base: 'main' } }, opts)).changes).toEqual({ base, target: 'worktree', untracked: false });
    expect((await resolveScope(dir, { diff: {} }, opts)).changes).toEqual({ base: head, target: 'worktree', untracked: true });
    expect((await resolveScope(dir, { diff: { staged: true } }, opts)).changes).toEqual({ base: head, target: 'index', untracked: false });
    expect((await resolveScope(dir, { since: 'main' }, opts)).changes).toEqual({ base, target: 'worktree', untracked: false });
    expect((await resolveScope(dir, { paths: ['src'] }, opts)).changes).toBeNull();
    expect((await resolveScope(dir, { since: '2 weeks ago' }, opts)).changes).toBeNull();
  });
});
