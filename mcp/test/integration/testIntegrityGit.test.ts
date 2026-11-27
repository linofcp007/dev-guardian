/**
 * The test-integrity check on real git repositories
 * (`testintegrity/gitChanges.ts`): the change from a base's merge base to a
 * commit, the index or the working tree (untracked files included), with
 * renames detected, a subdirectory project, and a base that shares no
 * history — and what a scoped scan_sast reads of it (`scope.changes`).
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, renameSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
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

  // 3.18.0 review 1: `GIT_DIFF_OPTS` overrides `-U` and `diff.interHunkContext` fuses hunks, so the check's own
  // `-U0` diffs can hold kept lines: a kept line in a hunk still counts a line.
  it('a diff with context lines numbers the added lines the same as its -U0 form', () => {
    const before = ['a', 'b', 'c', 'd', 'e', '', 'f'];
    const after = ['a', 'B', 'c', 'd', 'E', '', 'f', 'g'];
    const zero = ['@@ -2 +2 @@', '-b', '+B', '@@ -5 +5 @@', '-e', '+E', '@@ -7,0 +8 @@', '+g'].join('\n');
    // The same change with three lines of context, a blank kept line printed empty (`diff.suppressBlankEmpty`).
    const wide = ['@@ -1,7 +1,8 @@', ' a', '-b', '+B', ' c', ' d', '-e', '+E', '', ' f', '+g'].join('\n');
    expect(before.length + 1).toBe(after.length);
    expect(parseUnifiedZero(wide).added).toEqual(parseUnifiedZero(zero).added);
    expect(parseUnifiedZero(wide).added.map((a) => [a.line, after[a.line - 1]])).toEqual([[2, 'B'], [5, 'E'], [8, 'g']]);
  });

  it('member keeps a scope to its paths', async () => {
    const { dir } = repo();
    weaken(dir);
    const read = await readChangeSet(dir, git(dir, 'rev-parse', 'main'), { kind: 'worktree', untracked: false }, (p) => p.startsWith('tests/'));
    expect(read.changes.map((c) => c.path)).toEqual(['tests/test_api.py']);
  });
});

// 3.18.0 review 2 (a lead of R2-DGBASE): the tree's own `.gitattributes` are the change's, and git applied them to
// every diff the check read — an `ident` attribute turned a skip written inside `$Id:…$` in the working tree back into
// the base's `$Id$` line (the file was not even listed), and a `binary` one printed "Binary files differ" and no
// line. Both passes now read the change with them set aside (`runners/git.ts#withoutTreeAttributes`), line endings
// compared with `--ignore-cr-at-eol`. Each repository sets `core.autocrlf=false`: with `true` (this machine's global)
// git would drop the CRs itself and the CRLF row would hold without the flag.
describe("the tree's own .gitattributes are set aside", () => {
  function attrRepo(files: Record<string, string>): string {
    const dir = makeTempDir('test-integrity-attrs-');
    git(dir, 'init', '-q');
    git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
    git(dir, 'config', 'core.autocrlf', 'false');
    for (const [rel, text] of Object.entries(files)) write(dir, rel, text);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'base');
    git(dir, 'checkout', '-q', '-b', 'feature');
    return dir;
  }
  // git's `ident` turns `$Id:` up to the next `$` of the line into `$Id$`: the skip sits between the two.
  const ID_TEST = "const id = '$Id$';\nit('adds', () => { expect(1 + 1).toBe(2); });\n";
  const ID_SKIP = "const id = '$Id: '; it.skip('adds', () => { expect(1 + 1).toBe(2); }); const end = '$';\nit('adds', () => { expect(1 + 1).toBe(2); });\n";

  // Legit first: a repository that checks its files out with CRLF from LF blobs. With the attributes set aside, git
  // no longer converts the working tree's side: without `--ignore-cr-at-eol` every line of a changed file reads as
  // added, and the skip that was already there is reported again.
  it('a repository that checks out CRLF (`* text eol=crlf`): a touched file is no change, and only the added line is read', async () => {
    const dir = attrRepo({
      '.gitattributes': '* text eol=crlf\n',
      'src/legacy.test.ts': "it.skip('old', () => {});\nit('adds', () => { expect(1).toBe(1); });\n",
    });
    rmSync(join(dir, 'src', 'legacy.test.ts'));
    git(dir, 'checkout', '-q', '--', 'src/legacy.test.ts');
    const crlf = "it.skip('old', () => {});\r\nit('adds', () => { expect(1).toBe(1); });\r\n";
    // The premise: the working tree holds CRLF, and a rewrite with the same bytes is stat-dirty.
    write(dir, 'src/legacy.test.ts', crlf);
    expect(await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } })).toBeNull();
    write(dir, 'src/legacy.test.ts', `${crlf}it.only('new', () => { expect(2).toBe(2); });\r\n`);
    const r = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rows(r?.findings ?? [])).toEqual(['test-focused src/legacy.test.ts:3 high']);
  });

  it('an `ident` attribute the change adds: a skip written inside `$Id:…$` in the working tree is still an added skip', async () => {
    const dir = attrRepo({ 'src/id.test.ts': ID_TEST });
    write(dir, '.gitattributes', '*.test.ts ident\n');
    write(dir, 'src/id.test.ts', ID_SKIP);
    // The premise: git, with the tree's attributes, sees no change at all.
    expect(git(dir, 'diff', '--name-only', 'main', '--')).toBe('');
    const worktree = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rows(worktree?.findings ?? [])).toEqual(['test-skipped src/id.test.ts:1 medium']);
  });

  // The stated limit (docs/ci.md): once `git add` has stored the cleaned file (`$Id$`: the commit holds no skip), git
  // trusts the working tree's stat and reads the file no more, with or without the attributes, so the skip the
  // working tree still runs is in no diff. The mtime is set back so that the index entry is not racily clean (git
  // would then read the file again, within the same second).
  it('the limit: an `ident` edit already staged or committed is in no diff', async () => {
    const dir = attrRepo({ 'src/id.test.ts': ID_TEST });
    write(dir, '.gitattributes', '*.test.ts ident\n');
    write(dir, 'src/id.test.ts', ID_SKIP);
    const past = new Date(Date.now() - 60_000);
    utimesSync(join(dir, 'src', 'id.test.ts'), past, past);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'ident');
    expect(git(dir, 'show', 'HEAD:src/id.test.ts')).toBe(ID_TEST.trim());
    expect(await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: false } })).toBeNull();
  });

  it('a `binary` attribute the change adds hides no skip: the index and commit targets', async () => {
    const dir = attrRepo({ 'src/b.test.ts': "it('adds', () => { expect(1).toBe(1); });\n" });
    write(dir, '.gitattributes', '*.test.ts binary\n');
    write(dir, 'src/b.test.ts', "it.skip('adds', () => { expect(1).toBe(1); });\n");
    git(dir, 'add', '-A');
    expect(git(dir, 'diff', '--cached', '--numstat', 'main', '--', 'src/b.test.ts')).toMatch(/^-\t-\t/);
    const staged = await runTestIntegrityCheck(dir, { base: 'main', target: { kind: 'index' } });
    expect(rows(staged?.findings ?? [])).toEqual(['test-skipped src/b.test.ts:1 medium']);
    git(dir, 'commit', '-qm', 'binary');
    const head = git(dir, 'rev-parse', 'HEAD');
    const committed = await runTestIntegrityCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head } });
    expect(rows(committed?.findings ?? [])).toEqual(['test-skipped src/b.test.ts:1 medium']);
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
