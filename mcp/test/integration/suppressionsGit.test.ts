/**
 * The suppressions pass on real git repositories (`runSuppressionCheck`,
 * `testintegrity/gitChanges.ts`): every case of the fixture table committed
 * in one repository and read on the commit, index and worktree targets — the
 * `-G` listing equal to what the JS reader predicts (git's POSIX ERE and V8
 * read the tokens alike), the findings equal to the table's — a move without
 * `git mv`, a subdirectory project, the null rule, the git calls counted
 * (the property is a count), and the bounds and failures as notes, never a
 * gap.
 *
 * What must STILL hold: `testIntegrityGit.test.ts` — the test-integrity pass
 * is unchanged, its null rule included.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { git as realGit, type GitResult } from '../../src/runners/git.js';
import { runSuppressionCheck } from '../../src/testintegrity/gitChanges.js';
import { mayHoldSuppression } from '../../src/testintegrity/suppressions.js';
import { caseText, SUPPRESSION_CASES, suppressionCase, type SuppressionCase } from '../helpers/suppressionCases.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 300_000 });
afterAll(cleanupTempDirs);

function git(cwd: string, ...args: string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], {
    cwd,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, rel: string, text: string): void {
  const abs = join(dir, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

/** A git runner that records every call. */
function counting(): { run: (cwd: string, args: readonly string[]) => Promise<GitResult>; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    run: async (cwd, args) => {
      calls.push([...args]);
      return realGit(cwd, args);
    },
  };
}

/** A repository on main, `feature` checked out. */
function newRepo(prefix: string): string {
  const dir = makeTempDir(prefix);
  git(dir, 'init', '-q');
  git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  write(dir, 'README.md', 'x\n');
  return dir;
}

function branch(dir: string): void {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'base');
  git(dir, 'checkout', '-q', '-b', 'feature');
}

const addedOf = (c: SuppressionCase): number[] => c.added ?? c.lines.map((_, i) => i + 1);

/** Each case's file under `c<i>/`: its base (the lines not added) on main, all its lines on `feature`, uncommitted. */
function tableRepo(cases: readonly SuppressionCase[]): { dir: string; paths: Map<string, SuppressionCase> } {
  const dir = newRepo('suppressions-table-');
  const paths = new Map<string, SuppressionCase>();
  cases.forEach((c, i) => {
    const path = `c${String(i)}/${c.path}`;
    paths.set(path, c);
    const added = new Set(addedOf(c));
    const base = c.lines.filter((_, k) => !added.has(k + 1));
    if (base.length > 0) write(dir, path, `${base.join('\n')}\n`);
  });
  branch(dir);
  for (const [path, c] of paths) write(dir, path, caseText(c));
  return { dir, paths };
}

/** The `-G` listing's paths (`--name-status -z`: a status, then one path — two for a rename or a copy). */
function listedByPickaxe(calls: readonly string[][], stdout: string | undefined): string[] {
  expect(calls.filter((a) => a.includes('-G'))).toHaveLength(1);
  const parts = (stdout ?? '').split('\0').filter((s) => s !== '');
  const out: string[] = [];
  for (let i = 0; i < parts.length; ) {
    const two = /^[RC]/.test(parts[i] ?? '');
    out.push(parts[i + (two ? 2 : 1)] ?? '');
    i += two ? 3 : 2;
  }
  return out.sort();
}

const letters = (fs: ReadonlyArray<{ severity: string }>): string =>
  fs
    .map((f) => (f.severity === 'medium' ? 'M' : 'L'))
    .sort()
    .join('');

// The cases that remove a line carry directives across the change: read on their own (below), never in the shared repository.
const SHARED = SUPPRESSION_CASES.filter((c) => (c.removed ?? []).length === 0);

/** Each file's findings as `path letters`, and the table's. */
function findingsByFile(findings: ReadonlyArray<{ file_path?: string; severity: string }>, paths: ReadonlyMap<string, SuppressionCase>): { got: string[]; want: string[] } {
  const want = [...paths].map(([path, c]) => `${path} ${[...c.out].filter((l) => l === 'M' || l === 'L').sort().join('')}`).filter((s) => !s.endsWith(' '));
  const byFile = new Map<string, Array<{ severity: string }>>();
  for (const f of findings) byFile.set(f.file_path ?? '', [...(byFile.get(f.file_path ?? '') ?? []), f]);
  return { got: [...byFile].map(([path, fs]) => `${path} ${letters(fs)}`).sort(), want: want.sort() };
}

/** The files whose diff holds a token on an added line, by the JS reader: what git's -G must list. */
function predicted(paths: ReadonlyMap<string, SuppressionCase>, tracked: (c: SuppressionCase) => boolean): string[] {
  return [...paths]
    .filter(([, c]) => tracked(c) && addedOf(c).some((n) => mayHoldSuppression(c.lines[n - 1] ?? '')))
    .map(([path]) => path)
    .sort();
}

describe('runSuppressionCheck over every case of the table', () => {
  it("the working tree (untracked files included): the -G listing is the JS reader's, each file's findings its case's", async () => {
    const { dir, paths } = tableRepo(SHARED);
    let pickaxeOut: string | undefined;
    const { run, calls } = counting();
    const recording = async (cwd: string, args: readonly string[]): Promise<GitResult> => {
      const r = await run(cwd, args);
      if (args.includes('-G')) pickaxeOut = r.stdout;
      return r;
    };
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true }, git: recording });
    expect(r?.toolRun).toMatchObject({ name: 'guardian-suppressions', status: 'ok' });
    expect(r?.notes).toEqual([]);
    // Git lists the tracked files; the cases with no base are untracked, read from disk.
    expect(listedByPickaxe(calls, pickaxeOut)).toEqual(predicted(paths, (c) => addedOf(c).length < c.lines.length));
    const { got, want } = findingsByFile(r?.findings ?? [], paths);
    expect(got).toEqual(want);
    // And the counts, over the whole change.
    const count = (l: string): number => SHARED.reduce((n, c) => n + [...c.out].filter((x) => x === l).length, 0);
    expect(r?.toolRun.reason).toContain(`${String(count('N'))} naming the rule(s) they silence`);
    expect(r?.toolRun.reason).toContain(`${String(count('R'))} with a reason`);
  });

  // The listing alone on the two other targets: the per-file calls are answered without git (each file then counts as
  // unread) — what is held is that git's ERE lists exactly what V8 reads, every file being tracked here.
  for (const target of ['commit', 'index'] as const) {
    it(`${target}: the -G listing is the JS reader's`, async () => {
      const { dir, paths } = tableRepo(SHARED);
      git(dir, 'add', '-A');
      let head: string | undefined;
      if (target === 'commit') {
        git(dir, 'commit', '-qm', 'the cases');
        head = git(dir, 'rev-parse', 'HEAD');
      }
      let pickaxeOut: string | undefined;
      const { run, calls } = counting();
      const listingOnly = async (cwd: string, args: readonly string[]): Promise<GitResult> => {
        if (args[0] === 'diff' && !args.includes('-G')) return { exitCode: 1, stdout: '', stderr: 'not run here' };
        const r = await run(cwd, args);
        if (args.includes('-G')) pickaxeOut = r.stdout;
        return r;
      };
      await runSuppressionCheck(dir, {
        base: 'main',
        ...(head !== undefined ? { head, target: { kind: 'commit', sha: head } } : { target: { kind: 'index' } }),
        git: listingOnly,
      });
      expect(listedByPickaxe(calls, pickaxeOut)).toEqual(predicted(paths, () => true));
    });
  }

  it("a commit target, one case per row: each file's findings are its case's", async () => {
    const one = [...new Map(SHARED.filter((c) => c.out !== '').map((c) => [c.row, c])).values()];
    const { dir, paths } = tableRepo(one);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'the cases');
    const head = git(dir, 'rev-parse', 'HEAD');
    git(dir, 'checkout', '-q', 'main');
    const r = await runSuppressionCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head } });
    expect(r?.notes).toEqual([]);
    const { got, want } = findingsByFile(r?.findings ?? [], paths);
    expect(got).toEqual(want);
  });
});

describe('runSuppressionCheck: moves, scope, the null rule', () => {
  const BLANKET = suppressionCase('ESLint: the whole file, every rule');

  it('a file moved without git mv (deleted, its copy untracked): its directive is carried, not new', async () => {
    const dir = newRepo('suppressions-move-');
    write(dir, 'src/old.ts', `${caseText(BLANKET)}export const x = 1;\n`);
    branch(dir);
    renameSync(join(dir, 'src', 'old.ts'), join(dir, 'src', 'new.ts'));
    const moved = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(moved?.findings).toEqual([]);
    expect(moved?.toolRun.reason).toMatch(/no suppression added; 1 kept or moved from a removed line/);
    // A copy, the old file kept: the copy's directive is new.
    git(dir, 'checkout', '-q', '--', 'src/old.ts');
    const copied = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(copied?.findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)} ${f.severity}`)).toEqual([
      'suppression-added src/new.ts:1 medium',
    ]);
  });

  it('a project in a subdirectory of its repository: only its files, paths relative to it', async () => {
    const root = newRepo('suppressions-mono-');
    write(root, 'apps/web/src/a.ts', 'export const a = 1;\n');
    write(root, 'apps/api/src/b.ts', 'export const b = 1;\n');
    branch(root);
    write(root, 'apps/web/src/a.ts', `${caseText(BLANKET)}export const a = 1;\n`);
    write(root, 'apps/api/src/b.ts', `${caseText(BLANKET)}export const b = 1;\n`);
    const r = await runSuppressionCheck(join(root, 'apps', 'web'), { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(r?.findings.map((f) => f.file_path)).toEqual(['src/a.ts']);
  });

  it('null when no changed file of a read language holds a token: code with none, prose naming a directive', async () => {
    const dir = newRepo('suppressions-null-');
    write(dir, 'src/a.ts', 'export const a = 1;\n');
    branch(dir);
    write(dir, 'src/a.ts', 'export const a = 2;\n');
    write(dir, 'README.md', `x\n${suppressionCase('Semgrep: a comment').lines.join('\n')}\n`);
    expect(await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } })).toBeNull();
    // A fixture folder is not read either, nor an untracked file that holds no token.
    write(dir, 'test/fixtures/bad.ts', caseText(BLANKET));
    write(dir, 'src/new.ts', 'export const b = 1;\n');
    expect(await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } })).toBeNull();
  });

  it("a scope's member filter: only its files are read", async () => {
    const dir = newRepo('suppressions-scope-');
    branch(dir);
    write(dir, 'src/a.ts', caseText(BLANKET));
    write(dir, 'src/b.ts', caseText(BLANKET));
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true }, member: (p) => p === 'src/a.ts' });
    expect(r?.findings.map((f) => f.file_path)).toEqual(['src/a.ts']);
  });

  // Review 1 of 3.17.0, R1-DG-D-7: a byte-order mark before line 1. git's -U0 diff keeps it on the added line; the
  // worktree's text is read with it stripped, a commit's (git show) with it kept — and the C# pragma's grammar is
  // anchored at the line's start. Each target reads both files' first lines.
  for (const target of ['worktree', 'commit'] as const) {
    it(`a byte-order mark before line 1, ${target} target: the line is read`, async () => {
      const BOM = String.fromCharCode(0xfeff);
      const dir = newRepo('suppressions-bom-');
      write(dir, 'src/gen.ts', 'export const x = 1;\n');
      write(dir, 'src/A.cs', 'class A {}\n');
      branch(dir);
      write(dir, 'src/gen.ts', `${BOM}${caseText(BLANKET)}export const x = 1;\n`);
      write(dir, 'src/A.cs', `${BOM}${caseText(suppressionCase('C# pragma: bare'))}class A {}\n`);
      let head: string | undefined;
      if (target === 'commit') {
        git(dir, 'add', '-A');
        git(dir, 'commit', '-qm', 'generated');
        head = git(dir, 'rev-parse', 'HEAD');
        git(dir, 'checkout', '-q', 'main');
      }
      const r = await runSuppressionCheck(dir, {
        base: 'main',
        ...(head !== undefined ? { head, target: { kind: 'commit', sha: head } } : { target: { kind: 'worktree', untracked: true } }),
      });
      expect((r?.findings ?? []).map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)} ${f.severity}`).sort()).toEqual([
        'scanner-suppression-added src/A.cs:1 medium',
        'suppression-added src/gen.ts:1 medium',
      ]);
    });

    // Review 2 of 3.17.0, R2-DG-D-2: the removed side too — a change that only strips the mark from a file whose
    // line 1 already held a directive adds none. git's diff keeps the mark on the removed line, and the C# pragma's
    // grammar is anchored at the line's start: read with the mark, the removed pragma carried nothing.
    it(`a byte-order mark removed from line 1, ${target} target: nothing is added`, async () => {
      const BOM = String.fromCharCode(0xfeff);
      const dir = newRepo('suppressions-bom-removed-');
      write(dir, 'src/A.cs', `${BOM}${caseText(suppressionCase('C# pragma: bare'))}class A {}\n`);
      write(dir, 'src/gen.ts', `${BOM}${caseText(BLANKET)}export const x = 1;\n`);
      branch(dir);
      write(dir, 'src/A.cs', `${caseText(suppressionCase('C# pragma: bare'))}class A {}\n`);
      write(dir, 'src/gen.ts', `${caseText(BLANKET)}export const x = 1;\n`);
      let head: string | undefined;
      if (target === 'commit') {
        git(dir, 'add', '-A');
        git(dir, 'commit', '-qm', 'no mark');
        head = git(dir, 'rev-parse', 'HEAD');
        git(dir, 'checkout', '-q', 'main');
      }
      const r = await runSuppressionCheck(dir, {
        base: 'main',
        ...(head !== undefined ? { head, target: { kind: 'commit', sha: head } } : { target: { kind: 'worktree', untracked: true } }),
      });
      expect(r?.findings).toEqual([]);
      expect(r?.toolRun.reason).toMatch(/no suppression added; 2 kept or moved from a removed line \(not new\)/);
    });
  }
});

// 3.18.0 review 2, with testIntegrityGit.test.ts' rows: the tree's own `.gitattributes` are set aside for this pass's
// diffs too (an `ident` attribute collapsed a directive written inside `$Id:…$` in the working tree; a `binary` one hid
// a committed one), line endings compared with `--ignore-cr-at-eol`. The CRLF row sets the repository's own
// `core.autocrlf=false` (the pass's git reads it; `git()` above sets it only on its own calls): with `true`, git would
// drop the CRs itself and the row would hold without the flag.
describe("runSuppressionCheck: the tree's own .gitattributes are set aside", () => {
  const BLANKET = suppressionCase('ESLint: the whole file, every rule');
  const SEMGREP = suppressionCase('Semgrep: upper case');
  const rowsOf = (r: Awaited<ReturnType<typeof runSuppressionCheck>>): string[] =>
    (r?.findings ?? []).map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)} ${f.severity}`);

  it('a repository that checks out CRLF (`* text eol=crlf`): a touched file is no change, and an old directive is not new', async () => {
    const dir = newRepo('suppressions-crlf-');
    git(dir, 'config', 'core.autocrlf', 'false');
    write(dir, '.gitattributes', '* text eol=crlf\n');
    write(dir, SEMGREP.path, caseText(SEMGREP));
    branch(dir);
    rmSync(join(dir, ...SEMGREP.path.split('/')));
    git(dir, 'checkout', '-q', '--', SEMGREP.path);
    const crlf = caseText(SEMGREP).replace(/\n/g, '\r\n');
    write(dir, SEMGREP.path, crlf);
    expect(await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } })).toBeNull();
    // The same bare directive once more: only the new line is added, and nothing is carried from a removed one.
    write(dir, SEMGREP.path, `${crlf}${crlf}`);
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rowsOf(r)).toEqual([`scanner-suppression-added ${SEMGREP.path}:${String(SEMGREP.lines.length + 1)} medium`]);
    expect(r?.toolRun.reason).not.toMatch(/kept or moved/);
  });

  it('an `ident` attribute the change adds: a directive written inside `$Id:…$` in the working tree is read', async () => {
    const dir = newRepo('suppressions-ident-');
    write(dir, SEMGREP.path, '/* $Id$ */\nexport const a = 1;\n');
    branch(dir);
    write(dir, '.gitattributes', '*.js ident\n');
    write(dir, SEMGREP.path, `/* $Id: */ ${SEMGREP.lines.join(' ')} /* $ */\nexport const a = 1;\n`);
    expect(git(dir, 'diff', '--name-only', 'main', '--')).toBe('');
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(rowsOf(r)).toEqual([`scanner-suppression-added ${SEMGREP.path}:1 medium`]);
  });

  it('a `binary` attribute the change adds hides no committed directive', async () => {
    const dir = newRepo('suppressions-binary-');
    write(dir, BLANKET.path, 'export const a = 1;\n');
    branch(dir);
    write(dir, '.gitattributes', '*.ts binary\n');
    write(dir, BLANKET.path, `${caseText(BLANKET)}export const a = 1;\n`);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'binary');
    const head = git(dir, 'rev-parse', 'HEAD');
    const r = await runSuppressionCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head } });
    expect(rowsOf(r)).toEqual([`suppression-added ${BLANKET.path}:1 medium`]);
  });
});

describe('runSuppressionCheck: its git calls, counted', () => {
  // 300 changed source files, two of them adding a directive, one removing one, one under a fixture folder and one
  // README naming one: the pass diffs and reads only the three it must.
  function costRepo(): string {
    const dir = newRepo('suppressions-cost-');
    for (let i = 0; i < 300; i += 1) write(dir, `src/f${String(i).padStart(3, '0')}.ts`, `export const x${String(i)} = 0;\n`);
    write(dir, 'src/gone.ts', `${suppressionCase('ESLint: the next line, a rule').lines.join('\n')}\n`);
    branch(dir);
    for (let i = 0; i < 300; i += 1) write(dir, `src/f${String(i).padStart(3, '0')}.ts`, `export const x${String(i)} = 1;\n`);
    write(dir, 'src/f000.ts', `${caseText(BLANKET)}export const x0 = 1;\n`);
    write(dir, 'src/f001.ts', `${caseText(BLANKET)}export const x1 = 1;\n`);
    write(dir, 'src/gone.ts', 'console.log(x);\n');
    write(dir, 'src/fixtures/f.ts', caseText(BLANKET));
    write(dir, 'README.md', `x\n${suppressionCase('Semgrep: a comment').lines.join('\n')}\n`);
    git(dir, 'add', '-A');
    return dir;
  }
  const BLANKET = suppressionCase('ESLint: the whole file, every rule');
  const kinds = (calls: readonly string[][]): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const a of calls) {
      const k = a[0] === 'diff' ? (a.includes('-G') ? 'listing' : 'diff') : (a[0] ?? '');
      out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  };

  it('a commit target: the merge base, one listing, and per candidate a diff — and its text only when an added line holds a token', async () => {
    const dir = costRepo();
    git(dir, 'commit', '-qm', 'change');
    const head = git(dir, 'rev-parse', 'HEAD');
    const { run, calls } = counting();
    const r = await runSuppressionCheck(dir, { base: 'main', head, target: { kind: 'commit', sha: head }, git: run });
    expect(r?.findings.map((f) => f.file_path).sort()).toEqual(['src/f000.ts', 'src/f001.ts']);
    expect(kinds(calls)).toEqual({ 'merge-base': 1, listing: 1, diff: 3, show: 2 });
    const named = calls.filter((a) => a[0] === 'diff' && !a.includes('-G')).map((a) => a[a.length - 1]);
    expect(named.sort()).toEqual(['src/f000.ts', 'src/f001.ts', 'src/gone.ts']);
  });

  it('a worktree target: no show (the text is read from disk); untracked files add one listing', async () => {
    const dir = costRepo();
    const tracked = counting();
    await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: false }, git: tracked.run });
    expect(kinds(tracked.calls)).toEqual({ 'merge-base': 1, listing: 1, diff: 3 });
    const all = counting();
    await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true }, git: all.run });
    expect(kinds(all.calls)).toEqual({ 'merge-base': 1, listing: 1, diff: 3, 'ls-files': 1 });
  });
});

describe('runSuppressionCheck: bounds and failures are notes, never a gap', () => {
  const BLANKET = suppressionCase('ESLint: the whole file, every rule');
  function threeFiles(): string {
    const dir = newRepo('suppressions-bound-');
    for (const n of ['a', 'b', 'c']) write(dir, `src/${n}.ts`, 'export {};\n');
    branch(dir);
    for (const n of ['a', 'b', 'c']) write(dir, `src/${n}.ts`, `${caseText(BLANKET)}export {};\n`);
    return dir;
  }

  it('past the bound: the files read are judged, the rest counted in a note; status ok', async () => {
    const dir = threeFiles();
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: false }, maxFiles: 2 });
    expect(r?.toolRun.status).toBe('ok');
    expect(r?.findings).toHaveLength(2);
    expect(r?.notes).toEqual(['1 more changed file(s) with a suppression token past the first 2 were not read']);
    expect(r?.toolRun.reason).toContain(r?.notes[0] ?? '-');
  });

  it('untracked files past the bound: a note, the reads stop', async () => {
    const dir = newRepo('suppressions-untracked-');
    branch(dir);
    for (const n of ['a', 'b', 'c']) write(dir, `src/${n}.ts`, caseText(BLANKET));
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true }, maxFiles: 2 });
    expect(r?.findings).toHaveLength(2);
    expect(r?.notes).toEqual(['1 more untracked file(s) past the first 2 were not read for suppressions']);
  });

  it('a file over the text bound: not judged, counted in a note', async () => {
    const dir = newRepo('suppressions-big-');
    write(dir, 'src/big.ts', 'export {};\n');
    branch(dir);
    write(dir, 'src/big.ts', `${caseText(BLANKET)}${'// x\n'.repeat(450_000)}`);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'big');
    const head = git(dir, 'rev-parse', 'HEAD');
    for (const target of [{ kind: 'commit', sha: head } as const, { kind: 'worktree', untracked: false } as const]) {
      const r = await runSuppressionCheck(dir, { base: 'main', head, target });
      expect(r?.findings).toEqual([]);
      expect(r?.notes).toEqual(['1 changed file(s) over 2 MiB or unreadable were not read for suppressions']);
    }
  });

  it('a -G listing git refuses: skipped with the reason, the same note — no finding, no gap', async () => {
    const dir = threeFiles();
    const failing = async (cwd: string, args: readonly string[]): Promise<GitResult> =>
      args.includes('-G') ? { exitCode: 128, stdout: '', stderr: 'fatal: invalid regular expression\n' } : realGit(cwd, args);
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true }, git: failing });
    expect(r?.toolRun).toMatchObject({ name: 'guardian-suppressions', status: 'skipped' });
    expect(r?.findings).toEqual([]);
    expect(r?.notes).toEqual(['the change could not be listed for suppressions (fatal: invalid regular expression): no file was read for them']);
  });

  it('a base that names no commit: skipped, no note (the test-integrity pass says it, as its gap)', async () => {
    const dir = threeFiles();
    const r = await runSuppressionCheck(dir, { base: 'no-such-ref', target: { kind: 'worktree', untracked: true } });
    expect(r?.toolRun).toMatchObject({ status: 'skipped', reason: 'no-such-ref names no commit: the change was not read for suppressions' });
    expect(r?.notes).toEqual([]);
  });
});

describe('runSuppressionCheck: a carried directive across files', () => {
  it.each(SUPPRESSION_CASES.filter((c) => (c.removed ?? []).length > 0).map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    const dir = newRepo('suppressions-carry-');
    write(dir, c.path, `${(c.removed ?? []).join('\n')}\n`);
    branch(dir);
    write(dir, c.path, caseText(c));
    const r = await runSuppressionCheck(dir, { base: 'main', target: { kind: 'worktree', untracked: true } });
    expect(letters(r?.findings ?? [])).toBe([...c.out].filter((l) => l === 'M' || l === 'L').sort().join(''));
    rmSync(join(dir, c.path));
  });
});
