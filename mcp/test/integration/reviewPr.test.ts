/**
 * `review_pr` on real git repositories, with the scanners mocked at
 * `runProcess` so every argument they would receive can be inspected.
 *
 * Every case here was reproduced against `review-scan.sh`, which received the
 * diff as ONE space-joined argument, split it with `tr ' ' '\n'`, and handed
 * it to `xargs semgrep … || true`:
 *
 *   - one deleted file in the PR → "Invalid scanning root", 0 results, `ok`;
 *   - a path with a space → two nonexistent paths;
 *   - a non-ASCII path → git's quoted form, `"h\303\251llo.py"`;
 *   - more than ~20 KB of paths → several xargs batches over ONE `sast.json`;
 *   - a file named `-x.py` → a Semgrep option;
 *   - `gitleaks protect --staged` → the branch's commits never read;
 *   - an unresolvable base (a `master` repository, a typo) → "no files
 *     changed", `ok`.
 */

import { execa } from 'execa';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Real repositories, hundreds of files in one test: under a loaded full-suite
 * run the 10 s default was measured too short (10.0 s, timed out). A
 * file-level ceiling, not a global one — see vitest.config.ts.
 */
vi.setConfig({ testTimeout: 180_000 });

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import {
  CAP_REASON,
  CAP_REPORTED,
  capBase,
  capChange,
  CARRY_REPORTED,
  CARRY_TREE,
  carryBase,
  carryChange,
  DELETED_DIR,
  DELETED_TREE,
  deletedTreeBase,
  deletedTreeChange,
  IGNORED_BASE,
  ignoredChange,
  MOVED_INTO_IGNORED,
  REPORTED,
  rowOf,
} from '../helpers/ignoredChange.js';
import { caseText, suppressionCase } from '../helpers/suppressionCases.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/reviewPr.js');
});

interface ReviewResult {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings_count_by_severity: Record<string, number>;
  base_ref?: string;
  head_ref?: string;
}

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];

function ok(exitCode = 0, stderr = ''): ProcessRunResult {
  return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout: '', stderr, truncated: false };
}

/** Semgrep's `--output`, and the targets after `--`. */
function semgrepTargets(args: readonly string[]): { out: string; targets: string[] } {
  const out = args[args.indexOf('--output') + 1] ?? '';
  const sep = args.indexOf('--');
  return { out, targets: sep >= 0 ? args.slice(sep + 1) : [] };
}

/** A well-behaved Semgrep: scans every target, one ERROR result on the first. */
function fakeSemgrep(opts: Call): ProcessRunResult {
  const { out, targets } = semgrepTargets(opts.args);
  const first = targets[0] ?? 'none';
  writeFileSync(
    out,
    JSON.stringify({
      results: [
        {
          check_id: 'test.rule',
          path: first,
          start: { line: 1, col: 1 },
          end: { line: 1, col: 2 },
          extra: { severity: 'ERROR', message: 'bad', lines: 'eval(x)' },
        },
      ],
      errors: [],
      paths: { scanned: targets },
    }),
  );
  return ok(1);
}

/** A clean Bandit report as Bandit writes it: one `metrics` entry per file handed after `--`. */
function banditReport(args: readonly string[]): string {
  const metrics = Object.fromEntries(args.slice(args.indexOf('--') + 1).map((f) => [f, { loc: 1 }]));
  return JSON.stringify({ errors: [], results: [], metrics });
}

function fakeGitleaks(opts: Call): ProcessRunResult {
  const report = opts.args.find((a) => a.startsWith('--report-path='));
  if (report) writeFileSync(report.slice('--report-path='.length), '[]');
  return ok(0, 'INF 1 commits scanned.');
}

beforeEach(() => {
  calls = [];
  vi.mocked(runShellScript).mockReset();
  vi.mocked(runShellScript).mockResolvedValue({
    outcome: 'completed',
    exitCode: 0,
    stdout: '',
    stderr: '',
    truncated: false,
  });
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => `/fake/bin/${name}`);
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    const call: Call = { ...opts, args: opts.args ?? [] };
    calls.push(call);
    if (opts.command === 'semgrep') return fakeSemgrep(call);
    if (opts.command === 'gitleaks') return fakeGitleaks(call);
    return ok();
  });
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: project,
    progressNotifier: { send: () => {} },
  };
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

/** A repository on `branch` with `base` committed, then a `feature` branch checked out. */
async function repo(branch: string, base: Record<string, string>): Promise<string> {
  const dir = makeTempDir('review-pr-');
  await git(dir, 'init', '-q');
  await git(dir, 'symbolic-ref', 'HEAD', `refs/heads/${branch}`);
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  for (const [path, content] of Object.entries(base)) write(dir, path, content);
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'base');
  await git(dir, 'checkout', '-q', '-b', 'feature');
  return dir;
}

function write(dir: string, path: string, content: string): void {
  const abs = join(dir, path);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

async function commitAll(dir: string, message = 'change'): Promise<void> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', message);
}

async function review(project: string, input: Record<string, unknown> = {}) {
  const tool = TOOLS.find((t) => t.name === 'review_pr');
  if (!tool) throw new Error('review_pr not registered');
  const p = plugin(project);
  const r = await tool.handler({ project_path: project, force: true, ...input }, p);
  return { r, p };
}

const semgrepCalls = (): Call[] => calls.filter((c) => c.command === 'semgrep');

describe('review_pr — what reaches Semgrep', () => {
  it('scans every changed file as its own argument after `--` — never a deleted one, never split on spaces, never git-quoted', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n', 'b.py': 'b = 1\n' });
    rmSync(join(dir, 'b.py'));
    write(dir, 'a.py', 'a = 2\n');
    write(dir, 'sub dir/my file.py', 'eval(x)\n');
    write(dir, 'héllo.py', 'eval(x)\n');
    write(dir, '日本.py', 'eval(x)\n');
    write(dir, '-dash.py', 'eval(x)\n');
    await commitAll(dir);

    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    const calls = semgrepCalls();
    expect(calls).toHaveLength(1);
    const { targets } = semgrepTargets(calls[0]?.args ?? []);
    expect([...targets].sort()).toEqual(['-dash.py', 'a.py', 'sub dir/my file.py', 'héllo.py', '日本.py'].sort());
    // The separator comes before the first target, so `-dash.py` is a file.
    const args = calls[0]?.args ?? [];
    expect(args.indexOf('--')).toBeLessThan(args.indexOf('-dash.py'));
    // Non-ASCII paths reach Semgrep's --output in UTF-8, not the locale codec.
    expect(calls[0]?.env?.['PYTHONUTF8']).toBe('1');
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.status, JSON.stringify(res.tools_run.find((t) => t.name === 'semgrep'))).toBe('ok');
  });

  it('splits more than 24 000 characters of paths into batches, each with its own report, all merged', async () => {
    const base: Record<string, string> = { 'keep.txt': 'x\n' };
    const dir = await repo('main', base);
    const long = 'a-rather-long-directory-name-to-push-the-command-line-over-the-limit';
    for (let i = 0; i < 600; i++) write(dir, `${long}/${long}-${i}.py`, `x = ${i}\n`);
    await commitAll(dir);

    const { r, p } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const calls = semgrepCalls();
    expect(calls.length).toBeGreaterThan(1);
    const outputs = calls.map((c) => semgrepTargets(c.args).out);
    expect(new Set(outputs).size).toBe(calls.length);
    const scanned = calls.flatMap((c) => semgrepTargets(c.args).targets);
    expect(scanned).toHaveLength(600);
    expect(new Set(scanned).size).toBe(600);
    for (const c of calls) expect(c.args.join(' ').length).toBeLessThan(24_000);
    // One finding per batch, every batch kept.
    expect(p.storage.findings.listByScan(res.scan_id).filter((f) => f.tool === 'semgrep')).toHaveLength(calls.length);
  });

  it('a change Semgrep scanned none of is "skipped", not ok, and coverage is not full', async () => {
    const dir = await repo('main', { 'README.md': '# a\n' });
    write(dir, 'README.md', '# b\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        // What semgrep 1.176.1 answers for a file no rule targets: exit 0, nothing scanned.
        writeFileSync(semgrepTargets(call.args).out, JSON.stringify({ results: [], errors: [], paths: { scanned: [] } }));
        return ok(0);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const semgrep = res.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('skipped');
    expect(semgrep?.reason).toMatch(/scanned none/);
    expect(res.missing_tools).toContain('semgrep');
    expect(res.coverage).not.toBe('full');
  });

  // Follow-up X1: the shared judge's `partial` verdict — a changed file
  // Semgrep only partly parsed is partial coverage, not a failed review.
  it('a changed file Semgrep only partly parsed: ok, listed missing, the file named', async () => {
    const dir = await repo('main', { 'app.php': '<?php\n' });
    write(dir, 'app.php', '<?php\nconst NAMESPACE = 1;\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { out, targets } = semgrepTargets(call.args);
        writeFileSync(
          out,
          JSON.stringify({
            results: [],
            errors: [{ level: 'warn', type: ['PartialParsing', []], message: 'Syntax error at line app.php:2', path: targets[0] }],
            paths: { scanned: targets },
          }),
        );
        return ok(0);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const semgrep = res.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; partially_parsed?: Array<{ file: string }> }
      | undefined;
    expect(semgrep?.status, JSON.stringify(semgrep)).toBe('ok');
    expect(semgrep?.reason).toMatch(/only partly parsed/);
    expect(semgrep?.partially_parsed?.map((p) => p.file)).toEqual(['app.php']);
    expect(res.missing_tools).toContain('semgrep');
    expect(res.coverage).toBe('partial');
  });

  // Review of the LLM pack, round 2 (I-C): a taint fixpoint timeout is only in
  // `time.fixpoint_timeouts` — `errors: []` — and is read the same way.
  it('a changed file whose taint analysis timed out (time.fixpoint_timeouts): ok, listed missing, the file named', async () => {
    const dir = await repo('main', { 'agent.py': 'x = 0\n' });
    write(dir, 'agent.py', 'x = 1\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { out, targets } = semgrepTargets(call.args);
        const location = { path: targets[0], start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 2, offset: 1 } };
        writeFileSync(
          out,
          JSON.stringify({
            version: '1.176.1',
            results: [],
            errors: [],
            paths: { scanned: targets },
            time: { fixpoint_timeouts: [{ error_type: 'Fixpoint timeout', severity: 'warn', message: 'Fixpoint timeout', location }] },
          }),
        );
        return ok(0);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const semgrep = res.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; partially_parsed?: Array<{ file: string; type: string }> }
      | undefined;
    expect(semgrep?.status, JSON.stringify(semgrep)).toBe('ok');
    expect(semgrep?.reason).toMatch(/taint analysis incomplete \(Semgrep fixpoint timeout\) in 1 function\(s\) across 1 file\(s\): agent\.py/);
    expect(semgrep?.partially_parsed?.map((p) => [p.file, p.type])).toEqual([['agent.py', 'Fixpoint timeout']]);
    expect(res.missing_tools).toContain('semgrep');
    expect(res.coverage).toBe('partial');
  });

  it('one batch of files no rule targets does not fail a run whose other batches scanned', async () => {
    const dir = await repo('main', { 'keep.txt': 'x\n' });
    const long = 'a-rather-long-directory-name-to-push-the-command-line-over-the-limit';
    for (let i = 0; i < 400; i++) write(dir, `${long}/${long}-${i}.py`, `x = ${i}\n`);
    await commitAll(dir);
    let n = 0;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        n += 1;
        const { out, targets } = semgrepTargets(call.args);
        writeFileSync(out, JSON.stringify({ results: [], errors: [], paths: { scanned: n === 1 ? [] : targets } }));
        return ok(0);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    expect(n).toBeGreaterThan(1);
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.status, JSON.stringify(res.tools_run.find((t) => t.name === 'semgrep'))).toBe('ok');
  });

  it('reports Semgrep failed — not "findings" — when a batch exits 7, and coverage is not full', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { out } = semgrepTargets(call.args);
        writeFileSync(
          out,
          JSON.stringify({
            results: [],
            errors: [{ type: 'SemgrepError', level: 'error', message: 'Failed to download configuration from https://semgrep.dev/c/auto' }],
            paths: { scanned: [] },
          }),
        );
        return ok(7);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });

    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const semgrep = res.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('failed');
    expect(semgrep?.reason).toMatch(/exit 7/);
    expect(res.coverage).not.toBe('full');
  });
});

describe('review_pr — which tree is scanned', () => {
  it('reviews a head that is not checked out from its own tree, then removes that tree', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'eval(feature)\n');
    write(dir, 'b.py', 'eval(b)\n');
    await commitAll(dir);
    await git(dir, 'checkout', '-q', 'main');

    // The head run, then (3.18.0) the merge-base run over the files holding a head result.
    const runs: Array<{ cwd: string; targets: string[]; a: string }> = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { targets } = semgrepTargets(call.args);
        // Line endings are the checkout's (core.autocrlf), the content is head's.
        const a = readFileSync(join(opts.cwd, 'a.py'), 'utf8').replace(/\r\n/g, '\n');
        runs.push({ cwd: opts.cwd, targets: [...targets].sort(), a });
        return fakeSemgrep(call);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'bandit') {
        writeFileSync(call.args[call.args.indexOf('-o') + 1] ?? '', banditReport(call.args));
        return ok(0);
      }
      return ok();
    });

    const { r } = await review(dir, { base_ref: 'main', head_ref: 'feature' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    const seen = runs[0];
    // Both files, at the head's version — not "b.py not on disk", not main's a.py.
    expect(seen?.targets).toEqual(['a.py', 'b.py']);
    expect(seen?.a).toBe('eval(feature)\n');
    expect(seen?.cwd).not.toBe(dir);
    // The merge-base run: the one modified file holding a head result, at main's version, in a tree of its own.
    expect(runs).toHaveLength(2);
    expect(runs[1]?.targets).toEqual(['a.py']);
    expect(runs[1]?.a).toBe('a = 1\n');
    expect(runs[1]?.cwd).not.toBe(seen?.cwd);
    expect(res.missing_tools, JSON.stringify(res.tools_run)).toEqual([]);
    expect(res.coverage, JSON.stringify(res.tools_run)).toBe('full');
    // Uncommitted changes of whatever is checked out are not the PR's.
    expect(calls.some((c) => c.args.includes('--no-git'))).toBe(false);
    // The materialised trees are gone, and git no longer lists them.
    expect(existsSync(seen?.cwd ?? dir)).toBe(false);
    expect(existsSync(runs[1]?.cwd ?? dir)).toBe(false);
    const worktrees = (await execa('git', ['worktree', 'list', '--porcelain'], { cwd: dir })).stdout;
    expect(worktrees.match(/^worktree /gm)).toHaveLength(1);
  });

  // A finding's identity hashes the text of its lines, read from disk. The
  // lines were read from the working tree — another version of the file, or
  // none — while the scan had read the head: the stored identity matched no
  // scan of that code.
  it('keys the findings of a head that is not checked out on the head\'s own lines', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'eval(feature)\n');
    await commitAll(dir);
    await git(dir, 'checkout', '-q', 'main');

    const { r, p } = await review(dir, { base_ref: 'main', head_ref: 'feature' });
    expect(r.ok).toBe(true);
    const stored = p.storage.findings.listByScan((r as unknown as ReviewResult).scan_id);
    const onA = stored.find((f) => f.file_path === 'a.py');
    const keyOf = (text: string): string => createHash('sha256').update(`text\n${text}`).digest('hex');
    expect(onA?.content_key).toBe(keyOf('eval(feature)'));
    expect(onA?.content_key).not.toBe(keyOf('a = 1'));
  });

  it('a changed file missing from the checked-out tree is a coverage gap, not a note on a full run', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    write(dir, 'c.py', 'eval(c)\n');
    await commitAll(dir);
    rmSync(join(dir, 'c.py'));
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.reason).toMatch(/1 changed file\(s\) not in the working tree/);
    expect(res.missing_tools).toContain('semgrep');
    expect(res.coverage).toBe('partial');
  });

  it('when head is the checked-out HEAD, uncommitted files are scanned for secrets too', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    write(dir, '.env', 'TOKEN=x\n');
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const noGit = calls.find((c) => c.command === 'gitleaks' && c.args.includes('--no-git'));
    expect(noGit).toBeDefined();
    expect(res.tools_run.find((t) => t.name === 'gitleaks-working-tree')?.status).toBe('ok');
  });
});

describe('review_pr — refs', () => {
  it('refuses a base ref that does not resolve instead of reporting "no files changed"', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    const { r } = await review(dir, { base_ref: 'mian' });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('target_not_found');
      expect(r.error.message).toMatch(/mian/);
    }
    expect(calls).toHaveLength(0);
  });

  it('finds the default base in a repository whose default branch is master', async () => {
    const dir = await repo('master', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    const { r } = await review(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(res.base_ref).toBe('master');
    expect(semgrepTargets(semgrepCalls()[0]?.args ?? []).targets).toEqual(['a.py']);
  });

  it('refuses a directory that is not a git repository', async () => {
    const dir = makeTempDir('review-pr-nogit-');
    writeFileSync(join(dir, 'a.py'), 'a = 1\n');
    const { r } = await review(dir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('not_a_git_repo');
  });

  it('refuses a repository with no commits', async () => {
    const dir = makeTempDir('review-pr-empty-');
    await git(dir, 'init', '-q');
    writeFileSync(join(dir, 'a.py'), 'a = 1\n');
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(false);
  });
});

describe('review_pr — secrets, Python, dependencies', () => {
  it('runs gitleaks over the commit range, not `protect --staged`', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const gl = calls.filter((c) => c.command === 'gitleaks');
    expect(gl).toHaveLength(1);
    expect(gl[0]?.args).not.toContain('protect');
    expect(gl[0]?.args.some((a) => /^--log-opts=[0-9a-f]{40}\.\.[0-9a-f]{40}$/.test(a))).toBe(true);
  });

  it('runs Bandit on the changed .py files only, after `--`', async () => {
    const dir = await repo('main', { 'old.py': 'a = 1\n', 'app.js': 'x\n' });
    write(dir, 'new mod.py', 'import pickle\n');
    write(dir, 'app.js', 'y\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return fakeSemgrep(call);
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'bandit') {
        const out = call.args[call.args.indexOf('-o') + 1] ?? '';
        writeFileSync(out, banditReport(call.args));
        return ok(0);
      }
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    const bandit = calls.filter((c) => c.command === 'bandit');
    expect(bandit).toHaveLength(1);
    const args = bandit[0]?.args ?? [];
    expect(args.slice(args.indexOf('--') + 1)).toEqual(['new mod.py']);
    expect(res.tools_run.find((t) => t.name === 'bandit')?.status).toBe('ok');
  });

  it('runs Trivy when a dependency manifest changed', async () => {
    const dir = await repo('main', { 'package.json': '{}\n' });
    write(dir, 'package-lock.json', '{}\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return fakeSemgrep(call);
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'trivy') {
        const out = call.args[call.args.indexOf('--output') + 1] ?? '';
        writeFileSync(out, JSON.stringify({ Results: [] }));
        return ok(0);
      }
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    expect(calls.some((c) => c.command === 'trivy')).toBe(true);
    expect(res.tools_run.find((t) => t.name === 'trivy')?.status).toBe('ok');
  });

  // Round 2, item 1: review_pr's Trivy pass is judged like scan_deps'
  // (runners/trivyRun.ts#judgeTrivyFs) — a manifest Trivy read nothing for,
  // anywhere in the reviewed tree, is a named gap, never `ok`, full.
  it('names a manifest Trivy read nothing for, as scan_deps does', async () => {
    const dir = await repo('main', { 'package.json': '{"dependencies":{"express":"4.0.0"}}\n', 'package-lock.json': '{}\n' });
    write(dir, 'web/package.json', '{"dependencies":{"lodash":"4.17.4"}}\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return fakeSemgrep(call);
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'trivy') {
        const out = call.args[call.args.indexOf('--output') + 1] ?? '';
        writeFileSync(out, JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] }));
        return ok(0);
      }
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult & { manifest_coverage_gaps?: Array<{ ecosystem: string; files: string[] }> };
    const trivy = res.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.status).toBe('ok');
    expect(trivy?.reason).toMatch(/^no_supported_manifest/);
    expect(res.missing_tools).toContain('trivy:npm');
    expect(res.manifest_coverage_gaps).toEqual([{ ecosystem: 'npm', files: ['web/package.json'] }]);
    expect(res.coverage).not.toBe('full');
  });

  /**
   * Round 3: a manifest gap is the review's only when its diff touches the
   * manifest or its lock file. A pre-existing one — unchanged, unlocked — is
   * the project's, would make every review of it partial, and is listed as a
   * note instead, bounded, without lowering coverage (as M1/M2 name only what
   * the diff touched).
   */
  describe('manifest gaps the diff did not touch', () => {
    const TRIVY_ROOT_ONLY = JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] });
    function trivyAnswers(report: string): void {
      vi.mocked(runProcess).mockImplementation(async (opts) => {
        const call: Call = { ...opts, args: opts.args ?? [] };
        calls.push(call);
        if (opts.command === 'semgrep') return fakeSemgrep(call);
        if (opts.command === 'gitleaks') return fakeGitleaks(call);
        if (opts.command === 'trivy') {
          writeFileSync(call.args[call.args.indexOf('--output') + 1] ?? '', report);
          return ok(0);
        }
        return ok();
      });
    }
    type WithNotes = ReviewResult & { warnings?: string[]; manifest_coverage_gaps?: unknown };

    it('an unchanged unlocked manifest: full, and a pre-existing note', async () => {
      const dir = await repo('main', {
        'package.json': '{"dependencies":{"express":"4.0.0"}}\n',
        'package-lock.json': '{}\n',
        'web/package.json': '{"dependencies":{"lodash":"4.17.4"}}\n',
      });
      write(dir, 'package.json', '{"dependencies":{"express":"4.1.0"}}\n');
      await commitAll(dir);
      trivyAnswers(TRIVY_ROOT_ONLY);
      const res = (await review(dir, { base_ref: 'main' })).r as unknown as WithNotes;
      const trivy = res.tools_run.find((t) => t.name === 'trivy');
      expect(trivy?.status).toBe('ok');
      expect(res.missing_tools.filter((m) => m.startsWith('trivy'))).toEqual([]);
      expect(res.manifest_coverage_gaps).toBeUndefined();
      expect(res.coverage).toBe('full');
      expect(res.warnings?.join(' ')).toMatch(
        /pre-existing: 1 manifest\(s\) Trivy cannot read, not changed by this diff: web\/package\.json/,
      );
    });

    it('a diff that modifies an unlocked manifest: partial', async () => {
      const dir = await repo('main', {
        'package.json': '{"dependencies":{"express":"4.0.0"}}\n',
        'package-lock.json': '{}\n',
        'web/package.json': '{"dependencies":{"lodash":"4.17.4"}}\n',
      });
      write(dir, 'web/package.json', '{"dependencies":{"lodash":"4.17.5"}}\n');
      await commitAll(dir);
      trivyAnswers(TRIVY_ROOT_ONLY);
      const res = (await review(dir, { base_ref: 'main' })).r as unknown as WithNotes;
      expect(res.missing_tools).toContain('trivy:npm');
      expect(res.manifest_coverage_gaps).toEqual([{ ecosystem: 'npm', files: ['web/package.json'] }]);
      expect(res.coverage).toBe('partial');
    });

    it('a diff that deletes a manifest’s lock file: partial', async () => {
      const dir = await repo('main', {
        'package.json': '{"dependencies":{"express":"4.0.0"}}\n',
        'package-lock.json': '{}\n',
        'web/package.json': '{"dependencies":{"lodash":"4.17.4"}}\n',
        'web/package-lock.json': '{}\n',
      });
      rmSync(join(dir, 'web', 'package-lock.json'));
      await commitAll(dir);
      trivyAnswers(TRIVY_ROOT_ONLY);
      const res = (await review(dir, { base_ref: 'main' })).r as unknown as WithNotes;
      expect(res.missing_tools).toContain('trivy:npm');
      expect(res.coverage).toBe('partial');
    });
  });

  // OWASP coverage reads whether the registry ran from the scan row; a
  // review row that did not say claimed the registry's categories even
  // under local_only (frameworks/coverage.ts#registryRan).
  it.each([true, false])('records local_only=%s on the scan row', async (localOnly) => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'a.py', 'a = 2\n');
    await commitAll(dir);
    const { r, p } = await review(dir, { base_ref: 'main', ...(localOnly ? { local_only: true } : {}) });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(p.storage.scans.getById(res.scan_id)?.meta?.['local_only']).toBe(localOnly);
  });

  // M-b: the languages of the tree the review scanned — the head's own tree
  // when it is not checked out — recorded for OWASP coverage.
  it('records the languages of the reviewed head, not of the working tree', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'lib.rs', 'fn f() {}\n');
    await commitAll(dir);
    await git(dir, 'checkout', '-q', 'main');
    const { r, p } = await review(dir, { base_ref: 'main', head_ref: 'feature' });
    expect(r.ok).toBe(true);
    const meta = p.storage.scans.getById((r as unknown as ReviewResult).scan_id)?.meta;
    expect(meta?.['project_languages']).toMatchObject({ languages: ['python', 'rust'] });
  });

  // A head that is an ancestor of the base changes no file and is not
  // checked out: the working tree's languages are not the head's.
  it('records no languages for a head it never checked out', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    write(dir, 'lib.rs', 'fn f() {}\n');
    await commitAll(dir);
    const { r, p } = await review(dir, { base_ref: 'feature', head_ref: 'main' });
    expect(r.ok).toBe(true);
    const meta = p.storage.scans.getById((r as unknown as ReviewResult).scan_id)?.meta;
    expect(meta?.['scanned_tree']).toBe('head_checkout');
    expect(meta?.['project_languages']).toMatchObject({ languages: null });
  });

  it('an empty pull request runs no scanner and says why', async () => {
    const dir = await repo('main', { 'a.py': 'a = 1\n' });
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(calls).toHaveLength(0);
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.reason).toMatch(/no changed file/);
    expect(res.tools_run.find((t) => t.name === 'gitleaks')?.reason).toMatch(/no commits/);
  });
});

// The diff's own checks: weakened tests (testintegrity/) and the client-trust
// pass over the changed env files and migrations (clienttrust/). Both reach the
// review's findings, so every view of review_pr's results shows them.
describe('review_pr — weakened tests and client trust in the diff', () => {
  const TEST = "describe('sum', () => {\n  it('adds', () => {\n    expect(1 + 1).toBe(2);\n    expect(2 + 2).toBe(4);\n  });\n});\n";
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  const serviceRole = `${b64({ alg: 'HS256' })}.${b64({ role: 'service_role' })}.${'Qw9Z'.repeat(10)}`;

  const rowsOf = (p: PluginContext, scanId: string, tool: string): string[] =>
    p.storage.findings
      .listByScan(scanId)
      .filter((f) => f.tool === tool)
      .map((f) => `${f.rule_id} ${f.file_path}:${f.line_start ?? '-'} ${f.severity}`)
      .sort();

  async function weakenedBranch(): Promise<string> {
    const dir = await repo('main', { 'src/sum.test.ts': TEST, 'src/old.test.ts': "it('x', () => { expect(1).toBe(1); });\n", 'src/sum.ts': 'export {};\n' });
    write(dir, 'src/sum.test.ts', TEST.replace("it('adds'", "it.only('adds'"));
    rmSync(join(dir, 'src/old.test.ts'));
    write(dir, '.env.production', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${serviceRole}\n`);
    write(dir, 'supabase/migrations/20240101_init.sql', 'create table public.orders (id int);\n');
    await commitAll(dir, 'make it green');
    return dir;
  }

  it('head checked out: the focused test, the deleted file, the browser secret and the open table are findings of the review', async () => {
    const dir = await weakenedBranch();
    const { r, p } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(res.tools_run.find((t) => t.name === 'guardian-test-integrity')).toMatchObject({ status: 'ok' });
    expect(res.tools_run.find((t) => t.name === 'guardian-client-trust')).toMatchObject({ status: 'ok' });
    expect(rowsOf(p, res.scan_id, 'guardian-test-integrity')).toEqual([
      'test-file-deleted src/old.test.ts:- medium',
      'test-focused src/sum.test.ts:2 high',
    ]);
    expect(rowsOf(p, res.scan_id, 'guardian-client-trust')).toEqual([
      'client-env-public-secret .env.production:1 critical',
      'supabase-rls-disabled supabase/migrations/20240101_init.sql:1 critical',
    ]);
    expect(res.findings_count_by_severity['high']).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(p.storage.findings.listByScan(res.scan_id)).includes(serviceRole)).toBe(false);
  });

  it('head not checked out: the same weakening read from the head commit', async () => {
    const dir = await weakenedBranch();
    await git(dir, 'checkout', '-q', 'main');
    const { r, p } = await review(dir, { base_ref: 'main', head_ref: 'feature' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(rowsOf(p, res.scan_id, 'guardian-test-integrity')).toEqual([
      'test-file-deleted src/old.test.ts:- medium',
      'test-focused src/sum.test.ts:2 high',
    ]);
  });

  it('a diff that touches no test, env file or migration: neither pass has an entry', async () => {
    const dir = await repo('main', { 'src/sum.ts': 'export {};\n', 'src/sum.test.ts': TEST });
    write(dir, 'src/sum.ts', 'export const x = 1;\n');
    await commitAll(dir);
    const { r } = await review(dir, { base_ref: 'main' });
    const res = r as unknown as ReviewResult;
    expect(res.tools_run.some((t) => t.name === 'guardian-test-integrity')).toBe(false);
    expect(res.tools_run.some((t) => t.name === 'guardian-client-trust')).toBe(false);
    expect(res.tools_run.some((t) => t.name === 'guardian-suppressions')).toBe(false);
  });

  // 3.17.0: the suppressions the diff adds, a pass of its own beside the test-integrity one.
  it('a suppression added with no reason: a finding of guardian-suppressions, read at head, checked out or not', async () => {
    const dir = await repo('main', { 'src/sum.ts': 'export {};\n', 'src/sum.test.ts': TEST });
    write(dir, 'src/sum.ts', `${caseText(suppressionCase('ESLint: the whole file, every rule'))}export {};\n`);
    write(dir, 'src/util.ts', `${caseText(suppressionCase('ESLint: the next line, a rule'))}`);
    await commitAll(dir, 'silence it');
    for (const args of [{ base_ref: 'main' }, { base_ref: 'main', head_ref: 'feature' }]) {
      if ('head_ref' in args) await git(dir, 'checkout', '-q', 'main');
      const { r, p } = await review(dir, args);
      expect(r.ok).toBe(true);
      const res = r as unknown as ReviewResult;
      const pass = res.tools_run.find((t) => t.name === 'guardian-suppressions');
      expect(pass).toMatchObject({ status: 'ok', reason: expect.stringMatching(/2 suppression\(s\) added — 1 with no reason reported, 1 naming/) });
      expect(rowsOf(p, res.scan_id, 'guardian-suppressions')).toEqual(['suppression-added src/sum.ts:1 medium']);
      // Its own name: nothing of it is a test-integrity finding.
      expect(res.tools_run.some((t) => t.name === 'guardian-test-integrity')).toBe(false);
    }
  });

  // Review 1 of 3.17.0, R1-DG-D-1, narrowed by review 2 (R2-DG-D-1): the suppressions pass skips the paths the
  // project's .guardianignore lists — the same change the CLI's scan --diff-base reads in ciRunScans.test.ts,
  // reported the same there; the factory's result filter drops a left-out test (the CLI keeps it, as in 3.16.1).
  // 3.18.0 (DG-14, B142-06): and the same with head NOT checked out. The filter asks head's tree whether a path is
  // in the project, never the working tree, which is then the base's: 3.17 reported the rename into vendor/ (the
  // base has no vendor/) and hid the deletion in legacy/ (the base still has it). Every finding of every pass, and
  // the count the filter dropped, are the same both ways. The precondition of this equality: the change does not
  // edit .guardianignore (a commit target applies the working tree's copy, a checked-out review head's), so no row
  // of these differentials edits it.
  const bothWays = async (repoDir: string, project: string) => {
    const out: Array<{ rows: (tool?: string) => string[]; excluded: unknown }> = [];
    for (const args of [{ base_ref: 'main' }, { base_ref: 'main', head_ref: 'feature' }]) {
      if ('head_ref' in args) await git(repoDir, 'checkout', '-q', 'main');
      const { r, p } = await review(project, args);
      expect(r.ok).toBe(true);
      const res = r as unknown as ReviewResult & { exclusions?: { findings_excluded?: number } };
      const rows = (tool?: string): string[] =>
        p.storage.findings
          .listByScan(res.scan_id)
          .filter((f) => tool === undefined || f.tool === tool)
          .map((f) => `${f.tool} ${rowOf(f)}`)
          .sort();
      out.push({ rows, excluded: res.exclusions?.findings_excluded });
    }
    const [checkedOut, commit] = out;
    if (checkedOut === undefined || commit === undefined) throw new Error('two reviews expected');
    expect(commit.rows()).toEqual(checkedOut.rows());
    expect(commit.excluded).toBe(checkedOut.excluded);
    return checkedOut;
  };
  const ignoredRepo = async (prefix: string): Promise<string> => {
    const dir = await repo('main', Object.fromEntries(Object.entries(IGNORED_BASE).map(([rel, text]) => [`${prefix}${rel}`, text])));
    for (const [rel, text] of Object.entries(ignoredChange())) write(dir, `${prefix}${rel}`, text);
    rmSync(join(dir, `${prefix}${DELETED_DIR}`), { recursive: true, force: true });
    rmSync(join(dir, `${prefix}${MOVED_INTO_IGNORED.from}`));
    await commitAll(dir, 'vendor bump');
    return dir;
  };
  const tool = (name: string, list: readonly string[]): string[] => list.map((row) => `${name} ${row}`);

  it('a path .guardianignore leaves out: neither pass reports it, the control files are — head checked out or not', async () => {
    const dir = await ignoredRepo('');
    const { rows } = await bothWays(dir, dir);
    expect(rows('guardian-suppressions')).toEqual(tool('guardian-suppressions', REPORTED.suppressions));
    expect(rows('guardian-test-integrity')).toEqual(tool('guardian-test-integrity', REPORTED.integrityReview));
  });

  it('the same for a project in a subdirectory of its repository: head’s tree is read from the project, not the root', async () => {
    const dir = await ignoredRepo('app/');
    const { rows } = await bothWays(dir, join(dir, 'app'));
    expect(rows('guardian-suppressions')).toEqual(tool('guardian-suppressions', REPORTED.suppressions));
    expect(rows('guardian-test-integrity')).toEqual(tool('guardian-test-integrity', REPORTED.integrityReview));
  });

  // A change that only deletes a listed tree changes no file Semgrep could read, so head is never checked out:
  // head's tree is still what answers (3.17 hid the deleted test file whenever the base was checked out).
  it('a change that only deletes a listed tree: its deleted test file is reported, head checked out or not', async () => {
    const dir = await repo('main', { '.guardianignore': `${DELETED_DIR}/\n`, 'src/app.py': 'x = 1\n', 'legacy/old.test.js': IGNORED_BASE['legacy/old.test.js'] ?? '' });
    rmSync(join(dir, DELETED_DIR), { recursive: true, force: true });
    await commitAll(dir, 'drop the legacy tree');
    const { rows, excluded } = await bothWays(dir, dir);
    expect(rows('guardian-test-integrity')).toEqual(['guardian-test-integrity test-file-deleted legacy/old.test.js:- medium']);
    expect(excluded).toBe(0);
  });

  // The working tree IS the reviewed tree when head is checked out, untracked files included (the test-integrity
  // pass reads them there): the disk answers, and a listed untracked directory stays left out, as in 3.17.
  it('head checked out: an untracked test file in a listed directory is left out, the control file is reported', async () => {
    const dir = await repo('main', { '.guardianignore': 'scratch/\n', 'src/sum.ts': 'export {};\n' });
    write(dir, 'src/sum.ts', 'export const x = 1;\n');
    await commitAll(dir);
    const focused = TEST.replace("it('adds'", "it.only('adds'");
    write(dir, 'scratch/a.test.ts', focused);
    write(dir, 'src/b.test.ts', focused);
    const { r, p } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult & { exclusions?: { findings_excluded?: number } };
    expect(rowsOf(p, res.scan_id, 'guardian-test-integrity')).toEqual(['test-focused src/b.test.ts:2 high']);
    expect(res.exclusions?.findings_excluded).toBe(1);
  });

  // Review 2 of 3.17.0, R2-DG-D-3: the pass lists only what .guardianignore keeps, before its 500-file bound — a
  // left-out tree's 600 changed files never fill it (ciRunScans.test.ts holds the CLI's side).
  it("a left-out tree's changed files never fill the suppressions pass's bound", async () => {
    const dir = await repo('main', capBase());
    for (const [rel, text] of Object.entries(capChange())) write(dir, rel, text);
    await commitAll(dir, 'regenerate');
    const { r, p } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    const rows = p.storage.findings
      .listByScan(res.scan_id)
      .filter((f) => f.tool === 'guardian-suppressions')
      .map(rowOf);
    expect(rows).toEqual(CAP_REPORTED);
    expect(res.tools_run.find((t) => t.name === 'guardian-suppressions')?.reason).toMatch(CAP_REASON);
  });

  // Review 3 of 3.17.0, R3-DG-1: a listed tree the change DELETES whole is no longer in the project, and the pass
  // still never lists it — its member is .guardianignore's own test (a git listing holds only project paths); the
  // factory's result filter keeps its rule (the legacy/ row above). ciRunScans.test.ts holds the CLI's side.
  const deletedTree = async (base: Record<string, string>, change: Record<string, string>, tree: string) => {
    const dir = await repo('main', base);
    rmSync(join(dir, tree), { recursive: true, force: true });
    for (const [rel, text] of Object.entries(change)) write(dir, rel, text);
    await commitAll(dir, 'drop the tree');
    const { r, p } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    const rows = p.storage.findings
      .listByScan(res.scan_id)
      .filter((f) => f.tool === 'guardian-suppressions')
      .map(rowOf);
    return { rows, reason: res.tools_run.find((t) => t.name === 'guardian-suppressions')?.reason };
  };

  it("a listed tree's 600 files the change deletes never fill the suppressions pass's bound", async () => {
    const { rows, reason } = await deletedTree(deletedTreeBase(), deletedTreeChange(), DELETED_TREE);
    expect(rows).toEqual(CAP_REPORTED);
    expect(reason).toMatch(CAP_REASON);
  });

  it('a directive of a listed tree the change deletes carries none it adds elsewhere', async () => {
    const { rows, reason } = await deletedTree(carryBase(), carryChange(), CARRY_TREE);
    expect(rows).toEqual(CARRY_REPORTED);
    // One file read (src/z.py), nothing carried.
    expect(reason).toMatch(CAP_REASON);
    expect(reason).not.toMatch(/kept or moved/);
  });
});

// 3.18.0 (DG-12, review/baseCompare.ts): each Semgrep finding judged at the merge base — `introduced` — by a second
// Semgrep run over the modified or renamed files that hold a head result, in a checkout of the merge base. No
// tools_run entry and no coverage gap of its own; any failure is `compared: false`; a cancel cancels the review.
describe('review_pr — introduced: the Semgrep findings judged at the merge base', () => {
  interface Introduced {
    compared: boolean;
    reason?: string;
    base_sha?: string;
    counts?: { introduced: number; preexisting: number; unknown: number; not_compared: number };
    preexisting?: Array<{ file_path?: string; tool: string }>;
  }
  const introducedOf = (r: unknown): Introduced => (r as { introduced: Introduced }).introduced;

  it('an old finding in a modified file is preexisting; the base run reads only the files holding a head result', async () => {
    const dir = await repo('main', { 'a.js': 'eval(x)\n', 'b.js': 'b = 1\n' });
    write(dir, 'a.js', 'eval(x)\nmore = 1\n');
    write(dir, 'b.js', 'b = 2\n');
    await commitAll(dir);
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    const runs = semgrepCalls();
    expect(runs).toHaveLength(2);
    // fakeSemgrep reports on its first target: a.py at head, so only a.py is read at the merge base.
    expect(semgrepTargets(runs[1]?.args ?? []).targets).toEqual(['a.js']);
    expect(runs[1]?.cwd).not.toBe(dir);
    // The same flags on both sides: one array.
    const flags = (c: Call | undefined): string[] => (c?.args ?? []).slice(0, (c?.args ?? []).indexOf('--output'));
    expect(flags(runs[1])).toEqual(flags(runs[0]));
    const introduced = introducedOf(r);
    expect(introduced.compared).toBe(true);
    expect(introduced.base_sha).toMatch(/^[0-9a-f]{40}$/);
    expect(introduced.counts).toEqual({ introduced: 0, preexisting: 1, unknown: 0, not_compared: 0 });
    expect(introduced.preexisting?.map((f) => f.file_path)).toEqual(['a.js']);
    // Nothing of the base checkout's temporary paths reaches the result; the review's own bookkeeping is unchanged.
    expect(JSON.stringify(introduced)).not.toMatch(/guardian-review-/);
    expect(res.tools_run.filter((t) => t.name === 'semgrep')).toHaveLength(1);
    expect(res.coverage).toBe('full');
  });

  it('an added file has no counterpart: its findings are introduced, and no base run is made for it', async () => {
    const dir = await repo('main', { 'keep.txt': 'x\n' });
    write(dir, 'c.js', 'eval(c)\n');
    await commitAll(dir);
    const { r } = await review(dir, { base_ref: 'main' });
    expect(semgrepCalls()).toHaveLength(1);
    expect(introducedOf(r)).toMatchObject({ compared: true, counts: { introduced: 1, preexisting: 0, unknown: 0, not_compared: 0 } });
  });

  it('a base run that fails: compared false, and no gap of the review', async () => {
    const dir = await repo('main', { 'a.js': 'eval(x)\n' });
    write(dir, 'a.js', 'eval(x)\nmore = 1\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return opts.cwd === dir ? fakeSemgrep(call) : ok(2, 'semgrep crashed');
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    expect(introducedOf(r)).toMatchObject({ compared: false });
    expect(introducedOf(r).reason).toMatch(/^Semgrep at the merge base [0-9a-f]{12}: failed/);
    expect(res.tools_run.filter((t) => t.name === 'semgrep').map((t) => t.status)).toEqual(['ok']);
    expect(res.coverage).toBe('full');
  });

  it('a cancel during the merge-base run cancels the review', async () => {
    const dir = await repo('main', { 'a.js': 'eval(x)\n' });
    write(dir, 'a.js', 'eval(x)\nmore = 1\n');
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        if (opts.cwd === dir) return fakeSemgrep(call);
        return { outcome: 'cancelled', exitCode: null, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(false);
    expect((r as { error?: { code?: string } }).error?.code).toBe('cancelled');
    expect(semgrepCalls()).toHaveLength(2);
  });
});

// [INT-6]: the merge-base run reads only files the review keeps — the factory's own .guardianignore predicate, the
// one its result filter applies (keptByExclusions, head's tree when head is not checked out).
describe('review_pr — the merge-base run reads only what the review keeps', () => {
  it('a modified file .guardianignore leaves out is never read at the merge base', async () => {
    const dir = await repo('main', { 'a.js': 'eval(a)\n', 'vendor/x.js': 'eval(v)\n', '.guardianignore': 'vendor/\n' });
    write(dir, 'a.js', 'eval(a)\nmore = 1\n');
    write(dir, 'vendor/x.js', 'eval(v)\nmore = 1\n');
    await commitAll(dir);
    // A Semgrep that reports on every target, so both files hold a head result.
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { out, targets } = semgrepTargets(call.args);
        writeFileSync(
          out,
          JSON.stringify({
            results: targets.map((path) => ({ check_id: 'test.rule', path, start: { line: 1, col: 1 }, end: { line: 1, col: 2 }, extra: { severity: 'ERROR', message: 'bad', lines: 'eval(x)' } })),
            errors: [],
            paths: { scanned: targets },
          }),
        );
        return ok(1);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      return ok();
    });
    const { r } = await review(dir, { base_ref: 'main' });
    expect(r.ok).toBe(true);
    const runs = semgrepCalls();
    expect(runs).toHaveLength(2);
    expect([...semgrepTargets(runs[0]?.args ?? []).targets].sort()).toEqual(['a.js', 'vendor/x.js']);
    expect(semgrepTargets(runs[1]?.args ?? []).targets).toEqual(['a.js']);
    expect((r as unknown as { introduced: { counts: unknown } }).introduced.counts).toEqual({ introduced: 0, preexisting: 1, unknown: 0, not_compared: 0 });
  });
});
