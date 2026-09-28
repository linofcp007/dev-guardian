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
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
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
    expect(semgrep?.status).toBe('ok');
    expect(semgrep?.reason).toMatch(/only partly parsed/);
    expect(semgrep?.partially_parsed?.map((p) => p.file)).toEqual(['app.php']);
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
    expect(res.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
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

    let seen: { cwd: string; targets: string[]; a: string } | undefined;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') {
        const { targets } = semgrepTargets(call.args);
        // Line endings are the checkout's (core.autocrlf), the content is head's.
        const a = readFileSync(join(opts.cwd, 'a.py'), 'utf8').replace(/\r\n/g, '\n');
        seen = { cwd: opts.cwd, targets: [...targets].sort(), a };
        return fakeSemgrep(call);
      }
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'bandit') {
        writeFileSync(call.args[call.args.indexOf('-o') + 1] ?? '', JSON.stringify({ errors: [], results: [] }));
        return ok(0);
      }
      return ok();
    });

    const { r } = await review(dir, { base_ref: 'main', head_ref: 'feature' });
    expect(r.ok).toBe(true);
    const res = r as unknown as ReviewResult;
    // Both files, at the head's version — not "b.py not on disk", not main's a.py.
    expect(seen?.targets).toEqual(['a.py', 'b.py']);
    expect(seen?.a).toBe('eval(feature)\n');
    expect(seen?.cwd).not.toBe(dir);
    expect(res.missing_tools, JSON.stringify(res.tools_run)).toEqual([]);
    expect(res.coverage, JSON.stringify(res.tools_run)).toBe('full');
    // Uncommitted changes of whatever is checked out are not the PR's.
    expect(calls.some((c) => c.args.includes('--no-git'))).toBe(false);
    // The materialised tree is gone, and git no longer lists it.
    expect(existsSync(seen?.cwd ?? dir)).toBe(false);
    const worktrees = (await execa('git', ['worktree', 'list', '--porcelain'], { cwd: dir })).stdout;
    expect(worktrees.match(/^worktree /gm)).toHaveLength(1);
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
        writeFileSync(out, JSON.stringify({ errors: [], results: [] }));
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
