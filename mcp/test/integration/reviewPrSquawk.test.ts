/**
 * `review_pr`'s squawk pass (`runners/squawkRun.ts`) on real git repositories, the scanners mocked at
 * `runProcess` (as in reviewPr.test.ts): opt-in by a root `.squawk.toml` in the reviewed tree, never otherwise;
 * what squawk is handed (its config by name, every file a literal path, no token); a missing squawk a gap only
 * under the opt-in; the warnings when the diff edits or removes the file. The fake report is squawk 2.71.0's own
 * JSON shape (scannerParsers/squawk.test.ts).
 */

import { execa } from 'execa';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 180_000 });

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
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
  warnings?: string[];
}

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];
/** What the fake squawk prints for a batch, by its files. */
let squawkOut: (files: string[]) => { exitCode: number; stdout: string } = () => ({ exitCode: 0, stdout: '[]\n' });

function ok(exitCode = 0, stdout = '', stderr = ''): ProcessRunResult {
  return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout, stderr, truncated: false };
}

function fakeSemgrep(opts: Call): ProcessRunResult {
  const out = opts.args[opts.args.indexOf('--output') + 1] ?? '';
  const sep = opts.args.indexOf('--');
  const targets = sep >= 0 ? opts.args.slice(sep + 1) : [];
  writeFileSync(out, JSON.stringify({ results: [], errors: [], paths: { scanned: targets } }));
  return ok(0);
}

function fakeGitleaks(opts: Call): ProcessRunResult {
  const report = opts.args.find((a) => a.startsWith('--report-path='));
  if (report) writeFileSync(report.slice('--report-path='.length), '[]');
  return ok(0, '', 'INF 1 commits scanned.');
}

const squawkFiles = (c: Call): string[] => c.args.slice(c.args.indexOf('--') + 1);

beforeEach(() => {
  calls = [];
  squawkOut = () => ({ exitCode: 0, stdout: '[]\n' });
  vi.mocked(runShellScript).mockReset();
  vi.mocked(runShellScript).mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => `/fake/bin/${name}`);
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    const call: Call = { ...opts, args: opts.args ?? [] };
    calls.push(call);
    if (opts.command === 'semgrep') return fakeSemgrep(call);
    if (opts.command === 'gitleaks') return fakeGitleaks(call);
    if (opts.command === 'squawk') {
      const r = squawkOut(squawkFiles(call));
      return ok(r.exitCode, r.stdout);
    }
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

function write(dir: string, path: string, content: string): void {
  const abs = join(dir, path);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

/** A repository on `main` with `base` committed, then a `feature` branch checked out. */
async function repo(base: Record<string, string>): Promise<string> {
  const dir = makeTempDir('review-squawk-');
  await git(dir, 'init', '-q');
  await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  for (const [path, content] of Object.entries(base)) write(dir, path, content);
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'base');
  await git(dir, 'checkout', '-q', '-b', 'feature');
  return dir;
}

async function commitAll(dir: string): Promise<void> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'change');
}

async function review(project: string, input: Record<string, unknown> = {}): Promise<{ res: ReviewResult; p: PluginContext }> {
  const tool = TOOLS.find((t) => t.name === 'review_pr');
  if (!tool) throw new Error('review_pr not registered');
  const p = plugin(project);
  const r = await tool.handler({ project_path: project, force: true, base_ref: 'main', ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r));
  return { res: r as unknown as ReviewResult, p };
}

const squawkCalls = (): Call[] => calls.filter((c) => c.command === 'squawk');
const squawkRun = (res: ReviewResult): ToolRun | undefined => res.tools_run.find((t) => t.name === 'squawk');

/** A Prisma-shaped migration (cal.com's layout): a NOT NULL column added to an existing table. */
const MIGRATION = 'ALTER TABLE "Booking" ADD COLUMN "tenantId" INTEGER NOT NULL;\n';
const CONFIG = 'excluded_rules = ["prefer-robust-stmts"]\nassume_in_transaction = true\n';

describe('review_pr — squawk, opt-in by a root .squawk.toml', () => {
  it('S4: no .squawk.toml — no squawk call and no entry, the review as it was; with one and squawk missing, a gap', async () => {
    const dir = await repo({ 'README.md': '# app\n' });
    write(dir, 'prisma/migrations/20261101000000_tenant/migration.sql', MIGRATION);
    await commitAll(dir);
    const without = (await review(dir)).res;
    expect(squawkCalls()).toEqual([]);
    expect(squawkRun(without)).toBeUndefined();
    expect(without.missing_tools).not.toContain('squawk');

    write(dir, '.squawk.toml', CONFIG);
    await commitAll(dir);
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'squawk' ? null : `/fake/bin/${name}`));
    const missing = (await review(dir)).res;
    expect(squawkRun(missing)).toMatchObject({ status: 'skipped', reason: 'not_installed' });
    expect(missing.missing_tools).toContain('squawk');
    expect(missing.coverage).not.toBe('full');
  });

  it('S1 / S3 / S7: one spawn for the changed .sql files — json, the root config by name, never a pattern match missing, after --; no token, the allowlisted env only', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG, 'README.md': '# app\n' });
    for (const n of [1, 2, 3]) write(dir, `db/migrations/00${String(n)}_x.sql`, MIGRATION);
    write(dir, 'db/schema.rb', 'x\n');
    await commitAll(dir);
    vi.stubEnv('SQUAWK_GITHUB_TOKEN', 'not-a-token-squawk');
    vi.stubEnv('GITHUB_TOKEN', 'not-a-token-github');
    try {
      const { res } = await review(dir);
      expect(squawkCalls()).toHaveLength(1);
      const call = squawkCalls()[0];
      expect(call?.args.slice(0, call.args.indexOf('--') + 1)).toEqual(['--reporter', 'json', '--config', '.squawk.toml', '--no-error-on-unmatched-pattern', '--']);
      expect(squawkFiles(call ?? ({ args: [] } as unknown as Call)).sort()).toEqual(['db/migrations/001_x.sql', 'db/migrations/002_x.sql', 'db/migrations/003_x.sql']);
      expect(call?.cwd).toBe(dir);
      expect(call?.extendEnv).toBe(false);
      expect(call?.env?.['SQUAWK_GITHUB_TOKEN']).toBeUndefined();
      expect(call?.env?.['GITHUB_TOKEN']).toBeUndefined();
      expect(squawkRun(res)).toMatchObject({ status: 'ok', honoured_config: ['.squawk.toml'] });
      expect(squawkRun(res)?.reason).toMatch(/^3 changed \.sql file\(s\) checked/);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('a violation is a low migration-safety finding on its file and line; a file squawk cannot parse is named partial, and a gap', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG });
    write(dir, 'db/001_add.sql', `\n${MIGRATION}`);
    write(dir, 'db/002_broken.sql', 'ALTER TABLE foo ALTER CONSTRAINT bar RENAME TO quux;\n');
    await commitAll(dir);
    squawkOut = () => ({
      exitCode: 1,
      stdout: `${JSON.stringify([
        { file: 'db/001_add.sql', line: 1, column: 0, level: 'Warning', message: 'adding a new column that is `not null` and has no default value to an existing table effectively makes it required', note: null, help: 'make the field nullable or add a non-volatile default', rule_name: 'adding-required-field', column_end: 64, line_end: 1 },
        { file: 'db/002_broken.sql', line: 0, column: 36, level: 'Error', message: 'missing comma', note: null, help: null, rule_name: 'syntax-error', column_end: 36, line_end: 0 },
      ])}\n`,
    });
    const { res, p } = await review(dir);
    const found = p.storage.findings.listByScan(res.scan_id).filter((f) => f.tool === 'squawk');
    expect(found.map((f) => [f.rule_id, f.severity, f.subcategory, f.file_path, f.line_start])).toEqual([
      ['adding-required-field', 'low', 'migration-safety', 'db/001_add.sql', 2],
    ]);
    expect(squawkRun(res)?.status).toBe('ok');
    expect(squawkRun(res)?.partially_parsed?.map((x) => x.file)).toEqual(['db/002_broken.sql']);
    expect(res.missing_tools).toContain('squawk');
  });

  it('a run that writes no report (exit 1, an error on stderr) failed; one whose every file the config excludes (exit 0, nothing printed) checked them', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG });
    write(dir, 'db/001.sql', MIGRATION);
    await commitAll(dir);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return fakeSemgrep(call);
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'squawk') return ok(1, '', 'Error: unknown variant `prefer-everything`\n');
      return ok();
    });
    const failed = (await review(dir)).res;
    expect(squawkRun(failed)).toMatchObject({ status: 'failed' });
    expect(squawkRun(failed)?.reason).toContain('unknown variant');
    expect(failed.missing_tools).toContain('squawk');

    squawkOut = () => ({ exitCode: 0, stdout: '' });
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command === 'semgrep') return fakeSemgrep(call);
      if (opts.command === 'gitleaks') return fakeGitleaks(call);
      if (opts.command === 'squawk') return ok(0, '');
      return ok();
    });
    const excluded = (await review(dir)).res;
    expect(squawkRun(excluded)?.status).toBe('ok');
    expect(excluded.missing_tools).not.toContain('squawk');
  });

  it('a file name squawk would read as a glob is handed as a literal: [ ] (and * on POSIX, where a name may hold one) in a class of its own', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG });
    write(dir, 'db/[tenant]/up.sql', MIGRATION);
    if (process.platform !== 'win32') write(dir, 'db/all*.sql', MIGRATION);
    await commitAll(dir);
    await review(dir);
    const expected = ['db/[[]tenant[]]/up.sql', ...(process.platform !== 'win32' ? ['db/all[*].sql'] : [])];
    expect(squawkFiles(squawkCalls()[0] ?? ({ args: [] } as unknown as Call)).sort()).toEqual(expected.sort());
  });

  it('S5: a diff that edits .squawk.toml is said; one that removes it is said as the removal it is, and squawk then has no entry', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG, 'db/001.sql': 'SELECT 1;\n' });
    write(dir, '.squawk.toml', `${CONFIG}excluded_paths = ["db/*.sql"]\n`);
    write(dir, 'db/002.sql', MIGRATION);
    await commitAll(dir);
    const edited = (await review(dir)).res;
    expect(edited.warnings?.some((w) => w.startsWith('This diff changes .squawk.toml, which squawk honours'))).toBe(true);
    expect(edited.warnings?.some((w) => w.startsWith('This diff removes'))).toBe(false);

    const dir2 = await repo({ '.squawk.toml': CONFIG, 'db/001.sql': 'SELECT 1;\n' });
    rmSync(join(dir2, '.squawk.toml'));
    write(dir2, 'db/002.sql', MIGRATION);
    await commitAll(dir2);
    const removed = (await review(dir2)).res;
    expect(removed.warnings?.some((w) => w.startsWith('This diff removes .squawk.toml, which turns squawk on'))).toBe(true);
    expect(removed.warnings?.some((w) => w.startsWith('This diff changes .squawk.toml'))).toBe(false);
    expect(squawkRun(removed)).toBeUndefined();
  });

  it('S6: a head that is not checked out opts in by ITS root .squawk.toml, read from its own tree, where squawk runs', async () => {
    const dir = await repo({ 'README.md': '# app\n' });
    write(dir, '.squawk.toml', CONFIG);
    write(dir, 'db/001.sql', MIGRATION);
    await commitAll(dir);
    await git(dir, 'checkout', '-q', 'main');
    const { res } = await review(dir, { head_ref: 'feature' });
    expect(squawkCalls()).toHaveLength(1);
    expect(squawkCalls()[0]?.cwd).not.toBe(dir);
    expect(squawkRun(res)?.status).toBe('ok');
  });

  it('a .squawk.toml that is no regular file (a directory) opts in, and is never read: squawk failed, a gap', async () => {
    const dir = await repo({ '.squawk.toml/README': 'not a config\n' });
    write(dir, 'db/001.sql', MIGRATION);
    await commitAll(dir);
    const { res } = await review(dir);
    expect(squawkCalls()).toEqual([]);
    expect(squawkRun(res)?.status).toBe('failed');
    expect(res.missing_tools).toContain('squawk');
  });

  // Fix round 1 (R1-DGTOOLS-3): the containment the header states, each held by a row.
  it('a .squawk.toml that links out of the project opts in, and is never read: squawk failed, a gap, never run', async (ctx) => {
    const outside = makeTempDir('review-squawk-outside-');
    writeFileSync(join(outside, 'squawk.toml'), CONFIG);
    const dir = await repo({ 'README.md': '# app\n' });
    await git(dir, 'config', 'core.symlinks', 'true');
    linkOrSkip(join(outside, 'squawk.toml'), join(dir, '.squawk.toml'), () => ctx.skip());
    write(dir, 'db/001.sql', MIGRATION);
    await commitAll(dir);
    const { res } = await review(dir);
    expect(squawkCalls()).toEqual([]);
    expect(squawkRun(res)?.status).toBe('failed');
    expect(res.missing_tools).toContain('squawk');
  });

  it('a changed .sql file that is a link (here, out of the project) is never handed to squawk; the regular one is', async (ctx) => {
    const outside = makeTempDir('review-squawk-outside-');
    writeFileSync(join(outside, 'secret.sql'), 'SELECT 1;\n');
    const dir = await repo({ '.squawk.toml': CONFIG });
    await git(dir, 'config', 'core.symlinks', 'true');
    write(dir, 'db/001.sql', MIGRATION);
    mkdirSync(join(dir, 'db', 'linked'), { recursive: true });
    linkOrSkip(join(outside, 'secret.sql'), join(dir, 'db', 'linked', 'evil.sql'), () => ctx.skip());
    await commitAll(dir);
    const { res } = await review(dir);
    expect(squawkCalls()).toHaveLength(1);
    expect(squawkFiles(squawkCalls()[0] ?? ({ args: [] } as unknown as Call))).toEqual(['db/001.sql']);
    expect(squawkRun(res)?.status).toBe('ok');
  });

  it('a squawk stdout that is no JSON array (text, an object) with exit 0 is a failed run and a gap, never a clean pass', async () => {
    const dir = await repo({ '.squawk.toml': CONFIG });
    write(dir, 'db/001.sql', MIGRATION);
    await commitAll(dir);
    for (const stdout of ['not json\n', '{"violations":[]}\n']) {
      squawkOut = () => ({ exitCode: 0, stdout });
      const { res } = await review(dir);
      expect(squawkRun(res)?.status, stdout).toBe('failed');
      expect(res.missing_tools, stdout).toContain('squawk');
    }
    // The control: an empty array is a clean pass.
    squawkOut = () => ({ exitCode: 0, stdout: '[]\n' });
    expect(squawkRun((await review(dir)).res)?.status).toBe('ok');
  });

  it('a head that could not be checked out, with a changed .sql file: squawk failed beside Semgrep, with the reason', async () => {
    const dir = await repo({ 'README.md': '# app\n' });
    // A tree entry no file system can create (a 300-byte name): `git reset --hard` in the head's checkout fails.
    const blob = (await execa('git', ['hash-object', '-w', '--stdin'], { cwd: dir, input: MIGRATION })).stdout.trim();
    const base = (await execa('git', ['ls-tree', 'main'], { cwd: dir })).stdout;
    const tree = (await execa('git', ['mktree'], { cwd: dir, input: `${base}\n100644 blob ${blob}\t${'a'.repeat(300)}.sql\n` })).stdout.trim();
    const head = (await execa('git', ['commit-tree', tree, '-p', 'main', '-m', 'change'], { cwd: dir })).stdout.trim();
    const { res } = await review(dir, { head_ref: head });
    expect(squawkCalls()).toEqual([]);
    expect(res.tools_run.find((t) => t.name === 'semgrep')).toMatchObject({ status: 'failed', reason: expect.stringMatching(/^could not check out head /) });
    expect(squawkRun(res)).toMatchObject({ status: 'failed', reason: expect.stringMatching(/^could not check out head /) });
  });
});

/** A symbolic link, or the test skipped where links cannot be made (Windows without the privilege); elsewhere the error stands. */
function linkOrSkip(target: string, path: string, skip: () => void): void {
  try {
    symlinkSync(target, path, 'file');
  } catch (e) {
    if (process.platform === 'win32') skip();
    throw e;
  }
}
