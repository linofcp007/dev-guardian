/**
 * The shared gitleaks helper must never take a scan down with it.
 *
 * Review of the first version: one unreadable file (`copyFileSync` → EBUSY /
 * EACCES), a git error listing the working tree or counting a range, or a
 * temporary copy that would not delete, each threw out of the helper — and
 * `scan_secrets` then lost the history pass it had already finished
 * (`scanner_failed`). Each of those is now a named gap or a failed pass, with
 * everything that did finish kept.
 *
 * Also here: a directory that is not a repository is scanned IN PLACE with a
 * generated config (no copy of a multi-gigabyte `wp-content/uploads` into the
 * OS temp directory), and the working-tree copy has a total size limit.
 */

import { execa } from 'execa';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 120_000 });

const faults = vi.hoisted(() => ({
  copyFails: null as string | null,
  rmFails: false,
  uncommittedFails: false,
  countFails: false,
  copies: 0,
  /** Every `guardian-gitleaks-*` copy the scan made, removed after each test. */
  copyDirs: [] as string[],
}));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    // The copy reads each file through `platform/projectFs.ts#readProjectBytes`
    // (an open of the file itself) and writes it into the scan's own
    // `guardian-gitleaks-*` directory.
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      if (faults.copyFails !== null && String(args[0]).endsWith(faults.copyFails)) {
        throw Object.assign(new Error(`EBUSY: resource busy or locked, open '${String(args[0])}'`), { code: 'EBUSY' });
      }
      return actual.openSync(...args);
    },
    writeFileSync: (...args: Parameters<typeof actual.writeFileSync>) => {
      if (String(args[0]).includes('guardian-gitleaks-')) faults.copies += 1;
      actual.writeFileSync(...args);
    },
    mkdtempSync: (prefix: string) => {
      const dir = actual.mkdtempSync(prefix);
      if (prefix.includes('guardian-gitleaks-')) faults.copyDirs.push(dir);
      return dir;
    },
    rmSync: (path: string, opts?: Parameters<typeof actual.rmSync>[1]) => {
      if (faults.rmFails && String(path).includes('guardian-gitleaks-')) {
        throw Object.assign(new Error(`EPERM: operation not permitted, rmdir '${String(path)}'`), { code: 'EPERM' });
      }
      actual.rmSync(path, opts);
    },
  };
});
vi.mock('../../src/runners/git.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/runners/git.js')>();
  return {
    ...actual,
    uncommittedFiles: async (...args: Parameters<typeof actual.uncommittedFiles>) => {
      if (faults.uncommittedFails) throw new Error('git failed listing changed files: fatal: index file corrupt');
      return actual.uncommittedFiles(...args);
    },
    countCommits: async (...args: Parameters<typeof actual.countCommits>) => {
      if (faults.countFails) throw new Error('git rev-list --count failed: fatal: bad object');
      return actual.countCommits(...args);
    },
  };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { runGitleaksScan } from '../../src/runners/gitleaksScan.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir, rmDirOrDefer } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
// The scan's own copy is left behind on purpose when `rmFails` is set — and
// then it is this file's to remove, or every run leaves one (109 had piled up).
afterEach(() => {
  faults.rmFails = false;
  for (const dir of faults.copyDirs.splice(0)) rmDirOrDefer(dir);
});
beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
});

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];

function leak(file: string): string {
  return JSON.stringify([{ RuleID: 'aws-access-token', Description: 'AWS', StartLine: 1, EndLine: 1, File: file }]);
}

/** gitleaks: the history pass finds nothing; a files pass finds `ok.env`. */
async function fakeGitleaks(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const call: Call = { ...opts, args: opts.args ?? [] };
  calls.push(call);
  const report = call.args.find((a) => a.startsWith('--report-path='))?.slice('--report-path='.length);
  const noGit = call.args.includes('--no-git');
  if (report) writeFileSync(report, noGit ? leak('ok.env') : '[]');
  return { outcome: 'completed', exitCode: 0, stdout: '', stderr: noGit ? '' : 'INF 1 commits scanned.', truncated: false };
}

beforeEach(() => {
  calls = [];
  Object.assign(faults, { copyFails: null, rmFails: false, uncommittedFails: false, countFails: false, copies: 0 });
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeGitleaks);
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: project,
    progressNotifier: { send: () => {} },
  };
}

async function repo(): Promise<string> {
  const dir = makeTempDir('gl-robust-');
  const git = (...a: string[]) => execa('git', a, { cwd: dir });
  await git('init', '-q');
  writeFileSync(join(dir, '.gitignore'), '.guardian/\n');
  await git('add', '.gitignore');
  await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x');
  writeFileSync(join(dir, 'ok.env'), 'k=v\n');
  writeFileSync(join(dir, 'locked.env'), 'k=v\n');
  return dir;
}

interface Result {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

async function scanSecrets(dir: string) {
  const tool = TOOLS.find((t) => t.name === 'scan_secrets');
  if (!tool) throw new Error('scan_secrets not registered');
  const p = plugin(dir);
  const r = await tool.handler({ project_path: dir, force: true }, p);
  return { r, p };
}

function entry(r: Result, name: string): ToolRun | undefined {
  return r.tools_run.find((t) => t.name === name);
}

describe('gitleaks helper — nothing it meets takes the scan down', () => {
  it('a file that cannot be read is a named gap; the rest is scanned and the history pass kept', async () => {
    const dir = await repo();
    faults.copyFails = 'locked.env';
    const { r, p } = await scanSecrets(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as Result;
    expect(entry(res, 'gitleaks')?.status).toBe('ok');
    const wt = entry(res, 'gitleaks-working-tree');
    expect(wt?.status).toBe('ok');
    expect(wt?.reason).toMatch(/1 file\(s\) could not be read/);
    expect(wt?.reason).toMatch(/locked\.env/);
    expect(res.missing_tools).toContain('gitleaks-working-tree');
    expect(res.coverage).toBe('partial');
    expect(p.storage.findings.listByScan(res.scan_id).map((f) => f.file_path)).toEqual(['ok.env']);
  });

  it('git failing to list the working tree fails that pass only', async () => {
    const dir = await repo();
    faults.uncommittedFails = true;
    const { r } = await scanSecrets(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as Result;
    expect(entry(res, 'gitleaks')?.status).toBe('ok');
    expect(entry(res, 'gitleaks-working-tree')?.status).toBe('failed');
    expect(entry(res, 'gitleaks-working-tree')?.reason).toMatch(/index file corrupt/);
    expect(res.coverage).toBe('partial');
  });

  it('a git error counting a commit range is a failed pass, not an exception', async () => {
    const dir = await repo();
    faults.countFails = true;
    const out = await runGitleaksScan({
      projectPath: dir,
      reportDir: makeTempDir('gl-robust-report-'),
      scope: { kind: 'range', base: 'a'.repeat(40), head: 'b'.repeat(40) },
      env: process.env,
      signal: new AbortController().signal,
    });
    expect(out.tools_run).toEqual([
      { name: 'gitleaks', status: 'failed', reason: expect.stringMatching(/bad object/) as unknown as string },
    ]);
  });

  it('a temporary copy that will not delete never discards what was found', async () => {
    const dir = await repo();
    faults.rmFails = true;
    const { r, p } = await scanSecrets(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as Result;
    expect(entry(res, 'gitleaks-working-tree')?.status).toBe('ok');
    expect(p.storage.findings.listByScan(res.scan_id).map((f) => f.file_path)).toEqual(['ok.env']);
  });

  it('the working-tree copy stops at its total size limit and names the remainder as a gap', async () => {
    const dir = await repo();
    const out = await runGitleaksScan({
      projectPath: dir,
      reportDir: makeTempDir('gl-robust-report-'),
      scope: { kind: 'project' },
      env: process.env,
      signal: new AbortController().signal,
      limits: { maxTotalBytes: 6 },
    });
    const wt = out.tools_run.find((t) => t.name === 'gitleaks-working-tree');
    expect(wt?.status).toBe('ok');
    expect(wt?.reason).toMatch(/1 file\(s\) not scanned: over the 6-byte total/);
    expect(out.missing_tools).toContain('gitleaks-working-tree');
  });
});

describe('gitleaks helper — a history pass that logs no commit count (final review M8)', () => {
  // A gitleaks release that changes its `N commits scanned.` log line — or
  // one that never walked the history — left `commits` null, and the pass
  // read `ok`, "an unreported number of commit(s) scanned". On a repository
  // with commits, nothing then says history was read.
  function historyWithoutCount(report: string) {
    return async (opts: ProcessRunOptions): Promise<ProcessRunResult> => {
      const args = opts.args ?? [];
      calls.push({ ...opts, args });
      const path = args.find((a) => a.startsWith('--report-path='))?.slice('--report-path='.length);
      if (path) writeFileSync(path, args.includes('--no-git') ? '[]' : report);
      return { outcome: 'completed', exitCode: report === '[]' ? 0 : 1, stdout: '', stderr: 'INF scan completed', truncated: false };
    };
  }

  it('no count and an empty report: the history pass failed, never ok', async () => {
    const dir = await repo();
    vi.mocked(runProcess).mockImplementation(historyWithoutCount('[]'));
    const out = await runGitleaksScan({
      projectPath: dir,
      reportDir: makeTempDir('gl-nocount-report-'),
      scope: { kind: 'project' },
      env: process.env,
      signal: new AbortController().signal,
    });
    const history = out.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('failed');
    expect(history?.reason).toMatch(/no commit count/);
  });

  it('no count, but the report holds findings: history was read, the pass is ok', async () => {
    const dir = await repo();
    vi.mocked(runProcess).mockImplementation(historyWithoutCount(leak('.gitignore')));
    const out = await runGitleaksScan({
      projectPath: dir,
      reportDir: makeTempDir('gl-nocount-report-'),
      scope: { kind: 'project' },
      env: process.env,
      signal: new AbortController().signal,
    });
    const history = out.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('ok');
    expect(history?.reason).toMatch(/an unreported number of commit/);
    expect(out.parser_inputs.some((i) => String(i.input).includes('aws-access-token'))).toBe(true);
  });

  it('no count on a commit range whose size git knows: failed as well — git counted, gitleaks did not say', async () => {
    const dir = await repo();
    const head = (await execa('git', ['rev-parse', 'HEAD'], { cwd: dir })).stdout.trim();
    const git = (...a: string[]) => execa('git', a, { cwd: dir });
    writeFileSync(join(dir, 'two.txt'), 'x\n');
    await git('add', 'two.txt');
    await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'y');
    const next = (await git('rev-parse', 'HEAD')).stdout.trim();
    vi.mocked(runProcess).mockImplementation(historyWithoutCount('[]'));

    const out = await runGitleaksScan({
      projectPath: dir,
      reportDir: makeTempDir('gl-nocount-report-'),
      scope: { kind: 'range', base: head, head: next },
      env: process.env,
      signal: new AbortController().signal,
    });
    expect(out.tools_run.find((t) => t.name === 'gitleaks')?.status).toBe('failed');
  });
});

describe('gitleaks helper — a directory that is not a repository is scanned in place', () => {
  it('runs `--no-git -s .` in the project with a generated config that excludes vendored trees', async () => {
    const dir = makeTempDir('gl-inplace-');
    writeFileSync(join(dir, 'ok.env'), 'k=v\n');
    const { r } = await scanSecrets(dir);
    expect(r.ok).toBe(true);
    expect(faults.copies).toBe(0);
    const gl = calls.find((c) => c.args.includes('--no-git'));
    expect(gl?.cwd).toBe(dir);
    const args = gl?.args ?? [];
    expect(args.slice(args.indexOf('-s'), args.indexOf('-s') + 2)).toEqual(['-s', '.']);
    const configArg = args.find((a) => a.startsWith('--config='));
    expect(configArg).toBeDefined();
    const config = readFileSync((configArg ?? '').slice('--config='.length), 'utf8');
    expect(config).toMatch(/useDefault = true/);
    expect(config).toMatch(/node_modules/);
    expect(config).toMatch(/vendor/);
    expect(config).toMatch(/\\\.guardian/);
  });

  it("extends the project's own .gitleaks.toml rather than replacing it", async () => {
    const dir = makeTempDir('gl-inplace-cfg-');
    writeFileSync(join(dir, 'ok.env'), 'k=v\n');
    writeFileSync(join(dir, '.gitleaks.toml'), '[extend]\nuseDefault = true\n');
    await scanSecrets(dir);
    const configArg = calls.find((c) => c.args.includes('--no-git'))?.args.find((a) => a.startsWith('--config='));
    const path = (configArg ?? '').slice('--config='.length);
    expect(existsSync(path)).toBe(true);
    const config = readFileSync(path, 'utf8');
    expect(config).not.toMatch(/useDefault/);
    expect(config).toContain(`path = '''${join(dir, '.gitleaks.toml')}'''`);
  });
});
