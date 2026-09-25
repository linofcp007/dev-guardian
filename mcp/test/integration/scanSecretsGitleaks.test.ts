/**
 * `scan_secrets` against REAL gitleaks, on real git repositories.
 *
 * `gitleaks detect` reads commits and nothing else. Each case below was
 * reproduced against the 2.0 tool before it was fixed:
 *
 *   - an uncommitted `.env` in a repository with history → 0 findings, `ok`;
 *   - a directory that is not a git repository → "0 commits scanned", `ok`;
 *   - a repository with no commits yet → likewise.
 *
 * gitleaks is found on PATH; without it every test here is SKIPPED (visibly),
 * never passed.
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

/**
 * Real repositories and real gitleaks: a file-level ceiling for a loaded
 * full-suite run, not a global one — see vitest.config.ts.
 */
vi.setConfig({ testTimeout: 120_000 });

const GITLEAKS = await isInstalled('gitleaks');

// Built at runtime so this file itself never holds a key-shaped literal.
const AWS_KEY_ID = ['AKIA', 'IOSFODNN7', 'ABCDEFG'].join('');
const SECRET_LINE = `aws_access_key_id = ${AWS_KEY_ID}\n`;

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
  resetScannerCache();
});

interface SecretsResult {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings_count_by_severity: Record<string, number>;
}

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

async function git(cwd: string, ...args: string[]): Promise<string> {
  const r = await execa('git', args, { cwd });
  return r.stdout;
}

async function repoWithCleanCommit(prefix: string): Promise<string> {
  const dir = makeTempDir(prefix);
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  writeFileSync(join(dir, 'README.md'), '# fixture\n');
  await git(dir, 'add', 'README.md');
  await git(dir, 'commit', '-q', '-m', 'initial');
  return dir;
}

async function scan(project: string, input: Record<string, unknown> = {}) {
  const tool = TOOLS.find((t) => t.name === 'scan_secrets');
  if (!tool) throw new Error('scan_secrets not registered');
  const p = plugin(project);
  const r = await tool.handler({ project_path: project, force: true, ...input }, p);
  return { r, p };
}

function findings(p: PluginContext, scanId: string): Finding[] {
  return p.storage.findings.listByScan(scanId);
}

describe.skipIf(!GITLEAKS)('scan_secrets with real gitleaks', () => {
  it('finds a secret in an UNCOMMITTED .env of a repository that has history', async () => {
    const dir = await repoWithCleanCommit('secrets-uncommitted-');
    writeFileSync(join(dir, '.env'), SECRET_LINE);

    const { r, p } = await scan(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as SecretsResult;
    const found = findings(p, res.scan_id);
    expect(found.map((f) => f.file_path)).toEqual(['.env']);
    expect(found[0]?.message).toMatch(/working_tree/);
    const history = res.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('ok');
    expect(history?.reason).toMatch(/1 commit/);
    expect(res.tools_run.find((t) => t.name === 'gitleaks-working-tree')?.status).toBe('ok');
    expect(res.coverage).toBe('full');
  });

  it('finds a secret in a modified TRACKED file, a staged file, and a path with spaces and accents', async () => {
    const dir = await repoWithCleanCommit('secrets-modified-');
    writeFileSync(join(dir, 'README.md'), `# fixture\n${SECRET_LINE}`);
    mkdirSync(join(dir, 'sub dir'), { recursive: true });
    writeFileSync(join(dir, 'sub dir', 'héllo wörld.cfg'), SECRET_LINE);
    writeFileSync(join(dir, 'staged.txt'), SECRET_LINE);
    await git(dir, 'add', 'staged.txt');

    const { r, p } = await scan(dir);
    const res = r as unknown as SecretsResult;
    expect(findings(p, res.scan_id).map((f) => f.file_path).sort()).toEqual([
      'README.md',
      'staged.txt',
      'sub dir/héllo wörld.cfg',
    ]);
  });

  it('still finds a secret that was committed and later deleted — in history', async () => {
    const dir = await repoWithCleanCommit('secrets-history-');
    writeFileSync(join(dir, 'creds.txt'), SECRET_LINE);
    await git(dir, 'add', 'creds.txt');
    await git(dir, 'commit', '-q', '-m', 'oops');
    await git(dir, 'rm', '-q', 'creds.txt');
    await git(dir, 'commit', '-q', '-m', 'remove');

    const { r, p } = await scan(dir);
    const res = r as unknown as SecretsResult;
    const found = findings(p, res.scan_id);
    expect(found.map((f) => f.file_path)).toEqual(['creds.txt']);
    expect(found[0]?.message).toMatch(/history/);
    // gitleaks counts the commits it read a patch from; the exact number is
    // its business, a non-zero count is ours.
    expect(res.tools_run.find((t) => t.name === 'gitleaks')?.reason).toMatch(/history: [1-9]\d* commit/);
  });

  it('scans a directory that is NOT a git repository, skipping node_modules and .git-less build output', async () => {
    const dir = makeTempDir('secrets-nogit-');
    writeFileSync(join(dir, 'settings.ini'), SECRET_LINE);
    mkdirSync(join(dir, 'node_modules', 'dep'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'dep', 'fixture.env'), SECRET_LINE);
    mkdirSync(join(dir, 'vendor', 'lib'), { recursive: true });
    writeFileSync(join(dir, 'vendor', 'lib', 'fixture.env'), SECRET_LINE);

    const { r, p } = await scan(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as SecretsResult;
    expect(findings(p, res.scan_id).map((f) => f.file_path)).toEqual(['settings.ini']);
    const run = res.tools_run.find((t) => t.name === 'gitleaks');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/not a git repository/);
    expect(run?.reason).not.toMatch(/0 commits/);
    expect(res.coverage).toBe('full');
  });

  it('scans the working tree of a repository with no commits yet', async () => {
    const dir = makeTempDir('secrets-nocommits-');
    await git(dir, 'init', '-q');
    writeFileSync(join(dir, 'app.properties'), SECRET_LINE);

    const { r, p } = await scan(dir);
    const res = r as unknown as SecretsResult;
    expect(findings(p, res.scan_id).map((f) => f.file_path)).toEqual(['app.properties']);
    const history = res.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('skipped');
    expect(history?.reason).toMatch(/no commits/);
    expect(res.missing_tools).toEqual([]);
    expect(res.tools_run.find((t) => t.name === 'gitleaks-working-tree')?.status).toBe('ok');
  });

  it('honours the project .gitleaksignore in the working-tree pass', async () => {
    const dir = await repoWithCleanCommit('secrets-ignore-');
    writeFileSync(join(dir, 'keep.env'), SECRET_LINE);
    writeFileSync(join(dir, 'ignored.env'), SECRET_LINE);
    writeFileSync(join(dir, '.gitleaksignore'), 'ignored.env:aws-access-token:1\n');

    const { r, p } = await scan(dir);
    const res = r as unknown as SecretsResult;
    expect(findings(p, res.scan_id).map((f) => f.file_path)).toEqual(['keep.env']);
  });

  it('log_opts restricts history to a range, resolving each ref first', async () => {
    const dir = await repoWithCleanCommit('secrets-logopts-');
    writeFileSync(join(dir, 'late.txt'), SECRET_LINE);
    await git(dir, 'add', 'late.txt');
    await git(dir, 'commit', '-q', '-m', 'late secret');

    const { r, p } = await scan(dir, { log_opts: 'HEAD~1..HEAD' });
    const res = r as unknown as SecretsResult;
    expect(findings(p, res.scan_id).map((f) => f.file_path)).toEqual(['late.txt']);
    expect(res.tools_run.find((t) => t.name === 'gitleaks')?.reason).toMatch(/1 commit/);
  });

  it('a log_opts range that selects no commit is a failed history pass, not a clean one', async () => {
    const dir = await repoWithCleanCommit('secrets-emptyrange-');
    const { r } = await scan(dir, { log_opts: '--since=2099-01-01' });
    const res = r as unknown as SecretsResult;
    const history = res.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('failed');
    expect(history?.reason).toMatch(/0 commits/);
    expect(res.coverage).not.toBe('full');
  });
});

describe('scan_secrets log_opts validation', () => {
  it.each([
    ['--output=/tmp/pwn'],
    ['HEAD; rm -rf /'],
    ['-p'],
    ['--since=2020-01-01 --author=x'],
    ['$(whoami)..HEAD'],
  ])('refuses %j', async (logOpts) => {
    const dir = await repoWithCleanCommit('secrets-badopts-');
    const { r } = await scan(dir, { log_opts: logOpts });
    expect(r.ok).toBe(false);
  });

  it('refuses a range whose ref does not resolve, naming it', async () => {
    const dir = await repoWithCleanCommit('secrets-badref-');
    const { r } = await scan(dir, { log_opts: 'no-such-branch..HEAD' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/no-such-branch/);
  });
});
