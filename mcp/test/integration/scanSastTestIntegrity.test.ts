/**
 * A diff-scoped scan_sast reports the tests its change weakened — a deleted
 * test file included, for uncommitted and staged changes too (fix round 1 of
 * the review, item 5: the scope's members were the files to SCAN, and a
 * deletion is none of them, so the factory dropped `test-file-deleted`).
 *
 * No scanner is installed here: Semgrep and the rest are skipped, the
 * in-process test-integrity pass still runs.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 120_000 });

vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
});
beforeEach(() => {
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue(null);
});

function git(cwd: string, ...args: string[]): void {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
}

function repo(): string {
  const dir = makeTempDir('sast-test-integrity-');
  git(dir, 'init', '-q');
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a.test.ts'), "it('a', () => { expect(1).toBe(1); });\n");
  writeFileSync(join(dir, 'src', 'b.test.ts'), "it('b', () => { expect(2).toBe(2); });\n");
  writeFileSync(join(dir, 'src', 'app.ts'), 'export const x = 1;\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'base');
  return dir;
}

async function scan(dir: string, scope: Record<string, unknown>): Promise<{ rows: string[]; run: ToolRun | undefined }> {
  const db = new Database(':memory:');
  runMigrations(db);
  const plugin: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (tool === undefined) throw new Error('scan_sast not registered');
  const r = (await tool.handler({ project_path: dir, force: true, scope }, plugin)) as unknown as { ok: boolean; scan_id: string; tools_run: ToolRun[] };
  expect(r.ok).toBe(true);
  const rows = plugin.storage.findings
    .listByScan(r.scan_id)
    .filter((f) => f.tool === 'guardian-test-integrity')
    .map((f) => `${f.rule_id} ${f.file_path}:${f.line_start ?? '-'}`)
    .sort();
  return { rows, run: r.tools_run.find((t) => t.name === 'guardian-test-integrity') };
}

describe('scan_sast with a change scope reports weakened tests, deletions included', () => {
  it('scope.diff {} (uncommitted): a deleted test file and an added focus', async () => {
    const dir = repo();
    rmSync(join(dir, 'src', 'a.test.ts'));
    writeFileSync(join(dir, 'src', 'b.test.ts'), "it.only('b', () => { expect(2).toBe(2); });\n");
    const { rows, run } = await scan(dir, { diff: {} });
    expect(run?.status).toBe('ok');
    expect(rows).toEqual(['test-file-deleted src/a.test.ts:-', 'test-focused src/b.test.ts:1']);
  });

  it('scope.diff { staged: true }: a test file removed with git rm', async () => {
    const dir = repo();
    git(dir, 'rm', '-q', 'src/a.test.ts');
    const { rows } = await scan(dir, { diff: { staged: true } });
    expect(rows).toEqual(['test-file-deleted src/a.test.ts:-']);
  });

  it('scope.paths: no change set, no check', async () => {
    const dir = repo();
    writeFileSync(join(dir, 'src', 'b.test.ts'), "it.only('b', () => {});\n");
    const { rows, run } = await scan(dir, { paths: ['src'] });
    expect(run).toBeUndefined();
    expect(rows).toEqual([]);
  });
});
