/**
 * `scan_secrets { log_opts }` narrows the HISTORY pass to a window of
 * commits, so its silence about every commit outside that window is not
 * evidence: such a run is recorded as scoped (`meta.scope`), exactly like
 * `scope.since`. Recorded as a whole-project scan, it became the secrets
 * slot's source at coverage full, and every secret found before the window
 * vanished from findings/open, risk_score and the dashboard — and a diff
 * counted them resolved.
 *
 * gitleaks is faked (a mocked `runProcess`: a history pass without
 * `--log-opts` finds one secret in an old commit, one with it finds none);
 * git is real, because `log_opts` refs are resolved against the repository.
 */

import { execa } from 'execa';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 60_000 });

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { openSetForProject } from '../../src/history/openSet.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
});

const OLD_COMMIT = 'a'.repeat(40);

/** gitleaks: the full history holds one secret, in an old commit; a narrowed one holds none. */
async function fakeGitleaks(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const args = opts.args ?? [];
  const reportPath = args.find((a) => a.startsWith('--report-path='))?.slice('--report-path='.length);
  const history = !args.includes('--no-git');
  const narrowed = args.some((a) => a.startsWith('--log-opts='));
  const items =
    history && !narrowed
      ? [
          {
            RuleID: 'generic-api-key',
            Description: 'Generic API Key',
            StartLine: 3,
            EndLine: 3,
            StartColumn: 1,
            EndColumn: 30,
            Match: 'REDACTED',
            Secret: 'REDACTED',
            File: 'config/old.env',
            Commit: OLD_COMMIT,
            Fingerprint: `${OLD_COMMIT}:config/old.env:generic-api-key:3`,
          },
        ]
      : [];
  if (reportPath !== undefined) writeFileSync(reportPath, JSON.stringify(items));
  return {
    outcome: 'completed',
    exitCode: items.length > 0 ? 1 : 0,
    stdout: '',
    stderr: history ? `INF ${narrowed ? 1 : 2} commits scanned.` : 'INF scanned ~10 bytes',
    truncated: false,
  };
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

async function repoWithTwoCommits(): Promise<string> {
  const dir = makeTempDir('secrets-logopts-');
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  writeFileSync(join(dir, 'README.md'), '# fixture\n');
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'first');
  writeFileSync(join(dir, 'README.md'), '# fixture, again\n');
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'second');
  return resolveProjectPath(dir).path;
}

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
}

async function scanSecrets(p: PluginContext, project: string, extra: Record<string, unknown> = {}): Promise<{ scan_id: string }> {
  const t = TOOLS.find((x) => x.name === 'scan_secrets');
  if (t === undefined) throw new Error('scan_secrets not registered');
  return okResult<{ scan_id: string }>(await t.handler({ project_path: project, force: true, ...extra }, p));
}

beforeEach(() => {
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeGitleaks);
});

describe('scan_secrets log_opts is a scoped run', () => {
  it('a narrowed history pass never hides the secrets an earlier full scan found before its window', async () => {
    const project = await repoWithTwoCommits();
    const p = plugin();
    const full = await scanSecrets(p, project);
    expect(openSetForProject(p.storage, project).findings).toHaveLength(1);

    const narrowed = await scanSecrets(p, project, { log_opts: 'HEAD~1..HEAD' });
    expect(p.storage.scans.getById(narrowed.scan_id)?.meta?.['scope']).toMatchObject({ kind: 'log_opts' });
    // It says what it narrowed, and never reads as a scope of "paths, 0 file(s)".
    const warnings = (narrowed as { warnings?: string[] }).warnings ?? [];
    expect(warnings).toContainEqual(expect.stringContaining('narrowed the history pass'));
    expect(warnings.some((w) => w.includes('0 file(s)'))).toBe(false);
    const set = openSetForProject(p.storage, project);
    expect(set.findings.map((f) => f.file_path)).toEqual(['config/old.env']);
    expect(set.sources.map((s) => s.scan_id)).toEqual([full.scan_id]);
  });

  it('--all alone narrows nothing: the run stays a whole-project scan', async () => {
    const project = await repoWithTwoCommits();
    const p = plugin();
    const all = await scanSecrets(p, project, { log_opts: '--all' });
    expect(p.storage.scans.getById(all.scan_id)?.meta?.['scope']).toBeUndefined();
    expect(openSetForProject(p.storage, project).sources.map((s) => s.scan_id)).toEqual([all.scan_id]);
  });
});
