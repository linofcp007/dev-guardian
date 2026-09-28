/**
 * precommit_install reports each hook stage as it actually came out.
 *
 * It installs the default `pre-commit` stage and then, "best effort",
 * `commit-msg` and `pre-push` — and used to report all three installed
 * whatever those two extra installs returned. A stage that failed to install
 * is a hook that will silently never run.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import type { PluginContext } from '../../src/context.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/precommitInstall.js');
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'precommit_install');
  if (!t) throw new Error('precommit_install not registered');
  return t;
}

function repo(): string {
  const dir = makeTempDir('precommit-');
  mkdirSync(join(dir, '.git'));
  writeFileSync(join(dir, '.pre-commit-config.yaml'), 'repos: []\n');
  return dir;
}

function plugin(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/usr/bin/pre-commit');
});

type Out = {
  ok: true;
  stages_installed: string[];
  stages_failed?: Array<{ stage: string; error: string }>;
  warnings?: string[];
};

describe('precommit_install', () => {
  it('reports a stage whose install failed as failed, not installed', async () => {
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const stage = opts.args?.[opts.args.indexOf('--hook-type') + 1];
      if (opts.args?.includes('--hook-type') && stage === 'commit-msg') {
        return {
          outcome: 'failed',
          exitCode: 1,
          stdout: '',
          stderr: 'An unexpected error has occurred: hook exists',
          truncated: false,
        };
      }
      return { outcome: 'completed', exitCode: 0, stdout: 'pre-commit installed', stderr: '', truncated: false };
    });
    const dir = repo();
    const r = (await tool().handler({ project_path: dir }, plugin(dir))) as Out;
    expect(r.ok).toBe(true);
    expect(r.stages_installed).toEqual(['pre-commit', 'pre-push']);
    expect(r.stages_failed).toEqual([
      { stage: 'commit-msg', error: 'An unexpected error has occurred: hook exists' },
    ]);
    expect(r.warnings?.join(' ')).toContain('commit-msg');
  });

  it('reports all three when all three installed', async () => {
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '',
      stderr: '',
      truncated: false,
    });
    const dir = repo();
    const r = (await tool().handler({ project_path: dir }, plugin(dir))) as Out;
    expect(r.stages_installed).toEqual(['pre-commit', 'commit-msg', 'pre-push']);
    expect(r.stages_failed).toEqual([]);
    expect(r.warnings).toBeUndefined();
  });
});
