/**
 * Mocks `scannerAvailable` and `runProcess` so the whole tool runs without
 * Semgrep installed, following the pattern in securityTools.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn(), readJsonSafe: vi.fn() };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { readJsonSafe, scannerAvailable } from '../../src/tools/scanHelpers.js';
import { runProcess, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { TOOLS } from '../../src/tools/index.js';
import type { PluginContext } from '../../src/context.js';
import '../../src/tools/mapAttackSurface.js';

const SEMGREP_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'guardian-route-express',
      path: 'src/routes/users.ts',
      start: { line: 12 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: { $METHOD: { abstract_content: 'get' }, $PATH: { abstract_content: '/users' } },
      },
    },
  ],
});

function makeCtx(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool() {
  const found = TOOLS.find((t) => t.name === 'map_attack_surface');
  if (!found) throw new Error('map_attack_surface is not registered');
  return found;
}

/** ProcessRunResult has five required fields — a partial mock will not type-check. */
function okRun(outcome: ProcessRunResult['outcome'] = 'completed'): ProcessRunResult {
  return { outcome, exitCode: outcome === 'completed' ? 0 : 1, stdout: '', stderr: '', truncated: false };
}

describe('map_attack_surface', () => {
  beforeEach(() => {
    vi.mocked(scannerAvailable).mockReset();
    vi.mocked(readJsonSafe).mockReset();
    vi.mocked(runProcess).mockReset();
  });

  it('extracts, resolves and persists a snapshot', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      routes_total: number;
      snapshot_id: number;
      sample: { path_resolved: string }[];
    };

    expect(result.ok).toBe(true);
    expect(result.routes_total).toBe(1);
    expect(result.sample[0]?.path_resolved).toBe('/users');
    expect(ctx.storage.surface.getById(result.snapshot_id)?.snapshot.routes).toHaveLength(1);
  });

  it('persists NOTHING when semgrep is unavailable', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      missing_tools: string[];
      snapshot_id: number | null;
    };

    expect(result.missing_tools).toContain('semgrep');
    expect(result.snapshot_id).toBeNull();
    // The critical assertion: a zero-route snapshot must never be written,
    // or scan_dast would later read "this app exposes nothing".
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });

  it('reports no_rules for a detected language the pack does not cover', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results: [] }));

    const ctx = makeCtx();
    ctx.storage.stack.insert({
      project_path: '/p',
      snapshot: {
        os: 'linux', arch: 'x64', languages: ['elixir'], package_managers: [],
        frameworks: [], existing_tools: [], has_docker: false, has_compose: false,
        has_terraform: false, has_kubernetes: false, has_ansible: false,
        has_github_actions: false, has_gitlab_ci: false,
      },
    });

    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      coverage: { language: string; status: string }[];
    };

    expect(result.coverage.find((c) => c.language === 'elixir')?.status).toBe('no_rules');
  });

  it('returns the cached snapshot when the tree hash is unchanged', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    const first = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number;
    };
    const second = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(second.snapshot_id).toBe(first.snapshot_id);
    expect(second.tools_run[0]?.reason).toBe('cached');
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(1);
  });

  it('persists the snapshot when semgrep fails but still emitted parseable JSON', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun('failed'));
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      tools_run: { status: string }[];
    };

    // Partial data is still useful — the failed tools_run entry carries the
    // warning. This is the one failure mode where we DO persist.
    expect(result.snapshot_id).not.toBeNull();
    expect(result.tools_run[0]?.status).toBe('failed');
    expect(ctx.storage.surface.getLatest()).not.toBeNull();
  });

  it('returns a domain error for an unusable project_path', async () => {
    const ctx = makeCtx();
    const result = (await tool().handler(
      { project_path: join(tmpdir(), 'guardian-does-not-exist-xyz') },
      ctx,
    )) as { ok: boolean; error?: { code: string } };

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('not_a_git_repo');
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });
});
