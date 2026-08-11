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
import { RESOURCES } from '../../src/resources/index.js';
import '../../src/resources/surface.js';

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

/** JS project: extension-less specifier, real route file is `.js` (B2 scenario 1). */
const JS_MOUNT_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'guardian-route-express',
      path: 'src/routes/users.js',
      start: { line: 5 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: { $METHOD: { abstract_content: 'get' }, $PATH: { abstract_content: '/users' } },
      },
    },
    {
      check_id: 'guardian-mount-express',
      path: 'src/app.js',
      start: { line: 10 },
      extra: {
        metadata: { guardian_kind: 'mount', framework: 'express' },
        metavars: {
          $PREFIX: { abstract_content: "'/api'" },
          $ROUTER: { abstract_content: 'usersRouter' },
        },
      },
    },
    {
      check_id: 'guardian-import-esm',
      path: 'src/app.js',
      start: { line: 1 },
      extra: {
        metadata: { guardian_kind: 'import' },
        metavars: {
          $SYMBOL: { abstract_content: 'usersRouter' },
          $MODULE: { abstract_content: "'./routes/users'" },
        },
      },
    },
  ],
});

/**
 * TS project under NodeNext (this repo's own convention): the import
 * specifier says `.js` but the real matched source file is `.ts` (B2
 * scenario 2 — the mismatch the extension-insensitive match must bridge).
 */
const TS_NODENEXT_MOUNT_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'guardian-route-express',
      path: 'src/routes/users.ts',
      start: { line: 5 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: { $METHOD: { abstract_content: 'get' }, $PATH: { abstract_content: '/users' } },
      },
    },
    {
      check_id: 'guardian-mount-express',
      path: 'src/app.ts',
      start: { line: 10 },
      extra: {
        metadata: { guardian_kind: 'mount', framework: 'express' },
        metavars: {
          $PREFIX: { abstract_content: "'/api'" },
          $ROUTER: { abstract_content: 'usersRouter' },
        },
      },
    },
    {
      check_id: 'guardian-import-esm',
      path: 'src/app.ts',
      start: { line: 1 },
      extra: {
        metadata: { guardian_kind: 'import' },
        metavars: {
          $SYMBOL: { abstract_content: 'usersRouter' },
          $MODULE: { abstract_content: "'./routes/users.js'" },
        },
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
      webhooks_total: number;
    };

    expect(result.ok).toBe(true);
    expect(result.routes_total).toBe(1);
    expect(result.sample[0]?.path_resolved).toBe('/users');
    expect(result.webhooks_total).toBe(0);
    expect(ctx.storage.surface.getById(result.snapshot_id)?.snapshot.routes).toHaveLength(1);
  });

  it('persists NOTHING when semgrep is unavailable (native or Docker)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      missing_tools: string[];
      snapshot_id: number | null;
      webhooks_total: number;
    };

    expect(result.missing_tools).toContain('semgrep');
    expect(result.snapshot_id).toBeNull();
    expect(result.webhooks_total).toBe(0);
    // The critical assertion: a zero-route snapshot must never be written,
    // or scan_dast would later read "this app exposes nothing".
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });

  it('falls back to Docker when semgrep is not on PATH', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'docker' ? '/fake/bin/docker' : null,
    );
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(result.snapshot_id).not.toBeNull();
    expect(result.tools_run[0]?.status).toBe('ok');
    expect(result.tools_run[0]?.reason).toContain('docker');
    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call?.command).toBe('docker');
    expect(ctx.storage.surface.getLatest()).not.toBeNull();
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
      stack_detected: boolean;
    };

    expect(result.coverage.find((c) => c.language === 'elixir')?.status).toBe('no_rules');
    expect(result.stack_detected).toBe(true);
  });

  it('reports stack_detected=false and advises detect_stack when no stack snapshot exists', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      stack_detected: boolean;
      note?: string;
    };

    expect(result.stack_detected).toBe(false);
    expect(result.note).toMatch(/detect_stack/);
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

  it('force:true bypasses the cache and re-runs semgrep', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    await tool().handler({ project_path: projectPath }, ctx);
    await tool().handler({ project_path: projectPath, force: true }, ctx);

    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(2);
  });

  it('persists the snapshot when semgrep fails but still emitted parseable JSON', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    // exitCode 1 means "found matches" under the repo's Semgrep convention —
    // that is success. A genuine failure needs a different exit code.
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'failed',
      exitCode: 2,
      stdout: '',
      stderr: 'semgrep: fatal: something broke\nmore detail\n',
      truncated: false,
    });
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      tools_run: { status: string; reason?: string }[];
    };

    // Partial data is still useful — the failed tools_run entry carries the
    // warning. This is the one failure mode where we DO persist.
    expect(result.snapshot_id).not.toBeNull();
    expect(result.tools_run[0]?.status).toBe('failed');
    expect(result.tools_run[0]?.reason).toBe('semgrep: fatal: something broke');
    expect(ctx.storage.surface.getLatest()).not.toBeNull();
  });

  it('treats exitCode 1 as success — semgrep exits 1 when it FINDS matches', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    // The normal success path for this tool: execa reports outcome 'failed'
    // for any non-zero exit, but exit 1 from Semgrep means "matches found".
    // Without the `|| exitCode === 1` clause in buildToolRun, every run that
    // actually found routes would be reported as a failed scan.
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'failed',
      exitCode: 1,
      stdout: '',
      stderr: '',
      truncated: false,
    });
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      routes_total: number;
      tools_run: { status: string; reason?: string }[];
    };

    expect(result.tools_run[0]?.status).toBe('ok');
    expect(result.routes_total).toBe(1);
    expect(result.snapshot_id).not.toBeNull();
  });

  it('keeps reporting a persisted failed run on later cached calls', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    // Genuine failure (exit 2) that still left parseable JSON — the one case
    // where a failed run is persisted. Its warning must not be swallowed by
    // the cache marker on the second call, or an empty snapshot that is empty
    // *because the scan died* reads as "this application exposes nothing".
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'failed',
      exitCode: 2,
      stdout: '',
      stderr: 'semgrep: fatal: rule pack failed to load\n',
      truncated: false,
    });
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results: [] }));

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    await tool().handler({ project_path: projectPath }, ctx);
    const second = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(1);
    expect(second.routes_total).toBe(0);
    expect(second.tools_run[0]?.reason).toBe('cached');
    const failed = second.tools_run.find((r) => r.status === 'failed');
    expect(failed).toBeDefined();
    expect(failed?.reason).toContain('rule pack failed to load');
  });

  it('persists nothing when semgrep runs but produces no readable output', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(null);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      snapshot_id: number | null;
      tools_run: { status: string; reason?: string }[];
      webhooks_total: number;
    };

    expect(result.snapshot_id).toBeNull();
    expect(result.tools_run[0]?.status).toBe('failed');
    expect(result.webhooks_total).toBe(0);
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });

  it('persists nothing and does not throw when semgrep output is not valid JSON', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue('{ this is not json');

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      snapshot_id: number | null;
      tools_run: { status: string; reason?: string }[];
    };

    expect(result.ok).toBe(true);
    expect(result.snapshot_id).toBeNull();
    expect(result.tools_run[0]?.status).toBe('failed');
    expect(result.tools_run[0]?.reason).toMatch(/unparseable/);
    expect(ctx.storage.surface.getLatest()).toBeNull();
  });

  it('invokes semgrep with the routes rule pack and without --no-git-ignore', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    await tool().handler({ project_path: projectPath }, ctx);

    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call?.command).toBe('semgrep');
    const args = call?.args ?? [];
    const configIndex = args.indexOf('--config');
    expect(configIndex).toBeGreaterThanOrEqual(0);
    expect(args[configIndex + 1]).toBe(
      join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml'),
    );
    expect(args).not.toContain('--no-git-ignore');
  });

  it('skips env var collection when include_env_vars is false', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(
      JSON.stringify({
        results: [
          {
            check_id: 'guardian-env-var',
            path: 'src/config.ts',
            start: { line: 1 },
            extra: {
              metadata: { guardian_kind: 'env' },
              metavars: { $NAME: { abstract_content: "'API_KEY'" } },
            },
          },
        ],
      }),
    );

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler(
      { project_path: projectPath, include_env_vars: false },
      ctx,
    )) as { env_vars_total: number; snapshot_id: number };

    expect(result.env_vars_total).toBe(0);
    expect(ctx.storage.surface.getById(result.snapshot_id)?.snapshot.env_vars).toHaveLength(0);
  });

  it('resolves a route in a mounted module for a plain-JS project (extension-less import)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(JS_MOUNT_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      sample: { path_resolved: string; path_partial: boolean; file: string }[];
    };

    const route = result.sample.find((r) => r.file === 'src/routes/users.js');
    expect(route?.path_resolved).toBe('/api/users');
    expect(route?.path_partial).toBe(false);
  });

  it('resolves a route in a mounted module under NodeNext (.js specifier, .ts source)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(TS_NODENEXT_MOUNT_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      sample: { path_resolved: string; path_partial: boolean; file: string }[];
    };

    const route = result.sample.find((r) => r.file === 'src/routes/users.ts');
    expect(route?.path_resolved).toBe('/api/users');
    expect(route?.path_partial).toBe(false);
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

describe('guardian://surface resources', () => {
  function resource(name: string) {
    const found = RESOURCES.find((r) => r.name === name);
    if (!found) throw new Error(`${name} is not registered`);
    return found;
  }

  it('returns { snapshot: null } before anything is captured', async () => {
    const ctx = makeCtx();
    const { json } = await resource('guardian-surface-latest').handler(
      new URL('guardian://surface/latest'),
      {},
      ctx,
    );
    expect(json).toEqual({ snapshot: null });
  });

  it('serves the latest snapshot with its full route list', async () => {
    const ctx = makeCtx();
    ctx.storage.surface.insert({
      project_path: '/p',
      tree_hash: 'h',
      snapshot: {
        routes: [], env_vars: [], ports: [], webhooks: [], coverage: [],
        tools_run: [], missing_tools: [],
      },
    });
    const { json } = await resource('guardian-surface-latest').handler(
      new URL('guardian://surface/latest'),
      {},
      ctx,
    );
    expect(json).toHaveProperty('captured_at');
    expect(json).toHaveProperty('snapshot.routes');
  });

  it('serves a snapshot by id and nulls an unknown id', async () => {
    const ctx = makeCtx();
    const inserted = ctx.storage.surface.insert({
      project_path: '/p',
      tree_hash: 'h',
      snapshot: {
        routes: [], env_vars: [], ports: [], webhooks: [], coverage: [],
        tools_run: [], missing_tools: [],
      },
    });

    const byId = resource('guardian-surface-by-id');
    const hit = await byId.handler(
      new URL(`guardian://surface/${inserted.id}`),
      { id: String(inserted.id) },
      ctx,
    );
    expect(hit.json).toHaveProperty('snapshot.routes');

    const miss = await byId.handler(new URL('guardian://surface/999'), { id: '999' }, ctx);
    expect(miss.json).toEqual({ snapshot: null });
  });
});
