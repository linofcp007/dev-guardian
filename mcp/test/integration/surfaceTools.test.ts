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

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
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
import { MAX_SPEC_FILES } from '../../src/surface/specDiscover.js';

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

/**
 * Same as `SEMGREP_OUTPUT` plus a second code route the spec does not
 * document, and a `guardian-mount-express` match in the same file. Without
 * the mount match, `resolveNodeMounts` cannot tell this file apart from an
 * unmounted router module and marks both routes `path_partial: true` (see
 * "marks a route partial when nothing mounts its module" in
 * `resolvers/node.test.ts`) — a partial route is `unmatchable`, never
 * `matched` or `code_only`, which would silently break the diff assertions
 * below. The mount match makes `src/routes/users.ts` a known "mounting
 * file", so both routes it declares are left resolved as-is.
 */
const SEMGREP_OUTPUT_WITH_SHADOW = JSON.stringify({
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
    {
      check_id: 'guardian-route-express',
      path: 'src/routes/users.ts',
      start: { line: 20 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: {
          $METHOD: { abstract_content: 'get' },
          $PATH: { abstract_content: '/internal/metrics' },
        },
      },
    },
    {
      check_id: 'guardian-mount-express',
      path: 'src/routes/users.ts',
      start: { line: 1 },
      extra: {
        metadata: { guardian_kind: 'mount', framework: 'express' },
        metavars: {
          $PREFIX: { abstract_content: "'/'" },
          $ROUTER: { abstract_content: 'someRouter' },
        },
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

/**
 * The same JS project as `JS_MOUNT_OUTPUT`, spelled the way Semgrep reports it
 * on Windows: absolute, backslash-separated. Every other field is identical,
 * so a difference in the result can only come from path handling.
 */
const WINDOWS_MOUNT_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'guardian-route-express',
      path: 'C:\\work\\proj\\src\\routes\\users.js',
      start: { line: 5 },
      extra: {
        metadata: { guardian_kind: 'route', framework: 'express', confidence: 'high' },
        metavars: { $METHOD: { abstract_content: 'get' }, $PATH: { abstract_content: '/users' } },
      },
    },
    {
      check_id: 'guardian-mount-express',
      path: 'C:\\work\\proj\\src\\app.js',
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
      path: 'C:\\work\\proj\\src\\app.js',
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

  it('resolves a mount when Semgrep reports Windows paths', async () => {
    // Semgrep reports paths in the host's native separator, and this tool
    // always hands it an absolute target — so on Windows every path comes back
    // as `C:\project\src\routes\users.js`. An import specifier is always
    // `./routes/users`, so before the paths are normalised the two never met:
    // resolveModuleFile saw one path segment, matched no known file, and every
    // mounted router degraded to path_partial. The bug was invisible to the
    // other mount tests because their fixtures are POSIX strings.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(WINDOWS_MOUNT_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      sample: { path_resolved: string; path_partial: boolean; file: string }[];
    };

    const route = result.sample.find((r) => r.file.endsWith('users.js'));
    expect(route?.path_resolved).toBe('/api/users');
    expect(route?.path_partial).toBe(false);
  });

  /* ---- redacted output (Semgrep >= ~1.120 without `semgrep login`) ------- */

  /**
   * A two-file Express app: the routes, the mount and the import that binds
   * them. Recovering all three from byte offsets is what makes `/api/list`
   * resolvable — a single-file fixture would not exercise the chain.
   */
  const REDACTED_FILES = new Map<string, string>([
    [
      'src/app.ts',
      "import usersRouter from './routes/users';\n" +
        'const app = express();\n' +
        "app.use('/api', usersRouter);\n" +
        "app.get('/health', (req, res) => res.send('ok'));\n" +
        "app.post('/items/:id', handler);\n",
    ],
    ['src/routes/users.ts', "router.get('/list', (req, res) => res.json([]));\n"],
  ]);

  const EXPRESS_ROUTE = { guardian_kind: 'route', framework: 'express', confidence: 'high' };

  const REDACTED_SPANS: { file: string; span: string; metadata: Record<string, unknown> }[] = [
    {
      file: 'src/app.ts',
      span: "import usersRouter from './routes/users'",
      metadata: { guardian_kind: 'import', framework: 'esm' },
    },
    {
      file: 'src/app.ts',
      span: "app.use('/api', usersRouter)",
      metadata: { guardian_kind: 'mount', framework: 'express' },
    },
    {
      file: 'src/app.ts',
      span: "app.get('/health', (req, res) => res.send('ok'))",
      metadata: EXPRESS_ROUTE,
    },
    { file: 'src/app.ts', span: "app.post('/items/:id', handler)", metadata: EXPRESS_ROUTE },
    {
      file: 'src/routes/users.ts',
      span: "router.get('/list', (req, res) => res.json([]))",
      metadata: EXPRESS_ROUTE,
    },
  ];

  /**
   * The exact shape modern Semgrep emits: `extra.metavars` absent, `lines`
   * and `fingerprint` replaced by "requires login", byte offsets intact.
   * Verified against Semgrep 1.164.0 on this machine.
   */
  function redactedOutput(
    spans: { file: string; span: string; metadata: Record<string, unknown> }[],
    reportedPath: (file: string) => string = (file) => file,
  ): string {
    return JSON.stringify({
      results: spans.map(({ file, span, metadata }, i) => {
        const source = REDACTED_FILES.get(file);
        if (source === undefined) throw new Error(`no test source for ${file}`);
        const start = Buffer.from(source, 'utf8').indexOf(Buffer.from(span, 'utf8'));
        if (start < 0) throw new Error(`test span not present in source: ${span}`);
        return {
          check_id: `guardian-redacted-${i}`,
          path: reportedPath(file),
          start: { line: 1, col: 1, offset: start },
          end: { line: 1, col: 1, offset: start + Buffer.byteLength(span, 'utf8') },
          extra: {
            metadata,
            severity: 'INFO',
            fingerprint: 'requires login',
            lines: 'requires login',
          },
        };
      }),
    });
  }

  /** Write REDACTED_FILES into a fresh project and return its path. */
  function projectWithSource(): string {
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    for (const [file, source] of REDACTED_FILES) {
      const absolute = join(projectPath, file);
      mkdirSync(join(absolute, '..'), { recursive: true });
      writeFileSync(absolute, source, 'utf8');
    }
    return projectPath;
  }

  it('extracts routes from redacted output by recovering metavars from the file', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());

    const projectPath = projectWithSource();
    vi.mocked(readJsonSafe).mockReturnValue(redactedOutput(REDACTED_SPANS));

    const ctx = makeCtx();
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      snapshot_id: number | null;
      sample: { method: string; path_resolved: string; path_partial: boolean; params: string[] }[];
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(result.routes_total).toBe(3);

    const health = result.sample.find((r) => r.path_resolved === '/health');
    expect(health?.method).toBe('GET');
    expect(health?.path_partial).toBe(false);

    const items = result.sample.find((r) => r.path_resolved === '/items/:id');
    expect(items?.method).toBe('POST');
    expect(items?.params).toEqual(['id']);

    // The whole chain — route + mount + import — recovered from byte offsets.
    const mounted = result.sample.find((r) => r.path_resolved === '/api/list');
    expect(mounted?.method).toBe('GET');
    expect(mounted?.path_partial).toBe(false);

    // A recovered run must not be silent.
    const recovery = result.tools_run.find((r) => r.name.includes('metavar'));
    expect(recovery?.status).toBe('ok');
    expect(recovery?.reason).toMatch(/5/);
    expect(ctx.storage.surface.getById(result.snapshot_id ?? 0)?.snapshot.routes).toHaveLength(3);
  });

  it('recovers when semgrep reports absolute paths (what it does for an absolute target)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());

    const projectPath = projectWithSource();
    vi.mocked(readJsonSafe).mockReturnValue(
      redactedOutput(REDACTED_SPANS, (file) => join(projectPath, file)),
    );

    const ctx = makeCtx();
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
    };
    expect(result.routes_total).toBe(3);
  });

  it('persists NOTHING when every redacted match is unrecoverable', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    // Offsets point into files that were never written — nothing to slice.
    vi.mocked(readJsonSafe).mockReturnValue(
      redactedOutput(REDACTED_SPANS, (file) => file.replace('src/', 'never-written/')),
    );

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      ok: boolean;
      routes_total: number;
      snapshot_id: number | null;
      note?: string;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    // Semgrep found matches; we could not read one of them. That is a broken
    // toolchain, not an application with no routes.
    expect(result.ok).toBe(true);
    expect(result.routes_total).toBe(0);
    expect(result.snapshot_id).toBeNull();
    expect(ctx.storage.surface.getLatest()).toBeNull();
    expect(result.note).toMatch(/semgrep login/i);
    expect(result.note).toMatch(/does not require an account/i);
    expect(result.tools_run.some((r) => r.status === 'failed')).toBe(true);
  });

  it('persists a partial recovery and reports the matches it could not read', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());

    const projectPath = projectWithSource();
    const readable = REDACTED_SPANS.filter((s) => s.file === 'src/app.ts');
    const lost = REDACTED_SPANS.filter((s) => s.file === 'src/routes/users.ts');
    const results = [
      ...(JSON.parse(redactedOutput(readable)) as { results: unknown[] }).results,
      ...(
        JSON.parse(redactedOutput(lost, (f) => f.replace('src/', 'gone/'))) as {
          results: unknown[];
        }
      ).results,
    ];
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results }));

    const ctx = makeCtx();
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      snapshot_id: number | null;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    // The two app.ts routes survive; the unreadable one is reported, not hidden.
    expect(result.routes_total).toBe(2);
    expect(result.snapshot_id).not.toBeNull();
    const recovery = result.tools_run.find((r) => r.name.includes('metavar'));
    expect(recovery?.status).toBe('failed');
    expect(recovery?.reason).toMatch(/1 match\(es\) could not be read/);
    // The remedy has to travel with the loss, or the reader is left guessing.
    expect(recovery?.reason).toMatch(/semgrep login/);
    expect(recovery?.reason).toMatch(/does not require an account/);
  });

  it('reports coverage `unreadable`, never `no_matches`, when routes were lost', async () => {
    // No rule family is refused any more, so the remaining way to lose a route
    // is a genuinely unreadable match: here, a TypeScript file Semgrep matched
    // that is not on disk when the recovery goes to read it — rewritten or
    // deleted mid-scan. The language must NOT report `no_matches`, which reads
    // as "this language exposes nothing" when the truth is "it exposes
    // something we could not read". That distinction is why the status exists,
    // and it outlives the limitation that first motivated it.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());

    const projectPath = projectWithSource();
    vi.mocked(readJsonSafe).mockReturnValue(
      JSON.stringify({
        results: [
          // One readable express route, so the run is not wholly degraded.
          ...(JSON.parse(redactedOutput([REDACTED_SPANS[2] as never])) as { results: unknown[] })
            .results,
          {
            check_id: 'guardian-route-nestjs-get',
            path: 'src/vanished.controller.ts',
            start: { line: 1, col: 1, offset: 0 },
            end: { line: 1, col: 1, offset: 42 },
            extra: {
              metadata: {
                guardian_kind: 'route',
                framework: 'nestjs',
                method: 'GET',
                guardian_focus: 'path',
              },
              severity: 'INFO',
              lines: 'requires login',
            },
          },
        ],
      }),
    );

    const ctx = makeCtx();
    const result = (await tool().handler({ project_path: projectPath }, ctx)) as {
      coverage: { language: string; status: string; unreadable_matches: number }[];
      tools_run: { name: string; status: string; reason?: string }[];
    };

    const ts = result.coverage.find((c) => c.language === 'typescript');
    expect(ts?.status).toBe('unreadable');
    expect(ts?.unreadable_matches).toBe(1);
    expect(result.coverage.every((c) => c.status !== 'no_matches')).toBe(true);
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

describe('map_attack_surface — spec import and diff', () => {
  const SPEC = [
    'openapi: "3.0.0"',
    'paths:',
    '  /users:',
    '    get: {}',
    '  /documented-but-gone:',
    '    get: {}',
  ].join('\n');

  it('imports spec routes, keeps routes_total counting code only, and finds both findings', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT); // one route: GET /users

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);
    // A second code route the spec does not document.
    // SEMGREP_OUTPUT_WITH_SHADOW adds GET /internal/metrics.
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT_WITH_SHADOW);

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      spec_routes_total: number;
      spec_diff_summary: { matched: number; code_only: number; spec_only: number } | null;
      shadow_sample: { path: string }[];
    };

    expect(r.routes_total).toBe(2);        // code routes only
    expect(r.spec_routes_total).toBe(2);
    expect(r.spec_diff_summary?.matched).toBe(1);
    expect(r.spec_diff_summary?.code_only).toBe(1);
    expect(r.spec_diff_summary?.spec_only).toBe(1);
    expect(r.shadow_sample[0]?.path).toBe('/internal/metrics');
  });

  it('produces no diff at all when the project has no spec', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_diff_summary: unknown;
      routes_total: number;
    };

    // The trap this guards: with no spec, every code route would otherwise
    // look undocumented.
    expect(r.spec_diff_summary).toBeNull();
    expect(r.routes_total).toBeGreaterThan(0);
  });

  it('keeps spec routes out of the per-language coverage report and the by_language breakdown', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      coverage: { language: string }[];
      by_language: { language: string }[];
    };
    expect(r.coverage.some((c) => c.language === 'spec')).toBe(false);
    // Same trap one layer up: by_language iterates snapshot.routes directly
    // and must filter to provenance === 'code' the same way buildCoverage
    // does, or a spec-provenance language sneaks into the breakdown.
    expect(r.by_language.some((c) => c.language === 'spec')).toBe(false);
  });

  it('reports a malformed spec without losing the diff of the good one', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);
    writeFileSync(join(projectPath, 'swagger.yaml'), 'paths:\n  - [unclosed\n');

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string }[];
      spec_diff_summary: unknown;
    };
    expect(r.spec_files.some((f) => f.status === 'parse_error')).toBe(true);
    expect(r.spec_diff_summary).not.toBeNull();
  });

  /** 25 spec paths — more than SAMPLE_SIZE (20) and more than the single code route below. */
  const MANY_PATHS_SPEC =
    'openapi: "3.0.0"\npaths:\n' +
    Array.from({ length: 25 }, (_, i) => `  /spec-path-${i}:\n    get: {}\n`).join('');

  it('does not let spec routes evict code routes from `sample`', async () => {
    // Reproduces the measured bug: `sample` used to slice snapshot.routes
    // (code + spec mixed) sorted by language first. `'spec'` sorts before
    // `'typescript'`, so 20 spec entries filled every slot and the sole code
    // route never appeared — even though routes_total said 1. A spec sample
    // is served separately in `spec_sample` instead of competing for the
    // same 20 slots.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT); // one code route: GET /users

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), MANY_PATHS_SPEC);

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      spec_routes_total: number;
      sample: { path_resolved: string }[];
      spec_sample: { path_resolved: string }[];
    };

    expect(r.routes_total).toBe(1);
    expect(r.spec_routes_total).toBe(25);
    // The result must be internally consistent: routes_total says 1 code
    // route exists, so `sample` — the field a reading agent looks at first —
    // must contain exactly that one, not be dominated by spec entries.
    expect(r.sample).toHaveLength(1);
    expect(r.sample[0]?.path_resolved).toBe('/users');
    // The spec sample is capped at 20 and holds only spec-provenance routes.
    expect(r.spec_sample).toHaveLength(20);
    expect(r.spec_sample.every((s) => s.path_resolved.startsWith('/spec-path-'))).toBe(true);
  });

  it('bypasses the cache when spec_paths is supplied, so different explicit specs are not confused', async () => {
    // Measured bug: the tree-hash cache key says nothing about spec_paths, so
    // a second call with a DIFFERENT explicit spec silently returned the
    // first call's spec_files. Two calls that name different documents must
    // never report the same spec_files.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'a.yaml'), SPEC);
    writeFileSync(join(projectPath, 'b.yaml'), MANY_PATHS_SPEC);

    const first = (await tool().handler(
      { project_path: projectPath, spec_paths: ['a.yaml'] },
      ctx,
    )) as { spec_files: { file: string }[]; spec_routes_total: number };
    const second = (await tool().handler(
      { project_path: projectPath, spec_paths: ['b.yaml'] },
      ctx,
    )) as { spec_files: { file: string }[]; spec_routes_total: number };

    expect(first.spec_routes_total).toBe(2); // SPEC declares /users + /documented-but-gone
    expect(second.spec_routes_total).toBe(25); // MANY_PATHS_SPEC
    expect(first.spec_files.map((f) => f.file)).not.toEqual(second.spec_files.map((f) => f.file));
    expect(second.spec_files.some((f) => f.file.endsWith('b.yaml'))).toBe(true);
    expect(second.spec_files.some((f) => f.file.endsWith('a.yaml'))).toBe(false);
  });

  it('does not persist an explicit spec_paths snapshot, so a later plain call never inherits it', async () => {
    // The write-side half of the same conflation the read-side cache-bypass
    // fixes above: if the explicit-spec_paths snapshot were persisted, it
    // would become "latest for this tree hash", and a later PLAIN call (no
    // spec_paths, same unchanged tree) would read it back from the cache and
    // report the explicitly-named document as if auto-discovery had found
    // it — even though nothing about this project's own layout ever named
    // it. Not persisting closes it at the source.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    // 'a.yaml' is not a conventional spec basename (openapi/swagger/api-docs)
    // and does not live under an openapi/ directory, so auto-discovery would
    // never find it on its own.
    writeFileSync(join(projectPath, 'a.yaml'), MANY_PATHS_SPEC);

    const explicit = (await tool().handler(
      { project_path: projectPath, spec_paths: ['a.yaml'] },
      ctx,
    )) as {
      spec_routes_total: number;
      spec_files: { file: string }[];
      snapshot_id: number | null;
    };

    expect(explicit.spec_routes_total).toBe(25);
    expect(explicit.spec_files.some((f) => f.file.endsWith('a.yaml'))).toBe(true);
    // Nothing was written: no row exists to become "latest for this tree hash".
    expect(explicit.snapshot_id).toBeNull();
    expect(ctx.storage.surface.getLatest()).toBeNull();

    const plain = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_routes_total: number;
      spec_files: { file: string }[];
      spec_diff_summary: unknown;
    };

    // The critical assertion: the plain call must NOT report a.yaml — it was
    // never auto-discoverable, so the plain call must see no spec at all.
    expect(plain.spec_routes_total).toBe(0);
    expect(plain.spec_files).toEqual([]);
    expect(plain.spec_diff_summary).toBeNull();
  });

  it('resolves a relative spec_paths entry against project_path, not process.cwd()', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    mkdirSync(join(projectPath, 'docs'), { recursive: true });
    writeFileSync(join(projectPath, 'docs', 'openapi.yaml'), SPEC);

    const r = (await tool().handler(
      { project_path: projectPath, spec_paths: ['docs/openapi.yaml'] },
      ctx,
    )) as { spec_routes_total: number; spec_files: { status: string; file: string }[] };

    expect(r.spec_routes_total).toBe(2);
    expect(r.spec_files[0]?.status).toBe('ok');
    expect(r.spec_files[0]?.file).toBe(join(projectPath, 'docs', 'openapi.yaml'));
  });

  it('reports an explicit spec_paths entry that does not exist, rather than reading as no spec', async () => {
    // Measured bug: a nonexistent explicit path produced spec_files: [],
    // spec_diff: null — indistinguishable from "this project has no spec".
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));

    const r = (await tool().handler(
      { project_path: projectPath, spec_paths: ['does-not-exist.yaml'] },
      ctx,
    )) as { spec_files: { status: string; file: string; reason?: string }[] };

    expect(r.spec_files).toHaveLength(1);
    expect(r.spec_files[0]?.status).toBe('parse_error');
    expect(r.spec_files[0]?.file).toBe(join(projectPath, 'does-not-exist.yaml'));
    expect(r.spec_files[0]?.reason).toMatch(/could not be read/);
  });

  it('counts a spec that parses but declares no paths toward specsParsed (diff is not null)', async () => {
    // Pins the `|| report.status === 'no_paths'` clause: a valid document
    // that declares nothing is still a successfully parsed spec and must not
    // disable the diff the way "no spec was found at all" does.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), 'openapi: "3.0.0"\npaths: {}\n');

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string }[];
      spec_diff_summary: unknown;
    };

    expect(r.spec_files[0]?.status).toBe('no_paths');
    expect(r.spec_diff_summary).not.toBeNull();
  });

  it('reports spec_diff as null when the ONLY spec present fails to parse', async () => {
    // The malformed-spec test above always writes a good spec alongside, so
    // it would still pass even if a parse_error counted toward specsParsed.
    // This pins the case that actually matters: no good spec anywhere means
    // specsParsed stays 0 and the diff must be null, not an empty diff.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), 'paths:\n  - [unclosed\n');

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string }[];
      spec_diff_summary: unknown;
    };

    expect(r.spec_files.some((f) => f.status === 'parse_error')).toBe(true);
    expect(r.spec_diff_summary).toBeNull();
  });

  it('reports the file-count discovery cap as a parse_error spec_files entry', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results: [] }));

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    mkdirSync(join(projectPath, 'openapi'), { recursive: true });
    for (let i = 0; i < MAX_SPEC_FILES + 3; i += 1) {
      writeFileSync(join(projectPath, 'openapi', `s${i}.yaml`), 'openapi: "3.0.0"\npaths: {}\n');
    }

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string; reason?: string }[];
    };

    expect(r.spec_files).toHaveLength(MAX_SPEC_FILES + 1); // 20 read + 1 cap report
    expect(
      r.spec_files.some(
        (f) => f.status === 'parse_error' && f.reason?.includes(`${MAX_SPEC_FILES}`),
      ),
    ).toBe(true);
  });

  it('reports an oversized spec file as a parse_error spec_files entry', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(JSON.stringify({ results: [] }));

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), 'x'.repeat(6 * 1024 * 1024));

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string; reason?: string }[];
    };

    expect(
      r.spec_files.some((f) => f.status === 'parse_error' && f.reason?.includes('size cap')),
    ).toBe(true);
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
        tools_run: [], missing_tools: [], spec_files: [], spec_diff: null,
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
        tools_run: [], missing_tools: [], spec_files: [], spec_diff: null,
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
