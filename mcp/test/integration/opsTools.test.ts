/**
 * Integration tests for detect_stack, init_project, observability_setup,
 * perf_check.
 *
 * detect_stack + init_project shell out → mock runShellScript.
 * perf_check spawns scanner CLI → mock runProcess + scannerAvailable.
 * observability_setup is pure file-system logic — no execa to mock.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/scanIac.js');
  await import('../../src/tools/bugHunt.js');
  await import('../../src/tools/qualityCheck.js');
  await import('../../src/tools/reviewPr.js');
  await import('../../src/tools/depsAudit.js');
  await import('../../src/tools/depsUpdatePlan.js');
  await import('../../src/tools/complianceCheck.js');
  await import('../../src/tools/generateSbom.js');
  await import('../../src/tools/detectStack.js');
  await import('../../src/tools/initProject.js');
  await import('../../src/tools/observabilitySetup.js');
  await import('../../src/tools/perfCheck.js');
});

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'ops-tools-'));
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string, scriptsDir?: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: {
      command: 'bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'fake',
    },
    scriptsDir: scriptsDir ?? projectPath,
    progressNotifier: { send: () => {} },
  };
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('detect_stack', () => {
  it('parses detect-stack.sh JSON output and persists a snapshot', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    const fakeSnapshot = {
      os: 'windows',
      arch: 'x86_64',
      languages: ['javascript', 'typescript'],
      package_managers: ['npm'],
      frameworks: ['react', 'nextjs'],
      existing_tools: [],
      has_docker: false,
      has_compose: false,
      has_terraform: false,
      has_kubernetes: false,
      has_ansible: false,
      has_github_actions: true,
      has_gitlab_ci: false,
    };
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: JSON.stringify(fakeSnapshot),
      stderr: '',
      truncated: false,
    });

    const tool = getTool('detect_stack');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      snapshot: typeof fakeSnapshot;
      snapshot_id: number;
    };
    expect(r.ok).toBe(true);
    expect(r.snapshot.languages).toEqual(['javascript', 'typescript']);
    // Persisted?
    expect(plugin.storage.stack.getLatest()?.snapshot.languages).toEqual([
      'javascript',
      'typescript',
    ]);
  });

  it('returns scanner_failed when stdout is not valid JSON', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: 'not-json',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('detect_stack');
    const r = (await tool.handler({ project_path: project }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('scanner_failed');
  });
});

describe('init_project', () => {
  it('copies profile configs into the project (idempotent)', async () => {
    const project = tempProject();
    // Build a fake "configs/" alongside scripts/ so initProject can resolve them.
    const scriptsDir = mkdtempSync(join(tmpdir(), 'init-scripts-'));
    const configsDir = join(scriptsDir, '..', 'configs');
    mkdirSync(join(configsDir, 'gitleaks'), { recursive: true });
    mkdirSync(join(configsDir, 'renovate'), { recursive: true });
    mkdirSync(join(configsDir, 'semgrep'), { recursive: true });
    mkdirSync(join(configsDir, 'pre-commit'), { recursive: true });
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '# gl\n', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{}', 'utf8');
    writeFileSync(join(configsDir, 'semgrep', 'base.yml'), 'rules: []\n', 'utf8');
    writeFileSync(
      join(configsDir, 'pre-commit', 'pre-commit-config.yaml'),
      'repos: []\n',
      'utf8',
    );
    // The tool guards `existsSync(scripts/scan/initial-scan.sh)` before
    // invoking the runner. Drop a stub so the mocked runShellScript is reached.
    mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
    writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n', 'utf8');

    const plugin = makePlugin(project, scriptsDir);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: 'Estado inicial:\n  Secrets: 0 findings',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('init_project');
    const r = (await tool.handler(
      { project_path: project, profile: 'standard' },
      plugin,
    )) as {
      ok: true;
      files_written: { target: string }[];
      files_skipped: { target: string }[];
      profile: string;
      initial_state: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.profile).toBe('standard');
    expect(r.files_written.map((f) => f.target).sort()).toEqual([
      '.gitleaks.toml',
      '.pre-commit-config.yaml',
      '.semgrep.yml',
      'renovate.json',
    ]);
    expect(existsSync(join(project, '.gitleaks.toml'))).toBe(true);
    expect(existsSync(join(project, 'renovate.json'))).toBe(true);
    expect(r.initial_state.length).toBeGreaterThan(0);

    // Idempotent: second call writes nothing, all skipped.
    const r2 = (await tool.handler({ project_path: project, profile: 'standard' }, plugin)) as {
      ok: true;
      files_written: unknown[];
      files_skipped: { reason_skipped: string }[];
    };
    expect(r2.files_written).toHaveLength(0);
    expect(r2.files_skipped.every((s) => s.reason_skipped === 'already_exists')).toBe(true);
  });

  it('respects apply=false (dry-run)', async () => {
    const project = tempProject();
    const scriptsDir = mkdtempSync(join(tmpdir(), 'init-scripts-'));
    const configsDir = join(scriptsDir, '..', 'configs');
    mkdirSync(join(configsDir, 'gitleaks'), { recursive: true });
    mkdirSync(join(configsDir, 'renovate'), { recursive: true });
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '# gl\n', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{}', 'utf8');

    const plugin = makePlugin(project, scriptsDir);

    const tool = getTool('init_project');
    const r = (await tool.handler(
      { project_path: project, profile: 'minimal', apply: false },
      plugin,
    )) as { ok: true; applied: boolean; files_written: unknown[] };
    expect(r.applied).toBe(false);
    expect(r.files_written).toHaveLength(0);
    expect(existsSync(join(project, '.gitleaks.toml'))).toBe(false);
  });
});

describe('observability_setup', () => {
  it('returns proposals for a Node project without writing when apply=false', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    const tool = getTool('observability_setup');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      stack_inferred: string;
      proposals: Array<{ target: string; language: string }>;
      files_written: string[];
    };
    expect(r.stack_inferred).toBe('node');
    expect(r.proposals.map((p) => p.target).sort()).toEqual(['src/logger.ts', 'src/metrics.ts']);
    expect(r.files_written).toEqual([]);
    expect(existsSync(join(project, 'src/logger.ts'))).toBe(false);
  });

  it('writes the proposals when apply=true (idempotent for existing files)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'pyproject.toml'), '[project]\nname="x"\n', 'utf8');
    const plugin = makePlugin(project);

    const tool = getTool('observability_setup');
    const r = (await tool.handler({ project_path: project, apply: true }, plugin)) as {
      ok: true;
      stack_inferred: string;
      files_written: string[];
    };
    expect(r.stack_inferred).toBe('python');
    expect(r.files_written).toContain('app/logging_config.py');
    expect(existsSync(join(project, 'app/logging_config.py'))).toBe(true);

    // Second run skips already-existing.
    const r2 = (await tool.handler({ project_path: project, apply: true }, plugin)) as {
      ok: true;
      files_written: string[];
      files_skipped: Array<{ reason_skipped: string }>;
    };
    expect(r2.files_written).toEqual([]);
    expect(r2.files_skipped.every((s) => s.reason_skipped === 'already_exists')).toBe(true);
  });

  it('falls back to a generic advisory when no stack is detected', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    const tool = getTool('observability_setup');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      stack_inferred: string;
      proposals: Array<{ target: string }>;
    };
    expect(r.stack_inferred).toBe('generic');
    expect(r.proposals[0]?.target).toBe('docs/observability.md');
  });
});

describe('perf_check', () => {
  it('rejects when neither target_url nor k6_script_path is provided', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    const tool = getTool('perf_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string; message: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('scanner_failed');
      expect(r.error.message).toMatch(/exactly one of/i);
    }
  });

  it('runs lighthouse and summarises Core Web Vitals from the JSON report', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'lighthouse' ? '/fake/bin/lighthouse' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outFlag = opts.args?.find((a) => a.startsWith('--output-path='));
      const outFile = outFlag?.replace('--output-path=', '');
      if (outFile) {
        writeFileSync(
          outFile,
          JSON.stringify({
            categories: {
              performance: { score: 0.92 },
              accessibility: { score: 0.85 },
              'best-practices': { score: 1.0 },
              seo: { score: 0.9 },
              pwa: { score: 0.5 },
            },
            audits: {
              'largest-contentful-paint': { numericValue: 1234.56 },
              'cumulative-layout-shift': { numericValue: 0.02 },
              'first-contentful-paint': { numericValue: 500 },
            },
          }),
          'utf8',
        );
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as {
      ok: true;
      tool: string;
      summary: {
        scores: Record<string, number | null>;
        core_web_vitals: Record<string, number | null>;
      };
    };
    expect(r.ok).toBe(true);
    expect(r.tool).toBe('lighthouse');
    expect(r.summary.scores.performance).toBe(92);
    expect(r.summary.core_web_vitals['largest-contentful-paint']).toBeCloseTo(1234.56, 1);
  });

  it('returns missing_scanner when lighthouse is not installed', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    expect(r.error.code).toBe('missing_scanner');
  });
});

// silence unused-import warnings
void readFileSync;
