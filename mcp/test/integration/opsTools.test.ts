/**
 * Integration tests for detect_stack, init_project, observability_setup,
 * perf_check.
 *
 * detect_stack is pure in-process filesystem detection now (no shell) — real
 * temp directories, no mocking. init_project still shells out to
 * initial-scan.sh → mock runShellScript.
 * perf_check spawns scanner CLI → mock runProcess + scannerAvailable.
 * observability_setup is pure file-system logic — no execa to mock.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

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
// init_project's secrets-status fix (see the 'reports uncommitted secrets'
// test) drives runGitleaksScan, which reads repository state through
// git.js. Mocked here rather than run against a real repo: `repoState` and
// `uncommittedFiles` are swapped for controllable fakes, everything else
// (log_opts helpers, etc.) passes through unchanged.
vi.mock('../../src/runners/git.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/runners/git.js')>('../../src/runners/git.js');
  return { ...actual, repoState: vi.fn(), uncommittedFiles: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { repoState, uncommittedFiles } from '../../src/runners/git.js';

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
  return makeTempDir('ops-tools-');
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
  vi.mocked(repoState).mockReset();
  vi.mocked(uncommittedFiles).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(repoState).mockReset();
  vi.mocked(uncommittedFiles).mockReset();
});

describe('detect_stack', () => {
  // detect_stack runs entirely in-process (`runners/stackDetect.ts`) — no
  // bash, no runShellScript. Real filesystem, no mocking; see
  // `test/unit/runners/stackDetect.test.ts` for the detection logic itself.
  it('detects the project stack in-process and persists a snapshot', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    writeFileSync(
      join(project, 'package.json'),
      JSON.stringify({ name: 'x', dependencies: { react: '^18.0.0', next: '^14.0.0' } }),
      'utf8',
    );
    mkdirSync(join(project, '.github', 'workflows'), { recursive: true });

    const tool = getTool('detect_stack');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      snapshot: { languages: string[]; frameworks: string[]; has_github_actions: boolean };
      snapshot_id: number;
    };
    expect(r.ok).toBe(true);
    expect(r.snapshot.languages).toEqual(['javascript']);
    expect(r.snapshot.frameworks.sort()).toEqual(['nextjs', 'react']);
    expect(r.snapshot.has_github_actions).toBe(true);
    // Persisted?
    expect(plugin.storage.stack.getLatest()?.snapshot.languages).toEqual(['javascript']);
  });

  it('reports not_a_git_repo when project_path does not resolve (invalid path)', async () => {
    const plugin = makePlugin(tempProject());
    const missing = join(tempProject(), 'does-not-exist');
    const tool = getTool('detect_stack');
    const r = (await tool.handler({ project_path: missing }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('not_a_git_repo');
  });
});

describe('init_project', () => {
  it('copies profile configs into the project (idempotent)', async () => {
    const project = tempProject();
    // Build a fake "configs/" alongside scripts/ so initProject can resolve them.
    const scriptsDir = makeTempDir('init-scripts-');
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
    const scriptsDir = makeTempDir('init-scripts-');
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

  // --- task 15: paranoid is genuinely stricter, not a standard alias ------

  function makeFullConfigsDir(scriptsDir: string): string {
    const configsDir = join(scriptsDir, '..', 'configs');
    for (const sub of ['gitleaks', 'renovate', 'semgrep', 'pre-commit']) {
      mkdirSync(join(configsDir, sub), { recursive: true });
    }
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '# gl standard\n', 'utf8');
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks-paranoid.toml'), '# gl paranoid\n', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{"standard":true}', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate-paranoid.json'), '{"paranoid":true}', 'utf8');
    writeFileSync(join(configsDir, 'semgrep', 'base.yml'), 'rules: []\n', 'utf8');
    writeFileSync(join(configsDir, 'pre-commit', 'pre-commit-config.yaml'), 'repos: []\n', 'utf8');
    return configsDir;
  }

  it('paranoid installs the paranoid gitleaks/renovate variants, not the standard ones', async () => {
    const project = tempProject();
    const scriptsDir = makeTempDir('init-scripts-');
    makeFullConfigsDir(scriptsDir);
    mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
    writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n', 'utf8');

    const plugin = makePlugin(project, scriptsDir);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false,
    });

    const tool = getTool('init_project');
    const r = (await tool.handler({ project_path: project, profile: 'paranoid' }, plugin)) as {
      ok: true;
      files_written: { target: string; source: string }[];
    };
    expect(r.ok).toBe(true);
    const bySource = Object.fromEntries(r.files_written.map((f) => [f.target, f.source]));
    expect(bySource['.gitleaks.toml']).toBe('gitleaks/gitleaks-paranoid.toml');
    expect(bySource['renovate.json']).toBe('renovate/renovate-paranoid.json');
    expect(readFileSync(join(project, '.gitleaks.toml'), 'utf8')).toContain('paranoid');
    expect(readFileSync(join(project, 'renovate.json'), 'utf8')).toContain('paranoid');
  });

  it('standard installs the standard gitleaks/renovate files (not the paranoid ones)', async () => {
    const project = tempProject();
    const scriptsDir = makeTempDir('init-scripts-');
    makeFullConfigsDir(scriptsDir);
    mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
    writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n', 'utf8');

    const plugin = makePlugin(project, scriptsDir);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false,
    });

    const tool = getTool('init_project');
    const r = (await tool.handler({ project_path: project, profile: 'standard' }, plugin)) as {
      ok: true;
      files_written: { target: string; source: string }[];
    };
    const bySource = Object.fromEntries(r.files_written.map((f) => [f.target, f.source]));
    expect(bySource['.gitleaks.toml']).toBe('gitleaks/gitleaks.toml');
    expect(bySource['renovate.json']).toBe('renovate/renovate.json');
  });

  // --- task 15: the first-pass status uses the TS secret scan helper ------
  // (history + working tree), not just initial-scan.sh's own gitleaks call,
  // which only reads commits — so an uncommitted .env used to show clean.

  it("computes the secrets line from gitleaks directly, catching what the shell script's own history-only pass would miss", async () => {
    const project = tempProject();
    const scriptsDir = makeTempDir('init-scripts-');
    const configsDir = join(scriptsDir, '..', 'configs');
    mkdirSync(join(configsDir, 'gitleaks'), { recursive: true });
    mkdirSync(join(configsDir, 'renovate'), { recursive: true });
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '# gl\n', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{}', 'utf8');
    mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
    writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n', 'utf8');
    // `uncommittedFiles` is mocked below to CLAIM `.env` is uncommitted, but
    // the copy step that follows (gitleaksScan.ts's filesPass) reads the
    // real file from disk before handing it to gitleaks, so it has to
    // actually be there.
    writeFileSync(join(project, '.env'), 'API_KEY=sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX\n', 'utf8');

    const plugin = makePlugin(project, scriptsDir);
    // The shell script's own (history-only) pass says clean — exactly the
    // bug: an uncommitted .env is invisible to `gitleaks detect` alone.
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: 'Estado inicial do projeto:\n\n  Secrets: 0 findings\n',
      stderr: '',
      truncated: false,
    });
    vi.mocked(scannerAvailable).mockResolvedValue('/usr/bin/gitleaks');
    vi.mocked(repoState).mockResolvedValue({ kind: 'has_commits', toplevel: project });
    vi.mocked(uncommittedFiles).mockResolvedValue(['.env']);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const args = opts.args ?? [];
      const reportArg = args.find((a) => a.startsWith('--report-path='));
      const reportPath = reportArg?.slice('--report-path='.length);
      const isWorkingTree = args.includes('--no-git');
      if (reportPath) {
        const findings = isWorkingTree
          ? [{ RuleID: 'generic-api-key-strict', Description: 'x', StartLine: 1, EndLine: 1, File: '.env' }]
          : [];
        writeFileSync(reportPath, JSON.stringify(findings), 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: isWorkingTree ? 1 : 0,
        stdout: '',
        stderr: isWorkingTree ? '' : '1 commits scanned.\n',
        truncated: false,
      };
    });

    const tool = getTool('init_project');
    const r = (await tool.handler({ project_path: project, profile: 'minimal' }, plugin)) as {
      ok: true;
      initial_state: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.initial_state.some((l) => /Secrets: 1 findings/.test(l))).toBe(true);
    expect(r.initial_state.some((l) => /Secrets: 0 findings/.test(l))).toBe(false);
  });

  it('leaves the shell summary untouched when gitleaks is not installed (nothing to correct it with)', async () => {
    const project = tempProject();
    const scriptsDir = makeTempDir('init-scripts-');
    const configsDir = join(scriptsDir, '..', 'configs');
    mkdirSync(join(configsDir, 'gitleaks'), { recursive: true });
    mkdirSync(join(configsDir, 'renovate'), { recursive: true });
    writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '# gl\n', 'utf8');
    writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{}', 'utf8');
    mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
    writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n', 'utf8');

    const plugin = makePlugin(project, scriptsDir);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: 'Estado inicial do projeto:\n\n  Vulnerabilidades: 0\n',
      stderr: '',
      truncated: false,
    });
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('init_project');
    const r = (await tool.handler({ project_path: project, profile: 'minimal' }, plugin)) as {
      ok: true;
      initial_state: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.initial_state).toEqual(['Estado inicial do projeto:', '  Vulnerabilidades: 0']);
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

  // --- task 15: perf_check reads .guardian/budgets.yml ---------------------

  function mockLighthouseRun(audits: Record<string, { numericValue: number }>): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'lighthouse' ? '/fake/bin/lighthouse' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outFlag = opts.args?.find((a) => a.startsWith('--output-path='));
      const outFile = outFlag?.replace('--output-path=', '');
      if (outFile) {
        writeFileSync(outFile, JSON.stringify({ categories: {}, audits }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
  }

  it('reports a finding when a Core Web Vital exceeds .guardian/budgets.yml', async () => {
    const project = tempProject();
    mkdirSync(join(project, '.guardian'), { recursive: true });
    writeFileSync(join(project, '.guardian', 'budgets.yml'), 'perf:\n  lcp_ms: 2500\n', 'utf8');
    const plugin = makePlugin(project);
    mockLighthouseRun({ 'largest-contentful-paint': { numericValue: 4000 } });

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as { ok: true; findings: { rule_id: string; category: string }[] };
    expect(r.ok).toBe(true);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ rule_id: 'perf.lcp_ms', category: 'performance' });
  });

  it('reports no findings when every measured vital is within budget', async () => {
    const project = tempProject();
    mkdirSync(join(project, '.guardian'), { recursive: true });
    writeFileSync(join(project, '.guardian', 'budgets.yml'), 'perf:\n  lcp_ms: 2500\n', 'utf8');
    const plugin = makePlugin(project);
    mockLighthouseRun({ 'largest-contentful-paint': { numericValue: 1200 } });

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as { ok: true; findings: unknown[] };
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it('reports no findings (and does not fail) when there is no budgets file at all', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    mockLighthouseRun({ 'largest-contentful-paint': { numericValue: 999999 } });

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as { ok: true; findings: unknown[] };
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it('derives bundle_size_kb from the total-byte-weight audit', async () => {
    const project = tempProject();
    mkdirSync(join(project, '.guardian'), { recursive: true });
    writeFileSync(join(project, '.guardian', 'budgets.yml'), 'perf:\n  bundle_size_kb: 500\n', 'utf8');
    const plugin = makePlugin(project);
    // 600 KB, over the 500 KB budget.
    mockLighthouseRun({ 'total-byte-weight': { numericValue: 600 * 1024 } });

    const tool = getTool('perf_check');
    const r = (await tool.handler(
      { project_path: project, target_url: 'https://example.com' },
      plugin,
    )) as { ok: true; findings: { rule_id: string }[] };
    expect(r.ok).toBe(true);
    expect(r.findings.some((f) => f.rule_id === 'perf.bundle_size_kb')).toBe(true);
  });
});

// silence unused-import warnings
void readFileSync;
