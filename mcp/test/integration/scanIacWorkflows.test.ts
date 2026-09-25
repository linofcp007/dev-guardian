/**
 * `scan_iac` (Task 21): zizmor and actionlint run against
 * `.github/workflows/*.yml` when it exists, independently of Trivy and of
 * each other — a missing one is a named gap (`missing_tools`, coverage
 * `partial`), never silence. Neither runs at all when there is no workflow
 * directory (coverage stays `full`: nothing to scan, not a gap).
 */
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
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
  await import('../../src/tools/scanIac.js');
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'scan_iac');
  if (!t) throw new Error('scan_iac not registered');
  return t;
}

function plugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

const ok = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };

function writeWorkflow(project: string): void {
  mkdirSync(join(project, '.github', 'workflows'), { recursive: true });
  writeFileSync(
    join(project, '.github', 'workflows', 'ci.yml'),
    'on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n',
    'utf8',
  );
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue(null); // trivy absent by default — irrelevant to these checks
  vi.mocked(runProcess).mockResolvedValue(ok);
});

type Result = Record<string, unknown> & { ok: boolean };
type ToolsRunResult = Result & {
  tools_run: { name: string; status: string; reason?: string }[];
  missing_tools: string[];
  coverage: string;
};

const ZIZMOR_FINDING = {
  ident: 'unpinned-uses',
  desc: 'unpinned action reference',
  url: 'https://docs.zizmor.sh/audits/#unpinned-uses',
  determinations: { confidence: 'High', severity: 'High', persona: 'Regular' },
  locations: [
    {
      symbolic: {
        key: { Local: { verbatim_path: './.github/workflows/ci.yml' } },
        annotation: 'this step',
        route: { route: [] },
        feature_kind: 'Normal',
        kind: 'Primary',
      },
      concrete: {
        location: { start_point: { row: 4, column: 8 }, end_point: { row: 4, column: 30 }, offset_span: { start: 0, end: 0 } },
        feature: 'uses: actions/checkout@v3',
        comments: [],
      },
    },
  ],
  ignored: false,
  fixes: [],
};

const ACTIONLINT_FINDING = {
  message: 'unexpected key "branch"',
  filepath: '.github/workflows/ci.yml',
  line: 2,
  column: 1,
  kind: 'syntax-check',
  snippet: 'branch: main',
  end_column: 11,
};

describe('scan_iac: workflow scanners gated on .github/workflows', () => {
  it('records an explicit skipped/no_workflows entry for both (never silently absent) and reports coverage=full, when there is no workflow directory', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy'); // trivy present and ok — isolates this case from trivy's own gap
    const project = makeTempDir('iac-');
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'zizmor')).toMatchObject({ status: 'skipped', reason: 'no_workflows' });
    expect(r.tools_run.find((t) => t.name === 'actionlint')).toMatchObject({ status: 'skipped', reason: 'no_workflows' });
    expect(r.missing_tools).not.toContain('zizmor');
    expect(r.missing_tools).not.toContain('actionlint');
    expect(r.coverage).toBe('full');
  });

  it('runs zizmor and actionlint, and parses their findings, when a workflow file exists and both are installed', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'zizmor' || name === 'actionlint' || name === 'trivy' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'zizmor') {
        return { outcome: 'completed', exitCode: 0, stdout: JSON.stringify([ZIZMOR_FINDING]), stderr: '', truncated: false };
      }
      if (opts.command === 'actionlint') {
        return { outcome: 'completed', exitCode: 1, stdout: JSON.stringify([ACTIONLINT_FINDING]), stderr: '', truncated: false };
      }
      return ok;
    });
    const project = makeTempDir('iac-');
    writeWorkflow(project);

    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult & {
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'zizmor')?.status).toBe('ok');
    expect(r.tools_run.find((t) => t.name === 'actionlint')?.status).toBe('ok');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(2);
    expect(r.coverage).toBe('full');
  });

  it('zizmor is invoked with --format=json --no-exit-codes --collect=workflows and one positional arg per workflow file (never the directory)', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'zizmor' ? '/fake/bin/zizmor' : null));
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    writeFileSync(join(project, '.github', 'workflows', 'release.yaml'), 'on: push\njobs: {}\n', 'utf8');
    await tool().handler({ project_path: project }, plugin(project));
    const call = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'zizmor');
    expect(call?.[0].args).toEqual([
      '--format=json',
      '--no-exit-codes',
      '--collect=workflows',
      '.github/workflows/ci.yml',
      '.github/workflows/release.yaml',
    ]);
    expect(call?.[0].args).not.toContain('.github/workflows');
  });

  it('actionlint is invoked with -pyflakes= -shellcheck= and one positional arg per workflow file', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'actionlint' ? '/fake/bin/actionlint' : null));
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    writeFileSync(join(project, '.github', 'workflows', 'release.yaml'), 'on: push\njobs: {}\n', 'utf8');
    await tool().handler({ project_path: project }, plugin(project));
    const call = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'actionlint');
    expect(call?.[0].args).toEqual(
      expect.arrayContaining(['-pyflakes=', '-shellcheck=', '.github/workflows/ci.yml', '.github/workflows/release.yaml']),
    );
  });

  it('zizmor missing is a named gap: skipped/not_installed, missing_tools, coverage partial', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'actionlint' ? '/fake/bin/actionlint' : null));
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'zizmor')).toMatchObject({ status: 'skipped', reason: 'not_installed' });
    expect(r.missing_tools).toContain('zizmor');
    expect(r.coverage).toBe('partial');
  });

  it('actionlint missing is a named gap: skipped/not_installed, missing_tools, coverage partial', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'zizmor' ? '/fake/bin/zizmor' : null));
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'actionlint')).toMatchObject({ status: 'skipped', reason: 'not_installed' });
    expect(r.missing_tools).toContain('actionlint');
    expect(r.coverage).toBe('partial');
  });

  it('a zizmor run that errors (exit 1, no --no-exit-codes override reachable) is reported failed, never as 0 findings', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'zizmor' ? '/fake/bin/zizmor' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'zizmor') {
        return { outcome: 'completed', exitCode: 1, stdout: '', stderr: 'audit error', truncated: false };
      }
      return ok;
    });
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.tools_run.find((t) => t.name === 'zizmor')?.status).toBe('failed');
    expect(r.coverage).not.toBe('full');
  });

  it('report_paths is truthful: zizmor/actionlint raw stdout is written under the report dir, not just trivy\'s own file', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'zizmor' || name === 'actionlint' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'zizmor') {
        return { outcome: 'completed', exitCode: 0, stdout: JSON.stringify([ZIZMOR_FINDING]), stderr: '', truncated: false };
      }
      if (opts.command === 'actionlint') {
        return { outcome: 'completed', exitCode: 0, stdout: JSON.stringify([ACTIONLINT_FINDING]), stderr: '', truncated: false };
      }
      return ok;
    });
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult & {
      report_paths: string[];
    };
    expect(r.ok).toBe(true);
    const reportDir = r.report_paths[0];
    expect(reportDir).toBeDefined();
    expect(existsSync(join(reportDir as string, 'zizmor.json'))).toBe(true);
    expect(existsSync(join(reportDir as string, 'actionlint.json'))).toBe(true);
    expect(JSON.parse(readFileSync(join(reportDir as string, 'zizmor.json'), 'utf8'))).toEqual([ZIZMOR_FINDING]);
  });

  it('a single scanner exceeding the stdout cap (output_too_large) does not discard the others\' already-good findings', async () => {
    // Regression: scanToolFactory.ts discards the WHOLE ScanResult when the
    // scan's own top-level outcome is 'output_too_large' or 'cancelled'.
    // zizmor/actionlint have no --output file (captured stdout only), so a
    // single one of them overflowing the 5 MB cap must not corrupt the
    // scan's own outcome and erase trivy's / the other scanner's findings.
    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'trivy' || name === 'zizmor' || name === 'actionlint' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'zizmor') {
        // Simulates processRunner's own output_too_large outcome: the
        // process was killed, but whatever was captured before the cap is
        // still returned in `stdout`.
        return { outcome: 'output_too_large', exitCode: null, stdout: '[{"partial":true}', stderr: '', truncated: true };
      }
      if (opts.command === 'actionlint') {
        return { outcome: 'completed', exitCode: 0, stdout: JSON.stringify([ACTIONLINT_FINDING]), stderr: '', truncated: false };
      }
      return ok;
    });
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult & {
      report_paths: string[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true); // not discarded via failDomain('output_too_large', ...) / failDomain('cancelled', ...)
    expect(r.tools_run.find((t) => t.name === 'zizmor')).toMatchObject({ status: 'failed', reason: 'output_too_large' });
    expect(r.tools_run.find((t) => t.name === 'actionlint')?.status).toBe('ok');
    // actionlint's finding still made it into the response.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);
    // Whatever zizmor captured before the cap is still on disk for inspection.
    const reportDir = r.report_paths[0];
    expect(existsSync(join(reportDir as string, 'zizmor.json'))).toBe(true);
  });

  it('a real host cancellation (signal already aborted) still reports the scan cancelled', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'zizmor' ? '/fake/bin/zizmor' : null));
    const controller = new AbortController();
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'zizmor') {
        controller.abort(); // the host cancelled the whole call while zizmor was running
        return { outcome: 'cancelled', exitCode: null, stdout: '', stderr: '', truncated: false };
      }
      return ok;
    });
    const project = makeTempDir('iac-');
    writeWorkflow(project);
    const t = tool();
    const r = (await t.handler(
      { project_path: project },
      plugin(project),
      { signal: controller.signal },
    )) as Result;
    expect(r.ok).toBe(false);
    expect((r as { error?: { code?: string } }).error?.code).toBe('cancelled');
  });

  it('a symlinked workflow file (pointing inside the project) is included, not silently dropped', async (t) => {
    const project = makeTempDir('iac-');
    mkdirSync(join(project, '.github', 'workflows'), { recursive: true });
    const real = join(project, 'shared-ci.yml');
    writeFileSync(real, 'on: push\njobs: {}\n', 'utf8');
    try {
      symlinkSync(real, join(project, '.github', 'workflows', 'linked.yml'));
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'actionlint' ? '/fake/bin/actionlint' : null));
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.ok).toBe(true);
    // Reached the "there are workflows" branch, not skipped/no_workflows.
    expect(r.tools_run.find((t2) => t2.name === 'actionlint')?.status).toBe('ok');
    const call = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'actionlint');
    expect(call?.[0].args).toContain('.github/workflows/linked.yml');
  });

  it('a symlinked workflow file pointing OUTSIDE the project is excluded', async (t) => {
    const project = makeTempDir('iac-');
    const outside = makeTempDir('iac-outside-');
    mkdirSync(join(project, '.github', 'workflows'), { recursive: true });
    writeFileSync(join(outside, 'external.yml'), 'on: push\njobs: {}\n', 'utf8');
    try {
      symlinkSync(join(outside, 'external.yml'), join(project, '.github', 'workflows', 'linked.yml'));
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'actionlint' ? '/fake/bin/actionlint' : null));
    const r = (await tool().handler({ project_path: project }, plugin(project))) as ToolsRunResult;
    expect(r.ok).toBe(true);
    // Nothing project-local to scan — the link resolves outside the project.
    expect(r.tools_run.find((t2) => t2.name === 'actionlint')).toMatchObject({ status: 'skipped', reason: 'no_workflows' });
  });
});
