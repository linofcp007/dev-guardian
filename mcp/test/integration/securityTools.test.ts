/**
 * Integration tests for the 6 security tools.
 *
 * Strategy:
 *   - mock `runProcess` and `runShellScript` to drop canned scanner reports
 *     into the expected output paths and return `outcome=completed`;
 *   - mock `scannerAvailable` so it answers "yes" for every probed scanner;
 *   - import each tool module, invoke its handler through the registry, and
 *     assert the ScanResult shape, finding counts, and missing_tools logic.
 *
 * The factory's edge-case behaviour (cache, cancel, error finalisation) is
 * covered in `test/unit/tools/scanToolFactory.test.ts`. These tests focus
 * on wiring: does the tool call the right command, route reports to the
 * right parser, and surface tools_run / missing_tools correctly?
 */

import Database from 'better-sqlite3';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
  return {
    ...actual,
    scannerAvailable: vi.fn(),
  };
});

// Re-import the mocked symbols + the source-of-truth `scanHelpers` so we can
// drive the mocks from each test.
import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

// Side-effect imports populate the TOOLS registry — once per file.
beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/scanIac.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
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
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'sec-tools-'));
}

const semgrepFixture = () => readFileSync(join(FIX, 'semgrep.json'), 'utf8');
const trivyFsFixture = () => readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
const trivyDockerFixture = () =>
  readFileSync(join(FIX, 'trivy-dockerfile.json'), 'utf8');
const gitleaksFixture = () => readFileSync(join(FIX, 'gitleaks.json'), 'utf8');
const banditFixture = () => readFileSync(join(FIX, 'bandit.json'), 'utf8');

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

interface SuccessOpts {
  ok?: boolean;
  exitCode?: number;
}

function fakeRunSuccess(opts: SuccessOpts = {}) {
  return {
    outcome: 'completed' as const,
    exitCode: opts.exitCode ?? 0,
    stdout: '',
    stderr: '',
    truncated: false,
  };
}

describe('scan_sast (Semgrep)', () => {
  it('drops semgrep.json into the report dir and persists findings', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const out = opts.args?.find((a, i) => opts.args?.[i - 1] === '--output');
      if (out) writeFileSync(out, semgrepFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string }[];
    };

    expect(r.ok).toBe(true);
    // Semgrep fixture has 3 results → 3 findings.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
    expect(r.tools_run.some((t) => t.name === 'semgrep' && t.status === 'ok')).toBe(true);
  });

  it('marks semgrep as missing when scannerAvailable returns null', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string }[];
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('skipped');
  });
});

describe('scan_secrets (gitleaks)', () => {
  it('runs with --redact and persists secret findings', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
      if (reportArg) {
        const path = reportArg.replace('--report-path=', '');
        writeFileSync(path, gitleaksFixture(), 'utf8');
      }
      // Verify gitleaks is invoked with --redact.
      expect(opts.args).toContain('--redact');
      return fakeRunSuccess({ exitCode: 1 }); // gitleaks exits 1 when leaks found
    });

    const tool = getTool('scan_secrets');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.high).toBe(2); // 2 secret findings in fixture
  });
});

describe('scan_deps (Trivy fs)', () => {
  it('runs trivy fs with vuln+license scanners and indexes CVEs', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('fs');
      expect(opts.args).toContain('vuln,license');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_deps');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    // Fixture: 2 vulns + 1 risky license → 3 findings; 2 CVEs indexed.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
    const cves = plugin.storage.cves.listActive(r.scan_id);
    expect(cves).toHaveLength(2);
  });
});

describe('scan_containers (Trivy Dockerfile)', () => {
  it('scans the project Dockerfile when present', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Dockerfile'), 'FROM node:20\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('config');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyDockerFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_containers');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.high).toBe(1);
    expect(r.tools_run.some((t) => t.name === 'trivy-dockerfile')).toBe(true);
  });

  it('reports skipped when neither Dockerfile nor image is provided', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');

    const tool = getTool('scan_containers');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run[0]?.status).toBe('skipped');
    expect(r.tools_run[0]?.reason).toBe('no_dockerfile_or_image');
  });
});

describe('scan_iac (Trivy config)', () => {
  it('runs trivy config on the project root', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('config');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyDockerFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_iac');
    const r = (await tool.handler({ project_path: project }, plugin)) as { ok: true };
    expect(r.ok).toBe(true);
  });
});

describe('security_scan_full', () => {
  it('routes each scanner output file in the script report dir to its parser', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    // The script (when running for real) would create
    // .guardian/reports/security-<TS>/ with the JSON files. Our mock does
    // that and returns success.
    vi.mocked(runShellScript).mockImplementation(async () => {
      const reportsRoot = join(project, '.guardian', 'reports');
      const reportDir = join(reportsRoot, 'security-20260526-120000');
      mkdirSync(reportDir, { recursive: true });
      writeFileSync(join(reportDir, 'sast.json'), semgrepFixture(), 'utf8');
      writeFileSync(join(reportDir, 'secrets.json'), gitleaksFixture(), 'utf8');
      writeFileSync(join(reportDir, 'deps.json'), trivyFsFixture(), 'utf8');
      writeFileSync(join(reportDir, 'dockerfile.json'), trivyDockerFixture(), 'utf8');
      writeFileSync(join(reportDir, 'bandit.json'), banditFixture(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('security_scan_full');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string }[];
      report_paths: string[];
    };

    expect(r.ok).toBe(true);
    // 3 semgrep + 2 gitleaks + 3 trivy fs + 1 trivy dockerfile + 2 bandit = 11 findings
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(11);
    expect(r.tools_run.map((t) => t.name).sort()).toEqual([
      'bandit',
      'gitleaks',
      'semgrep',
      'trivy',
      'trivy-dockerfile',
    ]);
    expect(r.tools_run.every((t) => t.status === 'ok')).toBe(true);
    expect(r.report_paths[0]).toContain('security-');
  });

  it('surfaces missing tools when the report file is absent', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(runShellScript).mockImplementation(async () => {
      const reportsRoot = join(project, '.guardian', 'reports');
      const reportDir = join(reportsRoot, 'security-no-tools');
      mkdirSync(reportDir, { recursive: true });
      // Only Semgrep's output present.
      writeFileSync(join(reportDir, 'sast.json'), semgrepFixture(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('security_scan_full');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    expect(r.missing_tools).toContain('gitleaks');
    expect(r.missing_tools).toContain('trivy');
    expect(r.missing_tools).not.toContain('trivy-dockerfile'); // conditional
    expect(r.missing_tools).not.toContain('bandit'); // conditional
  });
});

// Suppress an unused-import warning when the helpers aren't used.
void cpSync;
void existsSync;
