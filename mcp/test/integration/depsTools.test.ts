/**
 * Integration tests for deps_audit and deps_update_plan.
 *
 * deps_audit goes through the scan-tool factory → we mock `runProcess` and
 * `scannerAvailable`. deps_update_plan is a custom handler that calls
 * `execa` directly → we mock the `execa` module.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('execa', () => ({
  execa: vi.fn(),
}));

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { execa } from 'execa';

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
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'deps-tools-'));
}

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

const trivyFsFx = () => readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
const npmAuditFx = () => readFileSync(join(FIX, 'npm-audit.json'), 'utf8');

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(execa).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(execa).mockReset();
});

describe('deps_audit', () => {
  it('detects renovate.json and surfaces bot_configured.renovate=true', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'renovate.json'), '{}', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      bot_configured: { renovate: boolean; dependabot: boolean };
      findings_count_by_severity: Record<string, number>;
    };

    expect(r.ok).toBe(true);
    expect(r.bot_configured.renovate).toBe(true);
    expect(r.bot_configured.dependabot).toBe(false);
    // Trivy fs fixture: 2 vulns + 1 license = 3 findings
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
  });

  it('parses npm audit output into Findings alongside Trivy (the npm-audit gap)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool'); // trivy + npm both present
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'npm') {
        // npm audit prints JSON to stdout and exits 1 when vulns are present.
        return {
          outcome: 'completed' as const,
          exitCode: 1,
          stdout: npmAuditFx(),
          stderr: '',
          truncated: false,
        };
      }
      // trivy fs
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    // 3 from Trivy fixture + 2 from npm-audit fixture (lodash high, minimist critical).
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(5);
    const npm = r.tools_run.find((t) => t.name === 'npm');
    expect(npm?.status).toBe('ok');
    expect(npm?.reason).toMatch(/parsed/i);
    expect(r.coverage).toBe('full');
  });

  it('dedupes an npm-audit finding for a package Trivy already reported (no double count)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    // npm audit reports tough-cookie (which Trivy ALSO reports) + lodash (unique to npm).
    const npmOverlap = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        'tough-cookie': {
          name: 'tough-cookie',
          severity: 'medium',
          via: [
            {
              source: 9999,
              name: 'tough-cookie',
              title: 'Prototype Pollution in tough-cookie',
              url: 'https://github.com/advisories/GHSA-tough',
              severity: 'medium',
              range: '<4.1.3',
            },
          ],
          range: '<4.1.3',
          fixAvailable: true,
        },
        lodash: {
          name: 'lodash',
          severity: 'high',
          via: [
            {
              source: 1065,
              name: 'lodash',
              title: 'Prototype Pollution in lodash',
              url: 'https://github.com/advisories/GHSA-jf85',
              severity: 'high',
              range: '<4.17.12',
            },
          ],
          range: '<4.17.12',
          fixAvailable: true,
        },
      },
      metadata: { vulnerabilities: { total: 2 } },
    });

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool'); // trivy + npm present
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'npm') {
        return { outcome: 'completed' as const, exitCode: 1, stdout: npmOverlap, stderr: '', truncated: false };
      }
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      // Trivy fixture reports tough-cookie + semver (vulns) + evil-lib (license).
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    // 3 Trivy findings + only the npm 'lodash' finding; the npm 'tough-cookie'
    // duplicate of Trivy's CVE is dropped. (5 - 1 overlap = 4.)
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(4);
    const npmFindings = plugin.storage.findings
      .listByScan((r as unknown as { scan_id: string }).scan_id)
      .filter((f) => f.tool === 'npm-audit');
    expect(npmFindings.map((f) => f.snippet)).toEqual([expect.stringContaining('lodash')]);
  });

  it('marks a missing native auditor (npm) as a coverage gap, not silent full coverage', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    // Trivy present and succeeds; npm absent from PATH.
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'npm' ? null : '/fake/bin/trivy',
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      warnings: string[];
    };
    expect(r.ok).toBe(true);
    // The npm advisory coverage the tool claims to add never ran — that is a gap.
    expect(r.missing_tools).toContain('npm');
    expect(r.coverage).toBe('partial');
    expect(r.warnings.some((w) => /npm/i.test(w))).toBe(true);
  });

  it('does not count an npm audit error (no lockfile) as a successful, clean scan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool'); // trivy + npm present
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'npm') {
        // npm audit with no lockfile prints an error object and exits non-zero.
        return {
          outcome: 'failed' as const,
          exitCode: 1,
          stdout: JSON.stringify({
            error: { code: 'ENOLOCK', summary: 'This command requires an existing lockfile.', detail: '' },
          }),
          stderr: '',
          truncated: false,
        };
      }
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.ok).toBe(true);
    const npm = r.tools_run.find((t) => t.name === 'npm');
    expect(npm?.status).toBe('failed');
    expect(r.missing_tools).toContain('npm');
    // Only Trivy's 3 findings — the npm error JSON must not be parsed into findings.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
    expect(r.coverage).toBe('partial');
  });

  it('detects .github/dependabot.yml when present', async () => {
    const project = tempProject();
    mkdirSync(join(project, '.github'));
    writeFileSync(join(project, '.github', 'dependabot.yml'), 'version: 2', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      bot_configured: { renovate: boolean; dependabot: boolean };
      missing_tools: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.bot_configured.dependabot).toBe(true);
    expect(r.missing_tools).toContain('trivy');
  });
});

describe('deps_update_plan', () => {
  it('classifies an npm outdated entry as patch when only the patch digit moves', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '4.17.20', latest: '4.17.21' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const tool = getTool('deps_update_plan');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      plan: Array<{ package_name: string; classification: string; upgrade_command: string }>;
      summary: { has_security_updates: boolean };
    };
    expect(r.ok).toBe(true);
    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.classification).toBe('patch');
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.21');
    expect(r.summary.has_security_updates).toBe(false);
  });

  it('classifies as security when the package has an active CVE', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    // Seed an active CVE on lodash.
    plugin.storage.scans.insert({
      scan_id: 'seed',
      scan_type: 'deps',
      project_path: project,
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'seed',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-2024-XXX',
      package_name: 'lodash',
      installed_version: '4.17.20',
      severity: 'high',
      scan_id: 'seed',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '4.17.20', latest: '4.17.21' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const tool = getTool('deps_update_plan');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      plan: Array<{ classification: string; reason?: string }>;
      summary: { has_security_updates: boolean };
    };
    expect(r.ok).toBe(true);
    expect(r.plan[0]?.classification).toBe('security');
    expect(r.plan[0]?.reason).toContain('CVE');
    expect(r.summary.has_security_updates).toBe(true);
  });

  it('orders security entries first when prefer=security (default)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    // Seed active CVE on "vulnerable-pkg".
    plugin.storage.scans.insert({
      scan_id: 'seed',
      scan_type: 'deps',
      project_path: project,
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'seed',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-Y',
      package_name: 'vulnerable-pkg',
      installed_version: '1.0.0',
      severity: 'high',
      scan_id: 'seed',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            'minor-update': { current: '1.0.0', latest: '1.5.0' },
            'vulnerable-pkg': { current: '1.0.0', latest: '1.0.1' },
            'major-update': { current: '1.0.0', latest: '3.0.0' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const tool = getTool('deps_update_plan');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      plan: Array<{ package_name: string; classification: string }>;
    };
    expect(r.ok).toBe(true);
    expect(r.plan[0]?.classification).toBe('security');
    expect(r.plan[0]?.package_name).toBe('vulnerable-pkg');
  });

  it('returns an empty plan when no package manifest is present', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    const tool = getTool('deps_update_plan');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      plan: unknown[];
      summary: { total: number };
    };
    expect(r.ok).toBe(true);
    expect(r.plan).toEqual([]);
    expect(r.summary.total).toBe(0);
  });

  it('reports unsupported ecosystems (maven / gradle) when they exist', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'pom.xml'), '', 'utf8');
    writeFileSync(join(project, 'build.gradle'), '', 'utf8');
    const plugin = makePlugin(project);

    const tool = getTool('deps_update_plan');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      unsupported_ecosystems_present: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.unsupported_ecosystems_present).toEqual(
      expect.arrayContaining(['maven', 'gradle']),
    );
  });
});
