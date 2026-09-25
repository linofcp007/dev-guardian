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
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

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
  return makeTempDir('deps-tools-');
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
const pipAuditFx = () => readFileSync(join(FIX, 'pip-audit.json'), 'utf8');
const dotnetListFx = () => readFileSync(join(FIX, 'dotnet-list-vulnerable.json'), 'utf8');

/** trivy fs run that produces NO Results at all — the bare-manifest shape
 *  reproduced against Trivy 0.69.3 (see trivy.ts's own module comment). */
const trivyNoResultsFx = () => JSON.stringify({ SchemaVersion: 2, ArtifactType: 'filesystem' });

function outputPathFor(args: string[] | undefined): string | undefined {
  const flagIdx = args?.findIndex((a) => a === '--output' || a === '-o') ?? -1;
  return flagIdx >= 0 ? args?.[flagIdx + 1] : undefined;
}

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

describe('scan_deps', () => {
  it('marks trivy skipped/no_supported_manifest for a bare .csproj instead of a clean 0-findings scan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('scan_deps');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      manifest_coverage_gaps: Array<{ ecosystem: string; files: string[] }>;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    const trivy = r.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.status).toBe('skipped');
    expect(trivy?.reason).toBe('no_supported_manifest');
    expect(r.missing_tools).toContain('trivy');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: 'dotnet', files: ['Test.csproj'] }]);
    expect(Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBe(0);
    expect(r.coverage).not.toBe('full');
  });

  it('item 4: a PARTIAL manifest gap (npm covered, dotnet not) never puts the bare "trivy" name in missing_tools', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');
    writeFileSync(join(project, 'Api.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) {
        writeFileSync(
          path,
          JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] }),
          'utf8',
        );
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('scan_deps');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    const trivy = r.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.status).toBe('ok');
    expect(r.missing_tools).not.toContain('trivy');
    expect(r.missing_tools).toContain('trivy:dotnet');
    expect(r.coverage).toBe('partial');
  });

  it('reports coverage=full for a project with no dependency manifest at all', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('scan_deps');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      tools_run: { name: string; status: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'trivy')?.status).toBe('ok');
    expect(r.coverage).toBe('full');
  });
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

  it('has its own scan_type, so scan_deps and deps_audit never answer for each other from the cache', async () => {
    // Reproduced: both wrote scan_type 'deps', so whichever ran second inside
    // the cache window got the other's scan — and deps_audit's answer then
    // had no bot_configured at all.
    const project = tempProject();
    writeFileSync(join(project, 'renovate.json'), '{}', 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const deps = okResult<{ scan_id: string; scan_type: string; cached?: boolean }>(
      await getTool('scan_deps').handler({ project_path: project }, plugin),
    );
    const audit = okResult<{
      scan_id: string;
      scan_type: string;
      cached?: boolean;
      bot_configured?: { renovate: boolean };
    }>(await getTool('deps_audit').handler({ project_path: project }, plugin));

    expect(deps.scan_type).toBe('deps');
    expect(audit.scan_type).toBe('deps_audit');
    expect(audit.cached).toBeUndefined();
    expect(audit.scan_id).not.toBe(deps.scan_id);
    expect(audit.bot_configured?.renovate).toBe(true);

    // Each is still a cache hit for ITSELF, and a deps_audit hit keeps its
    // bot_configured (it used to be dropped on every hit).
    const auditAgain = okResult<{ cached?: boolean; cached_from?: string; bot_configured?: { renovate: boolean } }>(
      await getTool('deps_audit').handler({ project_path: project }, plugin),
    );
    expect(auditAgain.cached).toBe(true);
    expect(auditAgain.cached_from).toBe(audit.scan_id);
    expect(auditAgain.bot_configured?.renovate).toBe(true);
    const depsAgain = okResult<{ cached?: boolean; cached_from?: string }>(
      await getTool('scan_deps').handler({ project_path: project }, plugin),
    );
    expect(depsAgain.cached_from).toBe(deps.scan_id);
  });

  it('scans again once Trivy is installed, instead of serving the not_installed run from the cache', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const path = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    vi.mocked(scannerAvailable).mockResolvedValue(null);
    const before = okResult<{ coverage: string; missing_tools: string[] }>(
      await getTool('scan_deps').handler({ project_path: project }, plugin),
    );
    expect(before.missing_tools).toContain('trivy');

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy'); // install_toolchain ran
    const after = okResult<{ cached?: boolean; coverage: string; findings_count_by_severity: Record<string, number> }>(
      await getTool('scan_deps').handler({ project_path: project }, plugin),
    );
    expect(after.cached).toBeUndefined();
    expect(after.coverage).toBe('full');
    expect(Object.values(after.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBe(3);
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

  it('marks trivy skipped/no_supported_manifest for a bare .csproj instead of a clean 0-findings scan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      manifest_coverage_gaps: Array<{ ecosystem: string; files: string[] }>;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    const trivy = r.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.status).toBe('skipped');
    expect(trivy?.reason).toBe('no_supported_manifest');
    expect(r.missing_tools).toContain('trivy');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: 'dotnet', files: ['Test.csproj'] }]);
    expect(Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBe(0);
    // Coverage must never read 'full' — nothing was actually scanned.
    expect(r.coverage).not.toBe('full');
  });

  it('item 4: a PARTIAL manifest gap (npm covered, dotnet not) never puts the bare "trivy" name in missing_tools', async () => {
    // Reproduced: create_fix_pr's own verification reads
    // missing_tools.includes('trivy') as "trivy did not run at all — cannot
    // verify ANYTHING it found", which would block an unrelated npm CVE fix
    // PR just because one ecosystem in the same repo (NuGet) went
    // uncovered. The gap must be named distinctly (`trivy:<ecosystem>`).
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');
    writeFileSync(join(project, 'Api.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) {
        writeFileSync(
          path,
          JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] }),
          'utf8',
        );
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    const trivy = r.tools_run.find((t) => t.name === 'trivy');
    // Trivy DID run and DID cover npm — its own status stays 'ok'.
    expect(trivy?.status).toBe('ok');
    // The bare 'trivy' string is never in missing_tools for a partial gap —
    // an exact-match consumer (create_fix_pr) must not treat this as
    // "trivy did not run".
    expect(r.missing_tools).not.toContain('trivy');
    expect(r.missing_tools).toContain('trivy:dotnet');
    // Coverage still correctly reads partial, never full.
    expect(r.coverage).toBe('partial');
  });

  it('never invokes pip-audit bare — always -r per requirements file', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'requirements.txt'), 'django==2.0.1\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
    );
    let capturedArgs: string[] | undefined;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'pip-audit') {
        capturedArgs = opts.args;
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, pipAuditFx(), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    expect(capturedArgs).toContain('-r');
    const reqIdx = capturedArgs?.indexOf('-r') ?? -1;
    expect(capturedArgs?.[reqIdx + 1]).toBe(join(project, 'requirements.txt'));
    // Never a bare call: some target argument must always precede --format.
    expect(capturedArgs?.length).toBeGreaterThan(2);

    const pipAudit = r.tools_run.find((t) => t.name === 'pip-audit');
    expect(pipAudit?.status).toBe('ok');
    expect(pipAudit?.reason).toMatch(/parsed/i);
    // pip-audit fixture: 2 vulns (django CVE + requests no-fix).
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(2);
  });

  it('audits a pyproject-only project by pointing pip-audit at the project directory', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'pyproject.toml'), '[project]\nname = "x"\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
    );
    let capturedArgs: string[] | undefined;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'pip-audit') {
        capturedArgs = opts.args;
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, pipAuditFx(), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    await getTool('deps_audit').handler({ project_path: project }, plugin);

    expect(capturedArgs).not.toContain('-r');
    expect(capturedArgs).toContain(project);
  });

  it('item 3 (GC3): a pip-audit resolution failure (exit 1, no valid report) reads as failed, never ok', async () => {
    // pip-audit exits 1 on a genuine failure (a Poetry-only pyproject it
    // cannot read, a broken requirements file) the SAME way it exits 1 when
    // vulnerabilities are found. Reproduced: no -o file is ever written on
    // this path (pip-audit prints its error to stderr instead).
    const project = tempProject();
    writeFileSync(join(project, 'requirements.txt'), 'django==2.0.1\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'pip-audit') {
        // No -o file written at all — the real failure signature.
        return { outcome: 'failed' as const, exitCode: 1, stdout: '', stderr: 'ResolutionImpossible', truncated: false };
      }
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
    const pipAudit = r.tools_run.find((t) => t.name === 'pip-audit');
    expect(pipAudit?.status).toBe('failed');
    expect(r.missing_tools).toContain('pip-audit');
    expect(Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBe(0);
    expect(r.coverage).not.toBe('full');
  });

  it('item 3 (GC3): an exit-1 pip-audit report that IS valid JSON with a dependencies array still reads as ok', async () => {
    // The positive control for the same check: exit 1 with vulnerabilities
    // found (a real, valid report) must not be mistaken for a failure.
    const project = tempProject();
    writeFileSync(join(project, 'requirements.txt'), 'django==2.0.1\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'pip-audit') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, pipAuditFx(), 'utf8');
        return { outcome: 'failed' as const, exitCode: 1, stdout: '', stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string }[];
    };
    expect(r.tools_run.find((t) => t.name === 'pip-audit')?.status).toBe('ok');
  });

  it('item 9: pip-audit runs once PER requirements file and attributes each finding to its real source file', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'requirements.txt'), 'django==2.0.1\n', 'utf8');
    mkdirSync(join(project, 'requirements'));
    writeFileSync(join(project, 'requirements', 'dev.txt'), 'requests==2.20.0\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
    );
    const calls: string[][] = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'pip-audit') {
        calls.push(opts.args ?? []);
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, pipAuditFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
    };
    expect(r.ok).toBe(true);
    // One pip-audit invocation per file — never both files combined into a
    // single -r -r call.
    expect(calls).toHaveLength(2);
    for (const args of calls) {
      const rIdx = args.indexOf('-r');
      expect(args.filter((a) => a === '-r')).toHaveLength(1);
      expect(rIdx).toBeGreaterThanOrEqual(0);
    }

    const findings = plugin.storage.findings.listByScan(r.scan_id).filter((f) => f.tool === 'pip-audit');
    const filePaths = new Set(findings.map((f) => f.file_path));
    // Findings from BOTH calls are attributed to their real file, never a
    // hardcoded 'requirements.txt' for the requirements/dev.txt call.
    expect(filePaths.has('requirements.txt')).toBe(true);
    expect([...filePaths].some((p) => p?.includes('dev.txt'))).toBe(true);
  });

  it('runs dotnet SCA for a bare .csproj Trivy could not cover, restoring first', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    const commands: string[] = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      commands.push([opts.command, ...(opts.args ?? [])].join(' '));
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        return {
          outcome: 'completed' as const,
          exitCode: 0,
          stdout: dotnetListFx(),
          stderr: '',
          truncated: false,
        };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    expect(commands.some((c) => c.startsWith('dotnet restore'))).toBe(true);
    expect(commands.some((c) => c.startsWith('dotnet list') && c.includes('--vulnerable'))).toBe(true);
    const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
    expect(dotnet?.status).toBe('ok');
    // dotnet-list-vulnerable.json fixture: 1 top-level + 1 transitive.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(2);
  });

  it('item 8 (fix round 3): deps_audit ALWAYS restores first, even when `dotnet list --no-restore` would have succeeded anyway', async () => {
    // Fix round 3 replaces "try list first, restore only on failure"
    // entirely — measured directly, `dotnet list --no-restore` against a
    // STALE obj/ exits 0 with valid-but-outdated JSON, which "try list
    // first" could never distinguish from a genuinely fresh one.
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    const commands: string[] = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      commands.push([opts.command, ...(opts.args ?? [])].join(' '));
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: dotnetListFx(), stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = await tool.handler({ project_path: project }, plugin);
    expect(r.ok).toBe(true);
    const restoreIdx = commands.findIndex((c) => c.startsWith('dotnet restore'));
    const listIdx = commands.findIndex((c) => c.startsWith('dotnet list'));
    expect(restoreIdx).toBeGreaterThanOrEqual(0);
    expect(listIdx).toBeGreaterThan(restoreIdx);
    // Fix round 2, item 8: EVERY `dotnet list` call carries `--no-restore`
    // — `dotnet list package` restores implicitly otherwise, with no
    // `--locked-mode` equivalent.
    expect(commands.some((c) => c.startsWith('dotnet list') && c.includes('--no-restore'))).toBe(true);
  });

  it('item 8 (fix round 3): a failed restore skips dotnet list entirely for that target and reports a gap', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    let listCalled = false;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        return {
          outcome: 'failed' as const,
          exitCode: 1,
          stdout: '',
          stderr: 'error NU1004: The package reference version has changed',
          truncated: false,
        };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        listCalled = true;
        return { outcome: 'completed' as const, exitCode: 0, stdout: dotnetListFx(), stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
    };
    expect(r.ok).toBe(true);
    expect(listCalled).toBe(false);
    const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
    expect(dotnet?.status).not.toBe('ok');
    expect(dotnet?.reason).toMatch(/NU1004/);
    expect(r.missing_tools).toContain('dotnet');
  });

  it('item 8 (fix round 3): requestedVersion != resolvedVersion in the list JSON is treated as a gap, not a clean scan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        const stale = JSON.stringify({
          projects: [
            {
              frameworks: [
                {
                  topLevelPackages: [
                    { id: 'Newtonsoft.Json', requestedVersion: '12.0.3', resolvedVersion: '12.0.1' },
                  ],
                },
              ],
            },
          ],
        });
        return { outcome: 'completed' as const, exitCode: 0, stdout: stale, stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
    expect(dotnet?.status).not.toBe('ok');
    expect(r.missing_tools).toContain('dotnet');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
  });

  it('item 8 (fix round 2): a .sln target discovers packages.lock.json next to EACH .csproj, not next to the .sln itself', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'App.sln'), 'Microsoft Visual Studio Solution File', 'utf8');
    mkdirSync(join(project, 'src', 'Proj'), { recursive: true });
    writeFileSync(join(project, 'src', 'Proj', 'Proj.csproj'), '<Project></Project>', 'utf8');
    // The lock file sits next to the .csproj, in a subdirectory — NOT next
    // to the .sln at the project root. `dirname(target)` for a .sln target
    // is the project root, so the fix round 1 shape's `existsSync(join(
    // dirname(target), 'packages.lock.json'))` would look in the WRONG
    // place and never find this file.
    writeFileSync(join(project, 'src', 'Proj', 'packages.lock.json'), '{}', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    const restoreCommands: string[][] = [];
    // Fix round 3: restore ALWAYS runs first, so the one `dotnet list` call
    // that follows always sees a fresh restore — no retry-on-failure mock
    // needed here any more.
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        restoreCommands.push(opts.args ?? []);
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: dotnetListFx(), stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = await tool.handler({ project_path: project }, plugin);
    expect(r.ok).toBe(true);
    expect(restoreCommands).toHaveLength(1);
    // The per-.csproj discovery found the lock file the .sln itself does
    // not sit next to — `--locked-mode` must be passed.
    expect(restoreCommands[0]).toContain('--locked-mode');
  });

  it('marks a missing dotnet SDK as a coverage gap for a project with a .csproj', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('deps_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      missing_tools: string[];
      coverage: string;
    };
    expect(r.ok).toBe(true);
    expect(r.missing_tools).toContain('dotnet');
    expect(r.coverage).not.toBe('full');
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
    // Every npm install this tool proposes carries --ignore-scripts.
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.21 --ignore-scripts');
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

  function seedCve(
    plugin: PluginContext,
    project: string,
    cve: { cve_id: string; package_name: string; installed_version: string; fixed_version?: string },
  ): void {
    plugin.storage.scans.insert({
      scan_id: cve.cve_id,
      scan_type: 'deps',
      project_path: project,
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: cve.cve_id,
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    plugin.storage.cves.upsert({ ...cve, severity: 'high', scan_id: cve.cve_id });
  }

  /** Seeds several CVEs into ONE scan (unlike `seedCve`, which creates a
   *  fresh scan per call — only the latest scan's CVEs are ever visible to
   *  `deps_update_plan`, so a package with more than one active CVE must be
   *  seeded this way for both to be seen together). */
  function seedCves(
    plugin: PluginContext,
    project: string,
    scanId: string,
    cves: Array<{ cve_id: string; package_name: string; installed_version: string; fixed_version?: string }>,
  ): void {
    plugin.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: project, tree_hash: 'h' });
    plugin.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
    for (const cve of cves) {
      plugin.storage.cves.upsert({ ...cve, severity: 'high', scan_id: scanId });
    }
  }

  it('ignores a messy (non-exact) Trivy fixed_version rather than corrupting the computed minimum', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"my-app","dependencies":{"lodash":"3.10.1"}}', 'utf8');
    const plugin = makePlugin(project);
    // Real Trivy data for a package with a long CVE history routinely mixes
    // exact versions with open ranges and multi-branch lists (lodash's own
    // CVE set has both). A naive string comparison between ">=4.17.11" and
    // "4.17.19" picks the range string as "greater" — this asserts it never
    // does, and that the messy one is simply ignored in the version math.
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-A', package_name: 'lodash', installed_version: '3.10.1', fixed_version: '4.17.19' },
      { cve_id: 'CVE-B', package_name: 'lodash', installed_version: '3.10.1', fixed_version: '>=4.17.11' },
    ]);

    // `dependent` deliberately does NOT match the package.json `name` field
    // ("npmoutdated" is real npm's own top-level `dependent` value in a
    // fixture whose package.json declares "name": "x" — see
    // readNpmDirectDependencies's own module comment) — directness is read
    // from package.json's own `dependencies`, never from this field.
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '3.10.1', latest: '4.18.1', dependent: 'some-directory-name' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ latest_version: string; cve_ids?: string[]; upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );

    expect(r.plan).toHaveLength(1);
    // The clean 4.17.19 wins — never the range string, and never silently
    // discarded in favour of npm's own "latest" either.
    expect(r.plan[0]?.latest_version).toBe('4.17.19');
    expect(r.plan[0]?.cve_ids).toEqual(['CVE-A', 'CVE-B']);
    // A real install, not an overrides-only step: lodash IS a direct
    // dependency (declared in package.json), regardless of what `dependent`
    // said.
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.19 --ignore-scripts');
  });

  it('falls back to npm outdated\'s "latest" when every active CVE\'s fixed_version is unusable', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"my-app","dependencies":{"lodash":"3.10.1"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-C',
      package_name: 'lodash',
      installed_version: '3.10.1',
      fixed_version: '>=4.17.11',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '3.10.1', latest: '4.18.1', dependent: 'irrelevant' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan[0]?.latest_version).toBe('4.18.1');
  });

  it('upgrades a direct npm package to the MINIMUM fixed version, not npm outdated\'s "latest"', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"my-app","dependencies":{"lodash":"4.17.15"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-2024-1',
      package_name: 'lodash',
      installed_version: '4.17.15',
      fixed_version: '4.17.19',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '4.17.15', latest: '4.17.21', dependent: 'irrelevant' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ package_name: string; latest_version: string; upgrade_command: string; cve_ids?: string[] }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.latest_version).toBe('4.17.19'); // fixed, not npm's own 4.17.21
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.19 --ignore-scripts');
    expect(r.plan[0]?.cve_ids).toEqual(['CVE-2024-1']);
  });

  it('emits an npm overrides step (not npm install) for a vulnerable TRANSITIVE package', async () => {
    const project = tempProject();
    // minimist is deliberately absent from package.json's own dependency
    // fields — a real transitive package (pulled in by something else),
    // never declared directly.
    writeFileSync(
      join(project, 'package.json'),
      '{"name":"my-app","dependencies":{"mkdirp":"0.5.0"}}',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-2024-2',
      package_name: 'minimist',
      installed_version: '0.0.8',
      fixed_version: '1.2.6',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            minimist: { current: '0.0.8', latest: '1.2.8', dependent: 'mkdirp' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{
        package_name: string;
        upgrade_command: string;
        shell_command?: string;
        follow_up_command?: string;
        classification: string;
        cve_ids?: string[];
      }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.classification).toBe('security');
    // Bracket notation, not dot notation: `npm pkg set` would otherwise
    // treat a dot in the package name as a nested-key path separator.
    // `upgrade_command` stays UNQUOTED (fix round 3, item N1 — reverting
    // fix round 2's own quoting): `create_fix_pr`'s `fixpr/apply.ts` splits
    // this on whitespace and runs it WITHOUT a shell, so a quoted token is
    // not unwrapped — it becomes literal characters in the argument,
    // corrupting package.json while still reporting `applied: true`. The
    // shell-quoted, paste-safe copy lives in `shell_command` instead.
    expect(r.plan[0]?.upgrade_command).toBe('npm pkg set overrides[minimist]=1.2.6');
    expect(r.plan[0]?.shell_command).toBe("npm pkg set 'overrides[minimist]=1.2.6'");
    expect(r.plan[0]?.cve_ids).toEqual(['CVE-2024-2']);
    // `npm pkg set` only rewrites package.json — the lockfile still needs a
    // real reinstall to actually apply the override.
    expect(r.plan[0]?.follow_up_command).toBe('npm install --ignore-scripts');
  });

  it('defaults to a real npm install (never overrides-only) when package.json cannot be read', async () => {
    // An overrides-only step never touches node_modules/package-lock.json —
    // reproduced against a genuine Trivy scan (see this file's own history):
    // guessing "transitive" when directness is unknown can leave a CVE
    // completely unfixed. A real `npm install` is the safe default either way.
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), 'not valid json{{{', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-2024-4',
      package_name: 'lodash',
      installed_version: '4.17.15',
      fixed_version: '4.17.19',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '4.17.15', latest: '4.17.21', dependent: 'whatever' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.19 --ignore-scripts');
  });

  it('scopes the CVE source to THIS project — a same-named package with a CVE on a different project does not leak in', async () => {
    const projectA = tempProject();
    const projectB = tempProject();
    writeFileSync(join(projectA, 'package.json'), '{"name":"app-a","dependencies":{"lodash":"4.17.15"}}', 'utf8');
    writeFileSync(join(projectB, 'package.json'), '{"name":"app-b","dependencies":{"lodash":"4.17.15"}}', 'utf8');
    const plugin = makePlugin(projectB);
    // CVE recorded against project A only.
    seedCve(plugin, projectA, {
      cve_id: 'CVE-2024-3',
      package_name: 'lodash',
      installed_version: '4.17.15',
      fixed_version: '4.17.19',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            lodash: { current: '4.17.15', latest: '4.17.21', dependent: 'app-b' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ classification: string; latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: projectB }, plugin),
    );

    // Project B's own scan never happened — no CVE data for it, so this is
    // an ordinary (non-security) update at npm's own "latest".
    expect(r.plan[0]?.classification).not.toBe('security');
    expect(r.plan[0]?.latest_version).toBe('4.17.21');
  });

  it('pip: plans a pin bump from requirements.txt for a package with an active CVE and fixed_version, never touching pip/pip-audit on the host', async () => {
    const project = tempProject();
    writeFileSync(project + '/requirements.txt', 'django==2.0.1\nrequests==2.20.0\n', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-2019-19844',
      package_name: 'django',
      installed_version: '2.0.1',
      fixed_version: '2.2.9',
    });

    const execaSpy = vi.mocked(execa);
    execaSpy.mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ package_name: string; installed_version: string; latest_version: string; ecosystem: string; cve_ids?: string[] }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]).toMatchObject({
      package_name: 'django',
      installed_version: '2.0.1',
      latest_version: '2.2.9',
      ecosystem: 'pip',
      cve_ids: ['CVE-2019-19844'],
    });
    // requests has no active CVE, so it is left alone.
    expect(r.plan.some((s) => s.package_name === 'requests')).toBe(false);
    // Never calls pip or pip-audit against the host.
    expect(execaSpy.mock.calls.some(([cmd]) => cmd === 'pip' || cmd === 'pip-audit')).toBe(false);
  });

  it('pip: plans from pyproject.toml PEP 621 dependencies when no requirements.txt exists', async () => {
    const project = tempProject();
    writeFileSync(
      project + '/pyproject.toml',
      '[project]\nname = "x"\ndependencies = ["django==2.0.1", "click>=8.0"]\n',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-2019-19844',
      package_name: 'django',
      installed_version: '2.0.1',
      fixed_version: '2.2.9',
    });

    const r = okResult<{ plan: Array<{ package_name: string; latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );

    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.package_name).toBe('django');
    expect(r.plan[0]?.latest_version).toBe('2.2.9');
  });

  it('pip: proposes nothing for a pin with no active CVE', async () => {
    const project = tempProject();
    writeFileSync(project + '/requirements.txt', 'django==2.0.1\n', 'utf8');
    const plugin = makePlugin(project);

    const r = okResult<{ plan: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([]);
  });

  // -------------------------------------------------------------- fix round 1

  it('CRITICAL item 1: npm never proposes a downgrade from a stale CVE row — falls back to npm outdated\'s own "latest"', async () => {
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"lodash":"4.17.21"}}', 'utf8');
    const plugin = makePlugin(project);
    // The CVE row was recorded against an OLDER installed version (3.10.1)
    // than what npm outdated reports as CURRENTLY installed (4.17.21) — a
    // stale scan. The recorded "fix" (4.17.19) is a downgrade relative to
    // what is actually installed now.
    seedCve(plugin, project, {
      cve_id: 'CVE-STALE-1',
      package_name: 'lodash',
      installed_version: '3.10.1',
      fixed_version: '4.17.19',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({ lodash: { current: '4.17.21', latest: '4.18.1', dependent: 'irrelevant' } }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ latest_version: string; installed_version: string; classification: string; cve_ids?: string[] }>;
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[]; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.installed_version).toBe('4.17.21');
    // Never 4.17.19 (a downgrade from 4.17.21) — falls back to npm's own latest.
    expect(r.plan[0]?.latest_version).toBe('4.18.1');
    // Fix round 2 ("cheap" item): this CVE is STALE — installed (4.17.21) is
    // already above its own recorded fix (4.17.19) — so the ordinary
    // npm-latest upgrade above must NOT be mislabelled `security` with
    // those (already resolved) CVE ids still attached.
    expect(r.plan[0]?.classification).toBe('minor');
    expect(r.plan[0]?.cve_ids).toBeUndefined();
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({ package_name: 'lodash', ecosystem: 'npm', cve_ids: ['CVE-STALE-1'] });
    expect(r.unplanned[0]?.reason).toMatch(/already_fixed/);
  });

  it('N2 (fix round 3): a PRE-RELEASE install is never mislabelled already_fixed — the CVE stays active if a clean fix is genuinely above its core version', async () => {
    // Reproduced from the review: `minCleanVersionAbove` rejects a
    // pre-release install (`2.0.0-beta.1`) outright, and the fix round 2
    // `staleCve` check read that rejection as "no safe version above
    // installed" — indistinguishable from "already past the fix". It is
    // not: 2.0.1 is genuinely above 2.0.0-beta.1's core version.
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"somepkg":"^2.0.0-beta.1"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-PRE-1',
      package_name: 'somepkg',
      installed_version: '1.9.0',
      fixed_version: '2.0.1',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            somepkg: { current: '2.0.0-beta.1', latest: '2.0.1', dependent: 'irrelevant' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ latest_version: string; installed_version: string; classification: string; cve_ids?: string[] }>;
      unplanned: unknown[];
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.installed_version).toBe('2.0.0-beta.1');
    expect(r.plan[0]?.latest_version).toBe('2.0.1');
    // Still labelled `security`, with the CVE id attached — the fix is
    // real, not a false already_fixed.
    expect(r.plan[0]?.classification).toBe('security');
    expect(r.plan[0]?.cve_ids).toEqual(['CVE-PRE-1']);
    expect(r.unplanned).toEqual([]);
  });

  it('N2 (fix round 3): a pre-release install genuinely past its own fix is still left unplanned, never a downgrade proposal', async () => {
    // The counterpart control: when a pre-release's OWN core is already at
    // or above the fix, there is still no safe target — this must not
    // regress into proposing the fix as a downgrade just because loose
    // comparison is now in play.
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"somepkg":"^2.0.1-beta.1"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-PRE-2',
      package_name: 'somepkg',
      installed_version: '1.9.0',
      fixed_version: '2.0.0',
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return {
          exitCode: 1,
          stdout: JSON.stringify({
            somepkg: { current: '2.0.1-beta.1', latest: '2.0.1-beta.1', dependent: 'irrelevant' },
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[]; unplanned: Array<{ package_name: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([]);
    // Not `already_fixed` (installed is NOT a clean version, so that tag is
    // never claimed) — the generic "no safe upgrade target" reason instead.
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]?.reason).not.toMatch(/already_fixed/);
  });

  it('CRITICAL item 1: npm reports unplanned (never a downgrade) when neither the CVE fix nor npm\'s "latest" is above installed', async () => {
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"lodash":"4.17.21"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-STALE-2',
      package_name: 'lodash',
      installed_version: '3.10.1',
      fixed_version: '4.17.19', // below the ACTUAL current 4.17.21
    });

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        // npm itself agrees nothing newer exists either.
        return {
          exitCode: 1,
          stdout: JSON.stringify({ lodash: { current: '4.17.21', latest: '4.17.21', dependent: 'irrelevant' } }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[]; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({ package_name: 'lodash', ecosystem: 'npm', cve_ids: ['CVE-STALE-2'] });
  });

  it('item 2: a transitive CVE\'d package npm outdated never lists at all still gets an overrides step, driven from the CVE map', async () => {
    const project = tempProject();
    // minimist is NOT declared directly — a real transitive dependency.
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"mkdirp":"0.5.0"}}', 'utf8');
    // Fix round 2, item 10: pass 2 now only claims a package this npm
    // install's own resolved graph actually contains (a lockfile or
    // node_modules) — minimist has to be a REAL resolved transitive
    // dependency here, not just a name that happens to be in the CVE map.
    writeFileSync(
      project + '/package-lock.json',
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: {
          '': { name: 'x', dependencies: { mkdirp: '0.5.0' } },
          'node_modules/mkdirp': { version: '0.5.0' },
          'node_modules/minimist': { version: '0.0.8' },
        },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-TRANS-1',
      package_name: 'minimist',
      installed_version: '0.0.8',
      fixed_version: '1.2.6',
    });

    // `npm outdated --json` — since npm 7+ — lists ONLY direct deps, so
    // minimist never appears here at all, unlike the earlier (unrealistic)
    // mocked shape this suite used to rely on.
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return { exitCode: 0, stdout: '', stderr: '' }; // nothing outdated among direct deps
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ package_name: string; upgrade_command: string; follow_up_command?: string; classification: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]).toMatchObject({
      package_name: 'minimist',
      classification: 'security',
      // Unquoted (fix round 3, item N1 — see the other test's comment for
      // why); `readNpmResolvedPackageNames` supplies the lockfile's own
      // spelling of the name here too.
      upgrade_command: 'npm pkg set overrides[minimist]=1.2.6',
      follow_up_command: 'npm install --ignore-scripts',
    });
  });

  it('item 10 (fix round 2, NEW BREAKAGE): pass 2 never turns a non-npm CVE (no package-lock.json evidence) into an npm overrides step', async () => {
    const project = tempProject();
    // A polyglot repo: npm present (package.json, no lockfile written for
    // this test — nothing here resolves via npm at all) alongside CVEs that
    // plainly belong to OTHER ecosystems (pip's django, composer's
    // laravel/framework) — reproducing the coordinator's own probe.
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{}}', 'utf8');
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-DJANGO-1', package_name: 'django', installed_version: '2.0.1', fixed_version: '2.2.9' },
      {
        cve_id: 'CVE-LARAVEL-1',
        package_name: 'laravel/framework',
        installed_version: '8.0.0',
        fixed_version: '8.22.1',
      },
    ]);
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ package_name: string; upgrade_command: string }>;
      unplanned: Array<{ package_name: string; ecosystem: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    // Neither package is npm-resolvable (no lockfile, no node_modules) — the
    // OLD code minted `npm pkg set overrides[django]=2.2.9` and
    // `overrides[laravel/framework]=8.22.1` here, both labelled `security`.
    expect(r.plan.some((s) => s.upgrade_command.includes('overrides'))).toBe(false);
    expect(r.plan.some((s) => s.package_name === 'django')).toBe(false);
    expect(r.plan.some((s) => s.package_name === 'laravel/framework')).toBe(false);
    // Fix round 3's top-level catch-all still reports both, ecosystem
    // 'unknown' — neither vanishes silently.
    expect(r.unplanned.find((u) => u.package_name === 'django')?.ecosystem).toBe('unknown');
    expect(r.unplanned.find((u) => u.package_name === 'laravel/framework')?.ecosystem).toBe('unknown');
  });

  it('#7 (fix round 3): npm+composer with NO pip present still surfaces a composer CVE via the catch-all, not dropped', async () => {
    // The coordinator's own probe: npm and composer present, pip absent —
    // laravel/framework has no runner of its own (composer has no CVE-map
    // sweep) and previously vanished from both plan and unplanned.
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{}}', 'utf8');
    writeFileSync(
      project + '/composer.json',
      JSON.stringify({ name: 'a/b', require: { 'laravel/framework': '^8.0' } }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-LARAVEL-2',
      package_name: 'laravel/framework',
      installed_version: '8.0.0',
      fixed_version: '8.22.1',
    });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[] }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({
      package_name: 'laravel/framework',
      ecosystem: 'unknown',
      cve_ids: ['CVE-LARAVEL-2'],
    });
  });

  it('#7 (fix round 3): a pnpm-resolved TRANSITIVE dependency is found via the .pnpm store, real symlinks and all', async () => {
    // pnpm's top-level node_modules/<name> entries are SYMLINKS into
    // .pnpm/ — Dirent.isDirectory() reflects the symlink itself (always
    // false), not its target, so a plain check silently skipped every pnpm
    // dependency. The .pnpm store itself holds a REAL directory per
    // installed package (direct or transitive), which this test builds by
    // hand to avoid depending on a real pnpm install being on PATH.
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"mkdirp":"0.5.1"}}', 'utf8');
    const nm = join(project, 'node_modules');
    mkdirSync(join(nm, '.pnpm', 'minimist@0.0.8', 'node_modules', 'minimist'), { recursive: true });
    writeFileSync(
      join(nm, '.pnpm', 'minimist@0.0.8', 'node_modules', 'minimist', 'package.json'),
      '{"name":"minimist","version":"0.0.8"}',
      'utf8',
    );
    mkdirSync(join(nm, '.pnpm', 'mkdirp@0.5.1', 'node_modules', 'mkdirp'), { recursive: true });
    writeFileSync(
      join(nm, '.pnpm', 'mkdirp@0.5.1', 'node_modules', 'mkdirp', 'package.json'),
      '{"name":"mkdirp","version":"0.5.1"}',
      'utf8',
    );
    // The top-level entry pnpm would normally symlink — a real directory
    // here is a fine stand-in: the point under test is the .pnpm store
    // scan, not symlink-following itself.
    mkdirSync(join(nm, 'mkdirp'), { recursive: true });
    writeFileSync(join(nm, 'mkdirp', 'package.json'), '{"name":"mkdirp","version":"0.5.1"}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-PNPM-1',
      package_name: 'minimist',
      installed_version: '0.0.8',
      fixed_version: '1.2.6',
    });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ package_name: string; upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]).toMatchObject({
      package_name: 'minimist',
      upgrade_command: 'npm pkg set overrides[minimist]=1.2.6',
    });
  });

  it('"cheap" item (fix round 3): the override key uses the LOCKFILE\'s spelling, not the CVE scanner\'s own casing', async () => {
    // The coordinator's own probe: a CVE row recorded as "MiniMist" against
    // a lockfile that (correctly) spells the package "minimist". Keying
    // the override on the CVE's own casing creates an override for a name
    // that does not exist in the tree at all.
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"mkdirp":"0.5.0"}}', 'utf8');
    writeFileSync(
      project + '/package-lock.json',
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: {
          '': { name: 'x', dependencies: { mkdirp: '0.5.0' } },
          'node_modules/mkdirp': { version: '0.5.0' },
          'node_modules/minimist': { version: '0.0.8' },
        },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-CASING-1',
      package_name: 'MiniMist',
      installed_version: '0.0.8',
      fixed_version: '1.2.6',
    });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ package_name: string; upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toHaveLength(1);
    expect(r.plan[0]?.package_name).toBe('minimist');
    expect(r.plan[0]?.upgrade_command).toBe('npm pkg set overrides[minimist]=1.2.6');
  });

  it('item 7 (fix round 2, npm half): a DIRECT npm dependency with an active CVE that `npm outdated` never lists is reported unplanned, not silently dropped', async () => {
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{"leftpad":"1.0.0"}}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-DIRECT-1',
      package_name: 'leftpad',
      installed_version: '1.0.0',
      fixed_version: '1.0.1',
    });
    // `npm outdated` reports NOTHING for leftpad at all (registry
    // unreachable, npm considers it current, whatever the reason) — the old
    // code's pass 2 silently `continue`d for any direct dependency.
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[]; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({ package_name: 'leftpad', ecosystem: 'npm', cve_ids: ['CVE-DIRECT-1'] });
  });

  it('item 2: a transitive CVE package with no recorded installed_version produces no step and no npm-SPECIFIC unplanned entry — but the top-level catch-all still reports it', async () => {
    const project = tempProject();
    writeFileSync(project + '/package.json', '{"name":"x","dependencies":{}}', 'utf8');
    const plugin = makePlugin(project);
    // No installed_version recorded at all — npm's own pass 2 cannot even
    // attribute it to this tree with confidence (the cves table has no
    // ecosystem column), so it never becomes an npm-labelled unplanned
    // entry. Fix round 3's top-level catch-all (item #7) is what keeps it
    // from vanishing entirely: EVERY CVE key with no step and no
    // ecosystem-specific unplanned entry is reported `unknown`.
    seedCve(plugin, project, {
      cve_id: 'CVE-TRANS-2',
      package_name: 'some-other-ecosystems-package',
      installed_version: '',
      fixed_version: '2.0.0',
    });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[] }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(r.unplanned.some((u) => u.ecosystem === 'npm')).toBe(false);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({
      package_name: 'some-other-ecosystems-package',
      ecosystem: 'unknown',
      cve_ids: ['CVE-TRANS-2'],
    });
  });

  it('item 7: pip reports unplanned for a range specifier and an unpinned name with an active CVE, instead of dropping them silently', async () => {
    const project = tempProject();
    writeFileSync(
      project + '/requirements.txt',
      'django>=4.0\nrequests\ndjango==2.0.1\n',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-RANGE-1', package_name: 'django', installed_version: '2.0.1', fixed_version: '2.2.9' },
      { cve_id: 'CVE-BARE-1', package_name: 'requests', installed_version: '2.20.0', fixed_version: '2.20.1' },
    ]);

    const r = okResult<{
      plan: Array<{ package_name: string }>;
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    // The exact `django==2.0.1` pin becomes a real step.
    expect(r.plan.some((s) => s.package_name === 'django')).toBe(true);
    // `requests` (bare, unpinned) — active CVE, no determinable installed
    // version — reported, not dropped.
    expect(r.unplanned.some((u) => u.package_name === 'requests' && u.ecosystem === 'pip')).toBe(true);
  });

  it('item 7: pip parses pip-compile hash-pinned continuation lines, extras and environment markers', async () => {
    const project = tempProject();
    writeFileSync(
      project + '/requirements.txt',
      [
        'django==2.0.1 \\',
        '    --hash=sha256:abc123 \\',
        '    --hash=sha256:def456',
        'celery[redis]==5.3.0',
        'somepkg==1.0.0; python_version >= "3.8"',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-HASH-1', package_name: 'django', installed_version: '2.0.1', fixed_version: '2.2.9' },
      { cve_id: 'CVE-EXTRAS-1', package_name: 'celery', installed_version: '5.3.0', fixed_version: '5.3.1' },
      { cve_id: 'CVE-MARKER-1', package_name: 'somepkg', installed_version: '1.0.0', fixed_version: '1.0.1' },
    ]);

    const r = okResult<{ plan: Array<{ package_name: string; installed_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    const names = r.plan.map((s) => s.package_name).sort();
    expect(names).toEqual(['celery', 'django', 'somepkg']);
  });

  it('item 7 (fix round 2): pyproject.toml — a range spec, an extras pin, and a transitive dependency no manifest mentions all end up somewhere, never in an empty plan AND an empty unplanned', async () => {
    // Reproduces the coordinator's own probe exactly: a pyproject with
    // django>=4.2 (range), celery[redis]==5.3.0 (extras + exact pin), and a
    // transitive urllib3 (no mention anywhere), all three with active CVEs
    // and known fixes. The fix round 1 shape returned `plan: []` AND
    // `unplanned: []` — both `django` and `celery` were silently dropped by
    // the old `[^\]]*` block regex (which truncated the array at the FIRST
    // `]`, the one `celery[redis]` itself introduces), and urllib3 had no
    // sweep at all.
    const project = tempProject();
    writeFileSync(
      join(project, 'pyproject.toml'),
      [
        '[project]',
        'name = "x"',
        'dependencies = [',
        '    "django>=4.2",',
        '    "celery[redis]==5.3.0",',
        ']',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-PYPROJECT-DJANGO', package_name: 'django', installed_version: '4.2.0', fixed_version: '4.2.5' },
      { cve_id: 'CVE-PYPROJECT-CELERY', package_name: 'celery', installed_version: '5.3.0', fixed_version: '5.3.1' },
      {
        cve_id: 'CVE-PYPROJECT-URLLIB3',
        package_name: 'urllib3',
        installed_version: '1.26.0',
        fixed_version: '1.26.5',
      },
    ]);

    const r = okResult<{
      plan: Array<{ package_name: string; installed_version: string; latest_version: string }>;
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[]; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));

    // celery[redis]==5.3.0 -> an exact pin once extras are stripped -> a
    // real step (proves the depth-counting array parser: `celery[redis]`
    // would have truncated the array before this element existed at all
    // under the old regex).
    expect(r.plan.some((s) => s.package_name === 'celery' && s.latest_version === '5.3.1')).toBe(true);
    // django>=4.2 -> a non-exact specifier -> unplanned, not dropped, and
    // not silently treated as an exact pin either.
    const django = r.unplanned.find((u) => u.package_name === 'django');
    expect(django).toBeDefined();
    expect(django?.ecosystem).toBe('pip');
    expect(django?.cve_ids).toEqual(['CVE-PYPROJECT-DJANGO']);
    // urllib3 -> no requirements*.txt / pyproject.toml mention at all
    // (genuinely transitive) -> unplanned via the fix round 3 top-level
    // catch-all, never silently absent from both plan and unplanned.
    // ecosystem 'unknown', not 'pip' — fix round 3 removed pip's own pass 2
    // sweep entirely (it used to mislabel non-pip packages, e.g. a
    // composer or Go one, as 'pip' purely because npm did not resolve
    // them); pip's ecosystem label is now used ONLY for a package this
    // file's own parsing actually found a manifest line for.
    const urllib3 = r.unplanned.find((u) => u.package_name === 'urllib3');
    expect(urllib3).toBeDefined();
    expect(urllib3?.ecosystem).toBe('unknown');
  });

  it('"cheap" item (fix round 3): pyproject dependencies are read from the [project] table only — a [tool.uv] dev-dependencies array placed EARLIER in the file must not win', async () => {
    // The coordinator's own probe: `dependencies\s*=\s*\[` as a bare
    // substring search also matches inside `dev-dependencies = [...]` —
    // "dev-dependencies" ends in "dependencies" — so whichever array
    // appears FIRST in the file wins regardless of which TOML table it is
    // actually in.
    const project = tempProject();
    writeFileSync(
      join(project, 'pyproject.toml'),
      [
        '[tool.uv]',
        'dev-dependencies = ["pytest==7.0.0"]',
        '',
        '[project]',
        'name = "x"',
        'dependencies = ["django==4.2.0"]',
        '',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-UV-DJANGO', package_name: 'django', installed_version: '4.2.0', fixed_version: '4.2.5' },
      { cve_id: 'CVE-UV-PYTEST', package_name: 'pytest', installed_version: '7.0.0', fixed_version: '7.0.1' },
    ]);

    const r = okResult<{ plan: Array<{ package_name: string; latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    // django (the REAL [project] dependency) becomes a step.
    expect(r.plan.some((s) => s.package_name === 'django' && s.latest_version === '4.2.5')).toBe(true);
    // pytest (dev-dependencies, a DIFFERENT table) must never be read as if
    // it were a [project] dependency — the old unscoped search would have
    // found ONLY `["pytest==7.0.0"]` (the first "dependencies = [" match in
    // the file) and never reached django's array at all.
    expect(r.plan.some((s) => s.package_name === 'pytest')).toBe(false);
  });

  it('"cheap" item (fix round 3): an environment marker on a pyproject array element is stripped before matching, not left to break every regex', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'pyproject.toml'),
      [
        '[project]',
        'name = "x"',
        'dependencies = [',
        '    "urllib3==1.26.0; python_version >= \'3.8\'",',
        '    "requests[socks] == 2.25.0",',
        ']',
        '',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-MARKER-U', package_name: 'urllib3', installed_version: '1.26.0', fixed_version: '1.26.5' },
      { cve_id: 'CVE-MARKER-R', package_name: 'requests', installed_version: '2.25.0', fixed_version: '2.31.0' },
    ]);

    const r = okResult<{ plan: Array<{ package_name: string; latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    // Without marker-stripping, EVERY regex in parseOneRequirementSpec
    // fails on the trailing "; python_version >= '3.8'" text — the whole
    // mention silently vanishes (not even reported unplanned).
    expect(r.plan.some((s) => s.package_name === 'urllib3' && s.latest_version === '1.26.5')).toBe(true);
    // The spaced-extras form (`requests[socks] == 2.25.0`) already worked
    // (the exact-pin regex's `\s*==\s*` tolerates the space) — asserted
    // here as a no-regression control alongside the marker fix.
    expect(r.plan.some((s) => s.package_name === 'requests' && s.latest_version === '2.31.0')).toBe(true);
  });

  it('item 9: pip steps expose the target file as a structured field, not only inside upgrade_command', async () => {
    const project = tempProject();
    writeFileSync(project + '/requirements.txt', 'django==2.0.1\n', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-FILE-1',
      package_name: 'django',
      installed_version: '2.0.1',
      fixed_version: '2.2.9',
    });

    const r = okResult<{ plan: Array<{ file?: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan[0]?.file).toBe('requirements.txt');
  });

  it('item 8 (fix round 3): dotnet ALWAYS restores first, then lists with --no-restore — never the reverse', async () => {
    // Fix round 3 replaces the fix round 1/2 "try list first, restore only
    // on failure" shape entirely: measured directly, `dotnet list
    // --no-restore` against a STALE obj/ (restored once, the csproj edited
    // since) exits 0 with valid-looking JSON built from the OLD resolution
    // — "try list first" can never detect that. Restore must run BEFORE
    // list, unconditionally, every time.
    const project = tempProject();
    writeFileSync(project + '/Test.csproj', '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      if (cmd === 'dotnet' && args[0] === 'restore') {
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    await getTool('deps_update_plan').handler({ project_path: project }, plugin);
    const restoreIdx = calls.findIndex((c) => c.startsWith('dotnet restore'));
    const listIdx = calls.findIndex((c) => c.startsWith('dotnet list'));
    expect(restoreIdx).toBeGreaterThanOrEqual(0);
    expect(listIdx).toBeGreaterThan(restoreIdx);
    expect(calls.some((c) => c.startsWith('dotnet list') && c.includes('--no-restore'))).toBe(true);
  });

  it('item 8 (fix round 3): a failed restore returns an empty plan — dotnet list is never even attempted', async () => {
    const project = tempProject();
    writeFileSync(project + '/Test.csproj', '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);
    let listCalled = false;
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        return { exitCode: 1, stdout: '', stderr: 'error NU1004: lock out of sync' };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        listCalled = true;
        return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(listCalled).toBe(false);
    expect(r.plan).toEqual([]);
  });

  it('item 8 (fix round 3): a requestedVersion != resolvedVersion mismatch in the list JSON is treated as stale, not trusted', async () => {
    const project = tempProject();
    writeFileSync(project + '/Test.csproj', '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            projects: [
              {
                frameworks: [
                  {
                    topLevelPackages: [
                      {
                        id: 'Newtonsoft.Json',
                        requestedVersion: '12.0.3',
                        resolvedVersion: '12.0.1',
                        latestVersion: '13.0.1',
                      },
                    ],
                  },
                ],
              },
            ],
          }),
          stderr: '',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([]);
  });

  it('item 8 (fix round 2): deps_update_plan finds a packages.lock.json in a SUBDIRECTORY, not only at the project root', async () => {
    const project = tempProject();
    // A root-level .csproj is what makes `detectEcosystems` include
    // 'dotnet' at all (nested-only .csproj discovery is a separately
    // parked item, not this one) — but the LOCK FILE lives in a
    // subdirectory, the routine multi-project-repo shape.
    // `existsSync(join(projectPath, 'packages.lock.json'))` (the fix round
    // 1 shape) never looked anywhere else.
    writeFileSync(join(project, 'Root.csproj'), '<Project></Project>', 'utf8');
    mkdirSync(join(project, 'src', 'Proj'), { recursive: true });
    writeFileSync(join(project, 'src', 'Proj', 'Proj.csproj'), '<Project></Project>', 'utf8');
    writeFileSync(join(project, 'src', 'Proj', 'packages.lock.json'), '{}', 'utf8');
    const plugin = makePlugin(project);
    const restoreCalls: string[][] = [];
    // Fix round 3: restore ALWAYS runs first now, so `dotnet list` only
    // ever runs once, against an already-fresh restore — no retry-on-
    // failure mock needed here any more.
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        restoreCalls.push(args);
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    await getTool('deps_update_plan').handler({ project_path: project }, plugin);
    expect(restoreCalls).toHaveLength(1);
    expect(restoreCalls[0]).toContain('--locked-mode');
  });
});
