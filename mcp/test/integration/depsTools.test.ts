/**
 * Integration tests for deps_audit and deps_update_plan.
 *
 * deps_audit goes through the scan-tool factory → we mock `runProcess` and
 * `scannerAvailable`. deps_update_plan is a custom handler that calls
 * `execa` directly → we mock the `execa` module.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  existsSync,
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

  // Final review I4, measured on Trivy 0.69.3: `Results: []` for both shapes.
  // Before, neither was in the manifest table: `trivy ok`, coverage `full`,
  // 0 findings — for a Spring service and a PEP 621 project alike.
  it.each([
    ['build.gradle', 'dependencies { implementation "org.apache.logging.log4j:log4j-core:2.14.1" }\n', 'gradle'],
    ['build.gradle.kts', 'dependencies { implementation("org.apache.logging.log4j:log4j-core:2.14.1") }\n', 'gradle'],
    ['pyproject.toml', '[project]\nname = "x"\ndependencies = ["django==3.2.0"]\n', 'python'],
  ])('a bare %s Trivy cannot read is a trivy:<ecosystem> gap, never a clean full scan (%#)', async (file, body, eco) => {
    const project = tempProject();
    writeFileSync(join(project, file), body, 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const r = (await getTool('scan_deps').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      manifest_coverage_gaps: Array<{ ecosystem: string; files: string[] }>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.tools_run.find((t) => t.name === 'trivy')).toMatchObject({ status: 'skipped', reason: 'no_supported_manifest' });
    expect(r.missing_tools).toContain('trivy');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: eco, files: [file] }]);
    expect(r.coverage).not.toBe('full');
  });

  // Follow-up 2, item 3: the warning said "NO scanner ran … Install trivy"
  // for a Trivy that was installed and ran. It names the manifest and the fix.
  it('the warning for a bare build.gradle names the manifest and the Gradle fix, never "Install trivy" — forced or not (a gap is never a cache hit)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'build.gradle'), "plugins { id 'java' }\n", 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    for (const force of [true, false]) {
      const r = (await getTool('scan_deps').handler({ project_path: project, force }, plugin)) as {
        ok: true;
        warnings: string[];
      };
      const text = r.warnings.join('\n');
      expect(text).not.toMatch(/Install trivy/);
      expect(text).toMatch(/trivy is installed and ran/);
      expect(text).toContain('gradle (build.gradle)');
      expect(text).toContain('dependencyLocking { lockAllConfigurations() }');
    }
  });

  it('a Gradle build beside a covered npm project: trivy ok, `trivy:gradle` missing, coverage partial', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');
    writeFileSync(join(project, 'build.gradle'), 'plugins { id "java" }\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) {
        writeFileSync(path, JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const r = (await getTool('scan_deps').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
    };
    expect(r.missing_tools).toEqual(['trivy:gradle']);
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

  // Self-security review R6-I1: npm audit runs in the project, so the
  // project's .npmrc picks the server that answers it. Honoured — a private
  // registry is legitimate — but named, and without the credentials.
  it("names the registry the project's .npmrc sends npm audit to, never silently", async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(
      join(project, '.npmrc'),
      '; a comment\n@acme:registry=https://scoped.example/\nregistry = "https://ci:s3cret@npm.example.internal/repo/"\n',
      'utf8',
    );
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'npm') {
        return { outcome: 'completed' as const, exitCode: 1, stdout: npmAuditFx(), stderr: '', truncated: false };
      }
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string; honoured_config?: string[] }[];
    };
    const npm = r.tools_run.find((t) => t.name === 'npm');
    expect(npm?.status).toBe('ok');
    expect(npm?.reason).toContain(
      "npm audit answered by https://npm.example.internal/repo/ (from the project's .npmrc)",
    );
    expect(npm?.reason).not.toContain('s3cret');
    expect(npm?.honoured_config).toEqual(['.npmrc']);
  });

  it.each([
    ['no .npmrc', null],
    ['the public registry', 'registry=https://registry.npmjs.org/\n'],
    ['only a scoped registry', '@acme:registry=https://scoped.example/\n'],
  ])('says nothing about the registry for %s', async (_label, npmrc) => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    if (npmrc !== null) writeFileSync(join(project, '.npmrc'), npmrc, 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'npm') {
        return { outcome: 'completed' as const, exitCode: 1, stdout: npmAuditFx(), stderr: '', truncated: false };
      }
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; reason?: string; honoured_config?: string[] }[];
    };
    const npm = r.tools_run.find((t) => t.name === 'npm');
    expect(npm?.reason ?? '').not.toMatch(/answered by/);
    // Round 5, item 2: a project .npmrc is named whenever npm audit read one
    // (omit=dev or audit-level decide what it reports), whatever its registry.
    if (npmrc === null) {
      expect(npm?.honoured_config).toBeUndefined();
    } else {
      expect(npm?.honoured_config).toEqual(['.npmrc']);
      expect(npm?.reason).toMatch(/honoured the project's \.npmrc \(its registry and settings decide what npm audit reads and reports\)/);
    }
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

  it('a Gradle build without gradle.lockfile is a gap: no auditor of its own, never a clean full scan (I4)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'build.gradle.kts'), 'dependencies { implementation("x:y:1.0") }\n', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const path = outputPathFor(opts.args);
      if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      manifest_coverage_gaps: Array<{ ecosystem: string; files: string[] }>;
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.tools_run.find((t) => t.name === 'trivy')).toMatchObject({ status: 'skipped', reason: 'no_supported_manifest' });
    expect(r.missing_tools).toContain('trivy');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: 'gradle', files: ['build.gradle.kts'] }]);
    expect(r.coverage).not.toBe('full');
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

  // Review 3.0, wave 2 (b): a requirements file can carry pip's index
  // options, and pip-audit installs `-r` requirements with pip, which honours
  // them — so the file decides which index the audited versions come from,
  // as `.npmrc` decides which registry answers npm audit. Honoured (a private
  // index is legitimate), never silently.
  describe('pip-audit: index options in a requirements file are named', () => {
    async function pipAuditRun(project: string) {
      const plugin = makePlugin(project);
      vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
        name === 'pip-audit' ? '/fake/bin/pip-audit' : null,
      );
      vi.mocked(runProcess).mockImplementation(async (opts) => {
        if (opts.command === 'pip-audit') {
          const path = outputPathFor(opts.args);
          if (path) writeFileSync(path, pipAuditFx(), 'utf8');
        }
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      });
      const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
        ok: true;
        tools_run: { name: string; status: string; reason?: string; honoured_config?: string[] }[];
      };
      return r.tools_run.find((t) => t.name === 'pip-audit');
    }

    it('names every requirements file pip-audit read whose index options steer it — an included one too', async () => {
      const project = tempProject();
      writeFileSync(
        join(project, 'requirements.txt'),
        '--index-url https://ci:s3cret@pypi.example.internal/simple\ndjango==2.0.1\n',
        'utf8',
      );
      writeFileSync(
        join(project, 'requirements-dev.txt'),
        '# dev\n--extra-index-url https://extra.example/simple\n-r common/base.txt\nrequests==2.20.0\n',
        'utf8',
      );
      mkdirSync(join(project, 'common'));
      writeFileSync(join(project, 'common', 'base.txt'), '-i https://third.example/simple\nflask==1.0\n', 'utf8');
      mkdirSync(join(project, 'requirements'));
      writeFileSync(join(project, 'requirements', 'test.txt'), 'pytest==7.0.0\n', 'utf8');

      const run = await pipAuditRun(project);
      expect(run?.status).toBe('ok');
      expect(run?.honoured_config).toEqual(['common/base.txt', 'requirements-dev.txt', 'requirements.txt']);
      expect(run?.reason).toMatch(
        /honoured the project's common\/base\.txt, requirements-dev\.txt, requirements\.txt \(its package-index options decide which index pip-audit's resolution installs from\)/,
      );
      expect(run?.reason).not.toContain('s3cret');
    });

    it.each([
      ['--index-url=https://x.example/simple'],
      ['  -i https://x.example/simple'],
      ['-ihttps://x.example/simple'],
      ['--extra-index-url https://x.example/simple'],
      ['--find-links ./wheels'],
      ['-f https://x.example/wheels/'],
      ['--no-index'],
      ['--trusted-host x.example'],
    ])('names a requirements file holding `%s`', async (line) => {
      const project = tempProject();
      writeFileSync(join(project, 'requirements.txt'), `${line}\ndjango==2.0.1\n`, 'utf8');
      const run = await pipAuditRun(project);
      expect(run?.honoured_config).toEqual(['requirements.txt']);
    });

    it.each([
      ['no option at all', 'django==2.0.1\n'],
      ['an index option in a comment', '# --index-url https://x.example/simple\ndjango==2.0.1\n'],
      ['a per-requirement hash', 'django==2.0.1 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n'],
      ['an include with no index option', '-r base.txt\ndjango==2.0.1\n'],
    ])('names nothing for %s', async (_label, text) => {
      const project = tempProject();
      writeFileSync(join(project, 'requirements.txt'), text, 'utf8');
      writeFileSync(join(project, 'base.txt'), 'flask==1.0\n', 'utf8');
      const run = await pipAuditRun(project);
      expect(run?.status).toBe('ok');
      expect(run?.honoured_config).toBeUndefined();
      expect(run?.reason ?? '').not.toMatch(/honoured/);
    });
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

  // -------------------------------------------------------------- fix round 4

  /** The shape `dotnet sln add` writes: backslash paths, a solution folder. */
  function slnListing(entries: Array<[string, string]>): string {
    const lines = ['Microsoft Visual Studio Solution File, Format Version 12.00'];
    lines.push('Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "src", "src", "{11111111-1111-1111-1111-111111111111}"', 'EndProject');
    for (const [name, path] of entries) {
      lines.push(`Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "${name}", "${path}", "{22222222-2222-2222-2222-222222222222}"`, 'EndProject');
    }
    return lines.join('\r\n');
  }

  /** A deps_audit run with trivy reporting nothing and dotnet answering from
   *  `onRestore` / `onList`; returns the dotnet commands it saw. */
  async function auditDotnet(
    project: string,
    onRestore: (args: string[]) => { outcome: 'completed' | 'failed'; exitCode: number; stdout?: string; stderr?: string },
    onList: () => string = dotnetListFx,
  ) {
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    const dotnetCalls: string[][] = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'trivy') {
        const path = outputPathFor(opts.args);
        if (path) writeFileSync(path, trivyNoResultsFx(), 'utf8');
        return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      }
      if (opts.command === 'dotnet') dotnetCalls.push(opts.args ?? []);
      if (opts.command === 'dotnet' && opts.args?.[0] === 'restore') {
        const r = onRestore(opts.args);
        return { outcome: r.outcome, exitCode: r.exitCode, stdout: r.stdout ?? '', stderr: r.stderr ?? '', truncated: false };
      }
      if (opts.command === 'dotnet' && opts.args?.[0] === 'list') {
        return { outcome: 'completed' as const, exitCode: 0, stdout: onList(), stderr: '', truncated: false };
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
      findings_count_by_severity: Record<string, number>;
      dotnet_restore_failures?: Array<{ target: string; code: string; reason: string }>;
    };
    const restores = dotnetCalls.filter((a) => a[0] === 'restore');
    const lists = dotnetCalls.filter((a) => a[0] === 'list');
    return { r, restores, lists, total: Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0) };
  }

  const ok = () => ({ outcome: 'completed' as const, exitCode: 0 });

  it('C (fix round 4): a floating/range PackageReference (requested "12.*", resolved "12.0.3") is NOT a gap — its findings are kept', async () => {
    // Reviewer's floating.mjs, against a real SDK: `12.*`, `[12.0.1,13.0)`,
    // `12.0` and a not-on-the-feed `12.0.0` all make requestedVersion differ
    // from resolvedVersion after a perfectly fresh restore. The round 3
    // "defence in depth" read every one of them as staleness: dotnet
    // `failed`, coverage `none`, the Newtonsoft.Json finding dropped.
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const floating = dotnetListFx().replace('"requestedVersion": "12.0.1"', '"requestedVersion": "12.*"').replace(
      '"resolvedVersion": "12.0.1"',
      '"resolvedVersion": "12.0.3"',
    );
    expect(floating).toContain('"12.*"'); // the fixture edit really happened
    const { r, total } = await auditDotnet(project, ok, () => floating);
    expect(r.tools_run.find((t) => t.name === 'dotnet')?.status).toBe('ok');
    expect(r.missing_tools).not.toContain('dotnet');
    expect(total).toBe(2);
  });

  it('E (fix round 4): every restore passes --locked-mode — and -p:RestorePackagesWithLockFile=false when no project has a lock', async () => {
    // Measured: a project with RestorePackagesWithLockFile=true and no
    // committed lock gets a NEW packages.lock.json from a plain restore AND
    // from `--locked-mode` alone; only the false property stops it.
    const project = tempProject();
    writeFileSync(
      join(project, 'Test.csproj'),
      '<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>',
      'utf8',
    );
    const { restores } = await auditDotnet(project, ok);
    expect(restores).toHaveLength(1);
    expect(restores[0]).toContain('--locked-mode');
    expect(restores[0]).toContain('-p:RestorePackagesWithLockFile=false');
  });

  it('E (fix round 4): a lock five directories below the .sln is found from the solution list — --locked-mode, and NOT the false property (NU1005)', async () => {
    // Reviewer's deep.mjs: the old depth-4 walk never saw this lock, so a
    // plain restore rewrote it.
    const project = tempProject();
    writeFileSync(join(project, 'Root.sln'), slnListing([['App', 'src\\a\\b\\c\\App\\App.csproj']]), 'utf8');
    mkdirSync(join(project, 'src', 'a', 'b', 'c', 'App'), { recursive: true });
    writeFileSync(join(project, 'src', 'a', 'b', 'c', 'App', 'App.csproj'), '<Project></Project>', 'utf8');
    writeFileSync(join(project, 'src', 'a', 'b', 'c', 'App', 'packages.lock.json'), '{}', 'utf8');
    const { restores } = await auditDotnet(project, ok);
    expect(restores).toHaveLength(1);
    expect(restores[0]).toContain('--locked-mode');
    expect(restores[0]).not.toContain('-p:RestorePackagesWithLockFile=false');
  });

  it('E (fix round 4): a solution mixing a locked project with an opted-in lock-less one is not restored at all — reported as a gap', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Root.sln'), slnListing([['A', 'A\\A.csproj'], ['B', 'B\\B.csproj']]), 'utf8');
    mkdirSync(join(project, 'A'));
    mkdirSync(join(project, 'B'));
    writeFileSync(join(project, 'A', 'A.csproj'), '<Project></Project>', 'utf8');
    writeFileSync(join(project, 'A', 'packages.lock.json'), '{}', 'utf8');
    writeFileSync(
      join(project, 'B', 'B.csproj'),
      '<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>',
      'utf8',
    );
    const { r, restores, lists } = await auditDotnet(project, ok);
    expect(restores).toHaveLength(0);
    expect(lists).toHaveLength(0);
    expect(r.tools_run.find((t) => t.name === 'dotnet')?.status).toBe('failed');
    expect(r.missing_tools).toContain('dotnet');
    expect(r.dotnet_restore_failures?.[0]?.code).toBe('lock_file_would_be_created');
  });

  it('E (fix round 4): a lock file the restore created anyway is deleted again and the target reported as a gap', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const lock = join(project, 'packages.lock.json');
    const { r, lists } = await auditDotnet(project, () => {
      writeFileSync(lock, '{}', 'utf8'); // an opt-in this scan could not see
      return { outcome: 'completed', exitCode: 0 };
    });
    expect(existsSync(lock)).toBe(false);
    expect(lists).toHaveLength(0);
    expect(r.tools_run.find((t) => t.name === 'dotnet')?.status).toBe('failed');
    expect(r.dotnet_restore_failures?.[0]?.code).toBe('lock_file_would_be_created');
  });

  it('A (fix round 4): a feed failure (NU1101) is reported with its own code, distinct from an out-of-sync lock', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');
    const { r } = await auditDotnet(project, () => ({
      outcome: 'failed',
      exitCode: 1,
      stdout:
        "C:\\p\\Test.csproj : warning NU1903: Package 'Newtonsoft.Json' 12.0.1 has a known high severity vulnerability\n" +
        'C:\\p\\Test.csproj : error NU1101: Unable to find package Zz.Nope. No packages exist with this id in source(s): nuget.org',
    }));
    const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
    expect(dotnet?.status).toBe('failed');
    expect(dotnet?.reason).toMatch(/NU1101/);
    expect(dotnet?.reason).not.toMatch(/out of sync/);
    expect(r.dotnet_restore_failures).toEqual([
      expect.objectContaining({ target: 'Test.csproj', code: 'NU1101' }),
    ]);
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

  // Final review M2: the CVE source was the first completed deps-flavoured
  // row in a 50-row window — a scoped `deps` run, or a security_full whose
  // Trivy half failed, answered "nothing to update" while risk_score (the
  // newest USABLE deps scan) still counted the CVE.
  it.each([
    ['a newer scoped deps run', { scan_type: 'deps' as const, meta: { scope: { mode: 'staged', files: 1 } } }],
    [
      'a newer security_full whose Trivy half failed',
      {
        scan_type: 'security_full' as const,
        tools_run: [{ name: 'semgrep', status: 'ok' as const }, { name: 'trivy', status: 'failed' as const }],
      },
    ],
  ])('takes its CVEs from the newest usable deps scan, never %s', async (_label, newer) => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    const plugin = makePlugin(project);

    plugin.storage.scans.insert({ scan_id: 'usable', scan_type: 'deps', project_path: project, tree_hash: 'h1' });
    plugin.storage.scans.finalize({
      scan_id: 'usable',
      status: 'completed',
      tools_run: [{ name: 'trivy', status: 'ok' }],
      missing_tools: [],
    });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-2024-XXX',
      package_name: 'lodash',
      installed_version: '4.17.20',
      severity: 'high',
      scan_id: 'usable',
    });
    plugin.storage.scans.insert({
      scan_id: 'newer',
      scan_type: newer.scan_type,
      project_path: project,
      tree_hash: 'h2',
      ...('meta' in newer ? { meta: newer.meta } : {}),
    });
    plugin.storage.scans.finalize({
      scan_id: 'newer',
      status: 'completed',
      tools_run: 'tools_run' in newer ? newer.tools_run : [{ name: 'trivy', status: 'ok' }],
      missing_tools: [],
    });
    plugin.storage
      .rawHandle()
      .prepare("UPDATE scans SET started_at = ? WHERE id = 'newer'")
      .run(new Date(Date.now() + 60_000).toISOString());

    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'npm' && args[0] === 'outdated') {
        return { exitCode: 1, stdout: JSON.stringify({ lodash: { current: '4.17.20', latest: '4.17.21' } }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = (await getTool('deps_update_plan').handler({ project_path: project }, plugin)) as {
      ok: true;
      plan: Array<{ classification: string; cve_ids?: string[] }>;
    };
    expect(r.plan[0]?.classification).toBe('security');
    expect(r.plan[0]?.cve_ids).toEqual(['CVE-2024-XXX']);
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

  it('#7 (fix round 3) / A (fix round 4): npm+composer with NO pip present still surfaces a composer CVE — attributed to composer, naming the runner failure', async () => {
    // The coordinator's own probe: npm and composer present, pip absent —
    // laravel/framework has no runner of its own (composer has no CVE-map
    // sweep) and previously vanished from both plan and unplanned. Round 4:
    // it is DECLARED in composer.json, and `composer outdated` printed
    // nothing here, so the reason says the composer runner failed — not the
    // round 3 "no ecosystem runner found evidence for it", which was false.
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
      unplanned: Array<{ package_name: string; ecosystem: string; cve_ids: string[]; reason: string }>;
      runner_failures: Array<{ ecosystem: string; code: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(r.runner_failures).toEqual([expect.objectContaining({ ecosystem: 'composer', code: 'no_output' })]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({
      package_name: 'laravel/framework',
      ecosystem: 'composer',
      cve_ids: ['CVE-LARAVEL-2'],
    });
    expect(r.unplanned[0]?.reason).toMatch(/declared in composer\.json, but the composer runner failed/);
  });

  it('D (fix round 4): a pnpm store in node_modules/.pnpm makes it a pnpm project — no npm override is emitted for the transitive CVE', async () => {
    // Round 3 found the pnpm-resolved transitive `minimist` here and emitted
    // `npm pkg set overrides[minimist]=…` — which pnpm ignores (measured:
    // pnpm 10.33.2 still resolved minimist@0.0.8 with a top-level
    // "overrides"). It is still FOUND via the .pnpm store; it is now reported
    // with the pnpm fix instead of an npm command.
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
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-PNPM-1',
      package_name: 'minimist',
      installed_version: '0.0.8',
      fixed_version: '1.2.6',
    });
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      unsupported_ecosystems_present: string[];
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.plan).toEqual([]);
    expect(calls.some((c) => c.startsWith('npm'))).toBe(false);
    expect(r.unplanned).toEqual([
      expect.objectContaining({ package_name: 'minimist', ecosystem: 'npm', reason: expect.stringMatching(/pnpm project \(node_modules\/\.pnpm\)/) }),
    ]);
    expect(r.unplanned[0]?.reason).toContain('"pnpm": { "overrides": { "minimist": "1.2.6" } }');
    expect(r.unplanned[0]?.reason).toContain('pnpm install --ignore-scripts');
    expect(r.unsupported_ecosystems_present).toContain('pnpm');
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

  it('fix round 4: a [project] header followed by a TOML comment still opens the table (reviewer crlf.mjs "header comment")', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'pyproject.toml'),
      '[project] # main\r\nname = "x"\r\ndependencies = ["django==4.2.0"]\r\n',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-D', package_name: 'django', installed_version: '4.2.0', fixed_version: '4.2.5' });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ package_name: string; latest_version: string }>; unplanned: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan.map((s) => [s.package_name, s.latest_version])).toEqual([['django', '4.2.5']]);
    expect(r.unplanned).toEqual([]);
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

  it('item 8 (fix round 3) / A (fix round 4): a failed restore never reaches dotnet list, and is reported in runner_failures with its NuGet code', async () => {
    const project = tempProject();
    writeFileSync(
      project + '/Test.csproj',
      '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'GHSA-5crp-9r3c-p9vr',
      package_name: 'Newtonsoft.Json',
      installed_version: '12.0.1',
      fixed_version: '13.0.1',
    });
    let listCalled = false;
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        return {
          exitCode: 1,
          stdout:
            'C:\\p\\Test.csproj : error NU1004: The package reference Newtonsoft.Json version has changed from [12.0.1, ) to [12.0.3, ). [C:\\p\\Test.csproj]',
          stderr: '',
        };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        listCalled = true;
        return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      runner_failures: Array<{ ecosystem: string; code: string; target?: string; reason: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(listCalled).toBe(false);
    expect(r.plan).toEqual([]);
    expect(r.runner_failures).toEqual([
      expect.objectContaining({ ecosystem: 'dotnet', code: 'NU1004', target: 'Test.csproj' }),
    ]);
    expect(r.runner_failures[0]?.reason).toMatch(/out of sync/);
    // Reviewer finding #8: the catch-all used to say "no ecosystem runner …
    // found evidence" for this package, which is declared right there in the
    // .csproj — the runner FAILED.
    expect(r.unplanned).toEqual([
      expect.objectContaining({ package_name: 'Newtonsoft.Json', ecosystem: 'dotnet' }),
    ]);
    expect(r.unplanned[0]?.reason).toMatch(/declared in Test\.csproj, but the dotnet runner failed/);
    expect(r.unplanned[0]?.reason).toMatch(/NU1004/);
  });

  it('A (fix round 4): an unreachable feed (NU1301) is told apart from an out-of-sync lock', async () => {
    const project = tempProject();
    writeFileSync(project + '/Test.csproj', '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        return {
          exitCode: 1,
          stdout: '',
          stderr: 'C:\\p\\Test.csproj : error NU1301: Unable to load the service index for source https://pkgs.example/index.json.',
        };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ runner_failures: Array<{ code: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.runner_failures).toHaveLength(1);
    expect(r.runner_failures[0]?.code).toBe('NU1301');
    expect(r.runner_failures[0]?.reason).toMatch(/feed could not be reached/);
    expect(r.runner_failures[0]?.reason).not.toMatch(/out of sync/);
  });

  it('C (fix round 4): a floating reference (requested "2.*", resolved "2.12.0") is planned — one such reference no longer empties the whole .NET plan', async () => {
    // Reviewer's floatplan.mjs P2, against a real SDK: `Serilog 2.*` next to
    // an exact, vulnerable Newtonsoft.Json made the round 3 mismatch check
    // return [] for the WHOLE target — the Newtonsoft security step vanished.
    const project = tempProject();
    writeFileSync(project + '/Test.csproj', '<Project></Project>', 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') return { exitCode: 0, stdout: '', stderr: '' };
      if (cmd === 'dotnet' && args[0] === 'list') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            projects: [
              {
                frameworks: [
                  {
                    topLevelPackages: [
                      { id: 'Newtonsoft.Json', requestedVersion: '12.0.1', resolvedVersion: '12.0.1', latestVersion: '13.0.4' },
                      { id: 'Serilog', requestedVersion: '2.*', resolvedVersion: '2.12.0', latestVersion: '4.4.0' },
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

    const r = okResult<{ plan: Array<{ package_name: string; installed_version: string }>; runner_failures: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan.map((s) => [s.package_name, s.installed_version]).sort()).toEqual([
      ['Newtonsoft.Json', '12.0.1'],
      ['Serilog', '2.12.0'],
    ]);
    expect(r.runner_failures).toEqual([]);
  });

  it('E (fix round 4): every restore passes --locked-mode, per target, and the false property only where no lock exists', async () => {
    // A root-level .csproj plus a second project in a subdirectory with its
    // own lock: two targets (no solution), two restores. Round 3 passed
    // `--locked-mode` only when SOME lock existed somewhere, and a plain
    // restore otherwise — which creates a lock for a project that opts in.
    const project = tempProject();
    writeFileSync(join(project, 'Root.csproj'), '<Project></Project>', 'utf8');
    mkdirSync(join(project, 'src', 'Proj'), { recursive: true });
    writeFileSync(join(project, 'src', 'Proj', 'Proj.csproj'), '<Project></Project>', 'utf8');
    writeFileSync(join(project, 'src', 'Proj', 'packages.lock.json'), '{}', 'utf8');
    const plugin = makePlugin(project);
    const restoreCalls: string[][] = [];
    const listCalls: string[][] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') {
        restoreCalls.push(args);
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      if (cmd === 'dotnet' && args[0] === 'list') {
        listCalls.push(args);
        return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    await getTool('deps_update_plan').handler({ project_path: project }, plugin);
    expect(restoreCalls).toHaveLength(2);
    for (const args of restoreCalls) expect(args).toContain('--locked-mode');
    const rootRestore = restoreCalls.find((a) => a[1]?.endsWith('Root.csproj'));
    const projRestore = restoreCalls.find((a) => a[1]?.endsWith('Proj.csproj'));
    expect(rootRestore).toContain('-p:RestorePackagesWithLockFile=false');
    expect(projRestore).not.toContain('-p:RestorePackagesWithLockFile=false');
    // Each listing is scoped to its own target and never restores on its own.
    expect(listCalls).toHaveLength(2);
    for (const args of listCalls) {
      expect(args[1]).toMatch(/\.csproj$/);
      expect(args).toContain('--no-restore');
    }
  });

  it('E (fix round 4): a lock below a solution is found from the solution list, not a depth-limited walk', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'Root.sln'),
      [
        'Microsoft Visual Studio Solution File, Format Version 12.00',
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "src\\a\\b\\c\\App\\App.csproj", "{22222222-2222-2222-2222-222222222222}"',
        'EndProject',
      ].join('\r\n'),
      'utf8',
    );
    mkdirSync(join(project, 'src', 'a', 'b', 'c', 'App'), { recursive: true });
    writeFileSync(join(project, 'src', 'a', 'b', 'c', 'App', 'App.csproj'), '<Project></Project>', 'utf8');
    writeFileSync(join(project, 'src', 'a', 'b', 'c', 'App', 'packages.lock.json'), '{}', 'utf8');
    const plugin = makePlugin(project);
    const restoreCalls: string[][] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'dotnet' && args[0] === 'restore') restoreCalls.push(args);
      if (cmd === 'dotnet' && args[0] === 'list') return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    await getTool('deps_update_plan').handler({ project_path: project }, plugin);
    expect(restoreCalls).toHaveLength(1);
    expect(restoreCalls[0]?.[1]).toMatch(/Root\.sln$/);
    expect(restoreCalls[0]).toContain('--locked-mode');
    expect(restoreCalls[0]).not.toContain('-p:RestorePackagesWithLockFile=false');
  });

  it('A (fix round 4): catch-all reasons — declared but not listed by a runner that worked, vs declared nowhere', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'monolog/monolog': '^2.0' } }), 'utf8');
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-MONO', package_name: 'monolog/monolog', installed_version: '2.0.0', fixed_version: '2.1.0' },
      { cve_id: 'CVE-GHOST', package_name: 'ghost-lib', installed_version: '1.0.0', fixed_version: '1.0.1' },
    ]);
    vi.mocked(execa).mockImplementation((async (cmd: string) => {
      if (cmd === 'composer') return { exitCode: 0, stdout: JSON.stringify({ installed: [] }), stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      runner_failures: unknown[];
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.runner_failures).toEqual([]);
    const mono = r.unplanned.find((u) => u.package_name === 'monolog/monolog');
    const ghost = r.unplanned.find((u) => u.package_name === 'ghost-lib');
    expect(mono?.ecosystem).toBe('composer');
    expect(mono?.reason).toMatch(/declared in composer\.json, but the composer runner only plans what `composer outdated` lists/);
    expect(mono?.reason).toMatch(/2\.1\.0/);
    expect(ghost?.ecosystem).toBe('unknown');
    expect(ghost?.reason).toMatch(/^no manifest declares it and no runner listed it/);
  });

  it('A (fix round 4): a runner that cannot start (composer not installed) is a runner failure, not an empty plan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'laravel/framework': '^8.0' } }), 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, {
      cve_id: 'CVE-LARAVEL-3',
      package_name: 'laravel/framework',
      installed_version: '8.0.0',
      fixed_version: '8.22.1',
    });
    vi.mocked(execa).mockImplementation((async (cmd: string) => {
      // execa with reject:false, command not on PATH: no exit code at all.
      if (cmd === 'composer') return { exitCode: undefined, failed: true, code: 'ENOENT', shortMessage: 'spawn composer ENOENT', stdout: '', stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      unplanned: Array<{ ecosystem: string; reason: string }>;
      runner_failures: Array<{ ecosystem: string; code: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.runner_failures).toEqual([expect.objectContaining({ ecosystem: 'composer', code: 'not_installed' })]);
    expect(r.unplanned[0]?.ecosystem).toBe('composer');
    expect(r.unplanned[0]?.reason).toMatch(/composer runner failed/);
  });

  it('B (fix round 4): a DIRECT dependency already at latest, with a stale CVE, is already_fixed — the version comes from package-lock.json', async () => {
    // Reviewer's atlatest.mjs: minimist@1.2.8 installed and current, CVE
    // row recorded against 0.0.8 with its fix in 1.2.6. `npm outdated` does
    // not list a package at latest, so round 3 reported "a direct dependency
    // that `npm outdated` did not report" instead of already_fixed.
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"minimist":"1.2.8"}}', 'utf8');
    writeFileSync(
      join(project, 'package-lock.json'),
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: { '': { name: 'x', dependencies: { minimist: '1.2.8' } }, 'node_modules/minimist': { version: '1.2.8' } },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-STALE', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '{}', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[]; unplanned: Array<{ package_name: string; ecosystem: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({ package_name: 'minimist', ecosystem: 'npm' });
    expect(r.unplanned[0]?.reason).toMatch(/^already_fixed: installed version 1\.2\.8/);
  });

  it('B (fix round 4): a DIRECT dependency below its fix that `npm outdated` could not report (registry error) still gets the minimum-fix install step', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"minimist":"^1.2.0"}}', 'utf8');
    mkdirSync(join(project, 'node_modules', 'minimist'), { recursive: true });
    writeFileSync(join(project, 'node_modules', 'minimist', 'package.json'), '{"name":"minimist","version":"1.2.5"}', 'utf8');
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-MM', package_name: 'minimist', installed_version: '1.2.5', fixed_version: '1.2.6' });
    vi.mocked(execa).mockImplementation((async () => ({
      exitCode: 1,
      stdout: JSON.stringify({ error: { code: 'ENOTFOUND', summary: 'request to https://registry.npmjs.org/minimist failed' } }),
      stderr: '',
    })) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ package_name: string; installed_version: string; latest_version: string; classification: string; upgrade_command: string }>;
      runner_failures: Array<{ ecosystem: string; code: string }>;
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(r.runner_failures).toEqual([expect.objectContaining({ ecosystem: 'npm', code: 'ENOTFOUND' })]);
    expect(r.plan).toEqual([
      expect.objectContaining({
        package_name: 'minimist',
        installed_version: '1.2.5',
        latest_version: '1.2.6',
        classification: 'security',
        upgrade_command: 'npm install minimist@1.2.6 --ignore-scripts',
      }),
    ]);
  });

  it('B (fix round 4): a TRANSITIVE dependency whose every resolved copy is past the fix is already_fixed, not an override', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"mkdirp":"1.0.4"}}', 'utf8');
    writeFileSync(
      join(project, 'package-lock.json'),
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: {
          '': { name: 'x', dependencies: { mkdirp: '1.0.4' } },
          'node_modules/mkdirp': { version: '1.0.4' },
          'node_modules/minimist': { version: '1.2.8' },
        },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-OLD', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '{}', stderr: '' })) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[]; unplanned: Array<{ package_name: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toEqual([expect.objectContaining({ package_name: 'minimist', reason: expect.stringMatching(/^already_fixed/) })]);
  });

  it('D (fix round 4): a pnpm-lock.yaml project gets NO npm command — npm outdated is not even run — and the transitive CVE carries the pnpm.overrides fix', async () => {
    // Reviewer's plan2.mjs on a real pnpm install: round 3 emitted
    // `npm pkg set overrides[minimist]=1.2.6` + `npm install --ignore-scripts`
    // labelled security (and an ordinary `npm install mkdirp@3.0.1`).
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"mkdirp":"0.5.1"}}', 'utf8');
    writeFileSync(
      join(project, 'pnpm-lock.yaml'),
      [
        "lockfileVersion: '9.0'",
        '',
        'importers:',
        '',
        '  .:',
        '    dependencies:',
        '      mkdirp:',
        '        specifier: 0.5.1',
        '        version: 0.5.1',
        '',
        'packages:',
        '',
        '  minimist@0.0.8:',
        '    resolution: {integrity: sha512-x}',
        '',
        '  mkdirp@0.5.1:',
        '    resolution: {integrity: sha512-y}',
        '',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-MM', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' });
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 1, stdout: JSON.stringify({ mkdirp: { current: '0.5.1', latest: '3.0.1' } }), stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: Array<{ upgrade_command: string }>;
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      unsupported_ecosystems_present: string[];
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(calls.filter((c) => c !== 'pnpm --version')).toEqual([]); // asking pnpm its version is allowed (R7-I5)
    expect(r.plan).toEqual([]);
    expect(r.unplanned).toHaveLength(1);
    expect(r.unplanned[0]).toMatchObject({ package_name: 'minimist', ecosystem: 'npm' });
    expect(r.unplanned[0]?.reason).toMatch(/^pnpm project \(pnpm-lock\.yaml\)/);
    expect(r.unplanned[0]?.reason).toContain('"pnpm": { "overrides": { "minimist": "1.2.6" } }');
    expect(r.unsupported_ecosystems_present).toContain('pnpm');
  });

  it('D (fix round 4): a yarn.lock project gets NO npm command — a direct CVE carries the yarn resolutions fix; a copy past the fix is already_fixed', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"lodash":"^4.17.0","minimist":"^1.2.0"}}', 'utf8');
    writeFileSync(
      join(project, 'yarn.lock'),
      [
        '# yarn lockfile v1',
        '',
        'lodash@^4.17.0:',
        '  version "4.17.20"',
        '',
        'minimist@^1.2.0, minimist@^1.2.5:',
        '  version "1.2.8"',
        '',
      ].join('\n'),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-LODASH', package_name: 'lodash', installed_version: '4.17.20', fixed_version: '4.17.21' },
      { cve_id: 'CVE-MM', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' },
    ]);
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; reason: string }>;
      unsupported_ecosystems_present: string[];
    }>(await getTool('deps_update_plan').handler({ project_path: project }, plugin));
    expect(calls).toEqual([]);
    expect(r.plan).toEqual([]);
    const lodash = r.unplanned.find((u) => u.package_name === 'lodash');
    const minimist = r.unplanned.find((u) => u.package_name === 'minimist');
    expect(lodash?.reason).toMatch(/^yarn project \(yarn\.lock\)/);
    expect(lodash?.reason).toContain('"resolutions": { "lodash": "4.17.21" }');
    expect(lodash?.reason).toContain('raise the "lodash" range in package.json to 4.17.21');
    expect(minimist?.reason).toMatch(/^already_fixed: installed version 1\.2\.8/);
    expect(r.unsupported_ecosystems_present).toContain('yarn');
  });

  // -------------------------------------------------------------- fix round 5

  it('fix round 5 (1): a transitive package in composer.lock is composer\'s — already_fixed when the lock is past the fix, never "unknown"', async () => {
    // Reviewer's probes4/comp.mjs: a real `composer install` of monolog 3
    // locks psr/log 3.0.2; a CVE fixed in 3.0.1 was reported `unknown` with
    // "no manifest, lockfile or outdated listing in this project mentions it".
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'monolog/monolog': '^3.0' } }), 'utf8');
    writeFileSync(
      join(project, 'composer.lock'),
      JSON.stringify({
        packages: [
          { name: 'monolog/monolog', version: '3.9.0' },
          { name: 'psr/log', version: '3.0.2' },
        ],
        'packages-dev': [{ name: 'guzzle/dev-only', version: '1.0.0' }],
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-PSR', package_name: 'psr/log', installed_version: '3.0.0', fixed_version: '3.0.1' },
      { cve_id: 'CVE-DEV', package_name: 'guzzle/dev-only', installed_version: '1.0.0', fixed_version: '1.0.1' },
    ]);
    vi.mocked(execa).mockImplementation((async (cmd: string) => {
      if (cmd === 'composer') return { exitCode: 0, stdout: JSON.stringify({ installed: [] }), stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ unplanned: Array<{ package_name: string; ecosystem: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    const psr = r.unplanned.find((u) => u.package_name === 'psr/log');
    const dev = r.unplanned.find((u) => u.package_name === 'guzzle/dev-only');
    expect(psr?.ecosystem).toBe('composer');
    expect(psr?.reason).toMatch(/^already_fixed: installed version 3\.0\.2 \(composer\.lock\)/);
    expect(dev?.ecosystem).toBe('composer');
    expect(dev?.reason).toMatch(/^resolved in composer\.lock at 1\.0\.0 as a transitive dependency/);
    expect(dev?.reason).toMatch(/1\.0\.1/);
  });

  it('fix round 5 (1): Cargo.lock, go.mod/go.sum, Gemfile.lock and a NuGet packages.lock.json attribute packages to their own ecosystem', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Cargo.toml'), '[package]\nname = "app"\n\n[dependencies]\nserde = "1"\n', 'utf8');
    writeFileSync(
      join(project, 'Cargo.lock'),
      ['version = 3', '', '[[package]]', 'name = "smallvec"', 'version = "1.6.0"', '', '[[package]]', 'name = "time"', 'version = "0.3.36"', ''].join('\n'),
      'utf8',
    );
    writeFileSync(
      join(project, 'go.mod'),
      ['module example.com/app', '', 'go 1.22', '', 'require (', '\tgolang.org/x/net v0.23.0 // indirect', ')', ''].join('\n'),
      'utf8',
    );
    writeFileSync(
      join(project, 'go.sum'),
      [
        'golang.org/x/net v0.10.0/go.mod h1:aaa=',
        'golang.org/x/net v0.23.0 h1:bbb=',
        'golang.org/x/text v0.3.0 h1:ccc=',
        'golang.org/x/text v0.3.0/go.mod h1:ddd=',
      ].join('\n'),
      'utf8',
    );
    writeFileSync(join(project, 'Gemfile'), "source 'https://rubygems.org'\ngem 'rails'\n", 'utf8');
    writeFileSync(
      join(project, 'Gemfile.lock'),
      ['GEM', '  remote: https://rubygems.org/', '  specs:', '    rack (2.2.3)', '    rails (7.0.4)', '      rack (>= 2.2.0)', '', 'PLATFORMS', '  ruby', ''].join('\n'),
      'utf8',
    );
    writeFileSync(join(project, 'App.csproj'), '<Project><ItemGroup><PackageReference Include="Serilog" Version="2.*" /></ItemGroup></Project>', 'utf8');
    writeFileSync(
      join(project, 'packages.lock.json'),
      JSON.stringify({
        version: 1,
        dependencies: {
          'net8.0': {
            Serilog: { type: 'Direct', requested: '[2.*, )', resolved: '2.12.0' },
            'System.Text.Encodings.Web': { type: 'Transitive', resolved: '4.5.0' },
          },
        },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    seedCves(plugin, project, 'scan1', [
      { cve_id: 'CVE-SV', package_name: 'smallvec', installed_version: '1.6.0', fixed_version: '1.6.1' },
      { cve_id: 'CVE-TIME', package_name: 'time', installed_version: '0.1.0', fixed_version: '0.2.23' },
      { cve_id: 'CVE-NET', package_name: 'golang.org/x/net', installed_version: '0.10.0', fixed_version: '0.23.0' },
      { cve_id: 'CVE-TEXT', package_name: 'golang.org/x/text', installed_version: '0.3.0', fixed_version: '0.3.8' },
      { cve_id: 'CVE-RACK', package_name: 'rack', installed_version: '2.2.3', fixed_version: '2.2.8' },
      { cve_id: 'CVE-STE', package_name: 'System.Text.Encodings.Web', installed_version: '4.5.0', fixed_version: '4.5.1' },
    ]);
    // Every runner works and lists nothing outdated; the .NET restore/list succeed.
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      if (cmd === 'cargo') return { exitCode: 0, stdout: JSON.stringify({ dependencies: [] }), stderr: '' };
      if (cmd === 'dotnet' && args[0] === 'list') return { exitCode: 0, stdout: JSON.stringify({ projects: [] }), stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ unplanned: Array<{ package_name: string; ecosystem: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    const by = (n: string) => r.unplanned.find((u) => u.package_name === n);
    expect(by('smallvec')).toMatchObject({ ecosystem: 'cargo', reason: expect.stringMatching(/^resolved in Cargo\.lock at 1\.6\.0 as a transitive dependency/) });
    expect(by('time')).toMatchObject({ ecosystem: 'cargo', reason: expect.stringMatching(/^already_fixed: installed version 0\.3\.36/) });
    // go.mod's selected version decides, not the older go.sum `/go.mod` line.
    expect(by('golang.org/x/net')).toMatchObject({ ecosystem: 'go', reason: expect.stringMatching(/^already_fixed: installed version v0\.23\.0/) });
    expect(by('golang.org/x/text')).toMatchObject({ ecosystem: 'go', reason: expect.stringMatching(/^resolved in go\.sum at v0\.3\.0/) });
    expect(by('rack')).toMatchObject({ ecosystem: 'rubygems', reason: expect.stringMatching(/^resolved in Gemfile\.lock at 2\.2\.3/) });
    expect(by('System.Text.Encodings.Web')).toMatchObject({
      ecosystem: 'dotnet',
      reason: expect.stringMatching(/^resolved in packages\.lock\.json at 4\.5\.0 as a transitive dependency/),
    });
    expect(r.unplanned.some((u) => u.ecosystem === 'unknown')).toBe(false);
  });

  it('fix round 5 (2): the description says only npm/pip target the minimum fixed version', () => {
    const description = getTool('deps_update_plan').description;
    expect(description).toContain('npm/pip target the MINIMUM fixed version, other stacks the latest available');
    expect(description).not.toMatch(/security \(minimum CVE-fixed version/);
    expect(description.length).toBeLessThanOrEqual(1500);
  });

  /** A pnpm workspace: root package.json + pnpm-workspace.yaml + the ONE
   *  root pnpm-lock.yaml, and a member under packages/web with no lock of
   *  its own — what `pnpm install` at the root really produces. */
  function pnpmWorkspace(): { root: string; member: string } {
    const root = tempProject();
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, 'package.json'), '{"name":"root","private":true}', 'utf8');
    writeFileSync(join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n", 'utf8');
    writeFileSync(
      join(root, 'pnpm-lock.yaml'),
      [
        "lockfileVersion: '9.0'",
        '',
        'importers:',
        '',
        '  .: {}',
        '',
        '  packages/web:',
        '    dependencies:',
        '      mkdirp:',
        '        specifier: 0.5.1',
        '        version: 0.5.1',
        '',
        'packages:',
        '',
        '  minimist@0.0.8:',
        '    resolution: {integrity: sha512-x}',
        '',
        '  mkdirp@0.5.1:',
        '    resolution: {integrity: sha512-y}',
        '',
      ].join('\n'),
      'utf8',
    );
    const member = join(root, 'packages', 'web');
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, 'package.json'), '{"name":"web","dependencies":{"mkdirp":"0.5.1"}}', 'utf8');
    return { root, member };
  }

  it('fix round 5 (3): a pnpm workspace MEMBER gets no npm command — the root lock decides, and the fix names the ROOT package.json', async () => {
    // Reviewer's probes4/ws.mjs: project_path = packages/web inside a pnpm
    // workspace got `npm install mkdirp@0.5.6 --ignore-scripts`.
    const { member } = pnpmWorkspace();
    const plugin = makePlugin(member);
    seedCves(plugin, member, 'scan1', [
      { cve_id: 'CVE-MM', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' },
      { cve_id: 'CVE-MK', package_name: 'mkdirp', installed_version: '0.5.1', fixed_version: '0.5.6' },
    ]);
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 1, stdout: JSON.stringify({ mkdirp: { current: '0.5.1', latest: '3.0.1' } }), stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{
      plan: unknown[];
      unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      unsupported_ecosystems_present: string[];
    }>(await getTool('deps_update_plan').handler({ project_path: member }, plugin));
    expect(calls.filter((c) => c !== 'pnpm --version')).toEqual([]); // asking pnpm its version is allowed (R7-I5)
    expect(r.plan).toEqual([]);
    expect(r.unsupported_ecosystems_present).toContain('pnpm');
    const minimist = r.unplanned.find((u) => u.package_name === 'minimist');
    const mkdirp = r.unplanned.find((u) => u.package_name === 'mkdirp');
    // minimist is resolved only in the ROOT lock — found through it.
    expect(minimist?.reason).toMatch(/^pnpm project \(\.\.\/\.\.\/pnpm-lock\.yaml, the workspace root\)/);
    expect(minimist?.reason).toContain('to the workspace root package.json (../../package.json)');
    expect(minimist?.reason).toContain('pnpm install --ignore-scripts at the workspace root');
    expect(mkdirp?.reason).toContain('raise the "mkdirp" range in package.json to 0.5.6');
  });

  it('fix round 5 (3): a yarn workspace member is yarn — resolutions go in the root package.json', async () => {
    const root = tempProject();
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, 'package.json'), '{"name":"root","private":true,"workspaces":["packages/*"]}', 'utf8');
    writeFileSync(join(root, 'yarn.lock'), ['# yarn lockfile v1', '', 'lodash@^4.17.0:', '  version "4.17.20"', ''].join('\n'), 'utf8');
    const member = join(root, 'packages', 'api');
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, 'package.json'), '{"name":"api","dependencies":{"lodash":"^4.17.0"}}', 'utf8');
    const plugin = makePlugin(member);
    seedCve(plugin, member, { cve_id: 'CVE-L', package_name: 'lodash', installed_version: '4.17.20', fixed_version: '4.17.21' });
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: unknown[]; unplanned: Array<{ package_name: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: member }, plugin),
    );
    expect(calls).toEqual([]);
    expect(r.plan).toEqual([]);
    expect(r.unplanned[0]?.reason).toMatch(/^yarn project \(\.\.\/\.\.\/yarn\.lock, the workspace root\)/);
    expect(r.unplanned[0]?.reason).toContain('"resolutions": { "lodash": "4.17.21" } to the workspace root package.json (../../package.json)');
  });

  it('fix round 5 (3): the walk stops at the repository root — a pnpm lock ABOVE the .git directory does not make the project pnpm', async () => {
    const outer = tempProject();
    writeFileSync(join(outer, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n", 'utf8');
    const repo = join(outer, 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(join(repo, 'package.json'), '{"name":"x","dependencies":{"lodash":"4.17.20"}}', 'utf8');
    const plugin = makePlugin(repo);
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 1, stdout: JSON.stringify({ lodash: { current: '4.17.20', latest: '4.17.21' } }), stderr: '' };
    }) as unknown as typeof execa);

    const r = okResult<{ plan: Array<{ upgrade_command: string }>; unsupported_ecosystems_present: string[] }>(
      await getTool('deps_update_plan').handler({ project_path: repo }, plugin),
    );
    expect(calls).toEqual(['npm outdated --json']);
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.21 --ignore-scripts');
    expect(r.unsupported_ecosystems_present).not.toContain('pnpm');
  });

  /** An npm project with no `.git` anywhere above it — the walk has no
   *  repository root to stop at. */
  async function planWithoutGit(project: string): Promise<{
    calls: string[];
    r: { plan: Array<{ upgrade_command: string }>; unplanned: Array<{ reason: string }>; unsupported_ecosystems_present: string[] };
  }> {
    const plugin = makePlugin(project);
    seedCve(plugin, project, { cve_id: 'CVE-L', package_name: 'lodash', installed_version: '4.17.20', fixed_version: '4.17.21' });
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      return { exitCode: 1, stdout: JSON.stringify({ lodash: { current: '4.17.20', latest: '4.17.21' } }), stderr: '' };
    }) as unknown as typeof execa);
    const r = okResult<{ plan: Array<{ upgrade_command: string }>; unplanned: Array<{ reason: string }>; unsupported_ecosystems_present: string[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    return { calls, r };
  }

  it('Task 11 fix round 1: run on a worktree of a project, it plans against the ORIGIN project\'s CVE history', async () => {
    // create_fix_pr runs the plan in a disposable checkout of HEAD, so the
    // plan's installed versions and pip files match what the fix edits and
    // nothing runs in the user's tree — while the CVEs are the project's own.
    const origin = tempProject();
    const worktree = tempProject();
    for (const dir of [origin, worktree]) {
      writeFileSync(join(dir, 'requirements.txt'), 'requests==2.31.0\n', 'utf8');
    }
    const plugin = makePlugin(origin);
    seedCve(plugin, origin, { cve_id: 'CVE-R', package_name: 'requests', installed_version: '2.31.0', fixed_version: '2.32.0' });
    vi.mocked(execa).mockImplementation((async () => ({ exitCode: 0, stdout: '', stderr: '' })) as unknown as typeof execa);

    const bare = okResult<{ plan: unknown[] }>(await getTool('deps_update_plan').handler({ project_path: worktree }, plugin));
    expect(bare.plan).toEqual([]);
    const r = okResult<{ plan: Array<{ package_name: string; file?: string; latest_version: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: worktree }, plugin, { originProjectPath: origin }),
    );
    expect(r.plan).toEqual([expect.objectContaining({ package_name: 'requests', file: 'requirements.txt', latest_version: '2.32.0' })]);
  });

  it('Task 11 fix round 1: on a fresh checkout (no node_modules) npm outdated gives no "current" — the lockfile\'s version stands in', async () => {
    // create_fix_pr now plans on a disposable checkout of HEAD, which has a
    // lockfile and no node_modules. Measured (npm 11): `npm outdated --json`
    // then omits `current` — with or without --package-lock-only — and the
    // direct dependency got no step at all unless a CVE row covered it.
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"lodash":"4.17.20"}}', 'utf8');
    writeFileSync(
      join(project, 'package-lock.json'),
      JSON.stringify({
        name: 'x',
        lockfileVersion: 3,
        packages: { '': { name: 'x', dependencies: { lodash: '4.17.20' } }, 'node_modules/lodash': { version: '4.17.20' } },
      }),
      'utf8',
    );
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async () => ({
      exitCode: 1,
      stdout: JSON.stringify({ lodash: { wanted: '4.17.20', latest: '4.18.1', dependent: 'x' } }),
      stderr: '',
    })) as unknown as typeof execa);
    const r = okResult<{ plan: Array<{ package_name: string; installed_version: string; upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.plan).toEqual([
      expect.objectContaining({ package_name: 'lodash', installed_version: '4.17.20', upgrade_command: 'npm install lodash@4.18.1 --ignore-scripts' }),
    ]);
  });

  it('Task 11 fix round 2: composer plans from the LOCK file (--locked) — a fresh checkout has no vendor/', async () => {
    // Measured, Composer 2.10.2, no vendor/: `composer outdated --format=json`
    // prints `[]` (exit 0, "No dependencies installed") and every Composer
    // step vanished; `--locked` lists the lock's packages with their latest.
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'psr/log': '1.0.0' } }), 'utf8');
    writeFileSync(join(project, 'composer.lock'), JSON.stringify({ packages: [{ name: 'psr/log', version: '1.0.0' }] }), 'utf8');
    const plugin = makePlugin(project);
    const calls: string[] = [];
    vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
      calls.push([cmd, ...args].join(' '));
      if (cmd === 'composer' && args.includes('--locked')) {
        return { exitCode: 0, stdout: JSON.stringify({ locked: [{ name: 'psr/log', version: '1.0.0', latest: '3.0.2' }] }), stderr: '' };
      }
      if (cmd === 'composer') return { exitCode: 0, stdout: '[]', stderr: 'No dependencies installed. Try running composer install or update.' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);
    const r = okResult<{ plan: Array<{ package_name: string; installed_version: string; latest_version: string }>; runner_failures: unknown[] }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(calls).toContain('composer outdated --locked --format=json');
    expect(r.plan).toEqual([expect.objectContaining({ package_name: 'psr/log', installed_version: '1.0.0', latest_version: '3.0.2' })]);
    expect(r.runner_failures).toEqual([]);
  });

  it('Task 11 fix round 2: composer saying "No dependencies installed" is a runner failure, never an empty plan', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'psr/log': '1.0.0' } }), 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async (cmd: string) =>
      cmd === 'composer'
        ? { exitCode: 0, stdout: '[]', stderr: 'No dependencies installed. Try running composer install or update.' }
        : { exitCode: 0, stdout: '', stderr: '' }) as unknown as typeof execa);
    const r = okResult<{ runner_failures: Array<{ ecosystem: string; reason: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    expect(r.runner_failures).toEqual([expect.objectContaining({ ecosystem: 'composer', reason: expect.stringContaining('No dependencies installed') })]);
  });

  it('Task 11 fix round 1: a Ruby step only re-locks (bundle lock --update) — never bundle update, which installs gems into the host', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Gemfile'), "source 'https://rubygems.org'\ngem 'rack'\n", 'utf8');
    const plugin = makePlugin(project);
    vi.mocked(execa).mockImplementation((async (cmd: string) => {
      if (cmd === 'bundle') return { exitCode: 1, stdout: 'rack (newest 3.1.8, installed 2.2.3)\n', stderr: '' };
      return { exitCode: 0, stdout: '', stderr: '' };
    }) as unknown as typeof execa);
    const r = okResult<{ plan: Array<{ package_name: string; upgrade_command: string }> }>(
      await getTool('deps_update_plan').handler({ project_path: project }, plugin),
    );
    const rack = r.plan.find((s) => s.package_name === 'rack');
    expect(rack?.upgrade_command).toBe('bundle lock --update rack');
  });

  it('Task 11 item 9: with no .git above it, a stray pnpm/yarn lock in an unrelated ancestor does not flip an npm project', async () => {
    const outer = tempProject();
    writeFileSync(join(outer, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n", 'utf8');
    writeFileSync(join(outer, 'yarn.lock'), '# yarn lockfile v1\n', 'utf8');
    const project = join(outer, 'somewhere', 'proj');
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"lodash":"4.17.20"}}', 'utf8');

    const { calls, r } = await planWithoutGit(project);
    expect(calls).toEqual(['npm outdated --json']);
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.21 --ignore-scripts');
    expect(r.unsupported_ecosystems_present).not.toContain('pnpm');
    expect(r.unsupported_ecosystems_present).not.toContain('yarn');
  });

  it('Task 11 item 9: with no .git, an ancestor workspace whose globs do NOT include the project is not its workspace', async () => {
    const outer = tempProject();
    writeFileSync(join(outer, 'package.json'), '{"name":"root","private":true}', 'utf8');
    writeFileSync(join(outer, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n", 'utf8');
    writeFileSync(join(outer, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n", 'utf8');
    const project = join(outer, 'tools', 'proj');
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"lodash":"4.17.20"}}', 'utf8');

    const { r } = await planWithoutGit(project);
    expect(r.plan[0]?.upgrade_command).toBe('npm install lodash@4.17.21 --ignore-scripts');
    expect(r.unsupported_ecosystems_present).not.toContain('pnpm');
  });

  it('Task 11 item 9: with no .git, a real pnpm workspace member (the globs include it) is still pnpm', async () => {
    const outer = tempProject();
    writeFileSync(join(outer, 'package.json'), '{"name":"root","private":true}', 'utf8');
    writeFileSync(join(outer, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/**'\n  - '!**/test/**'\n", 'utf8');
    writeFileSync(join(outer, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n", 'utf8');
    const project = join(outer, 'packages', 'web');
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, 'package.json'), '{"name":"web","dependencies":{"lodash":"4.17.20"}}', 'utf8');

    const { calls, r } = await planWithoutGit(project);
    expect(calls.filter((c) => c !== 'pnpm --version')).toEqual([]); // asking pnpm its version is allowed (R7-I5)
    expect(r.plan).toEqual([]);
    expect(r.unsupported_ecosystems_present).toContain('pnpm');
    expect(r.unplanned[0]?.reason).toMatch(/^pnpm project \(\.\.\/\.\.\/pnpm-workspace\.yaml, the workspace root\)|^pnpm project \(\.\.\/\.\.\/pnpm-lock\.yaml, the workspace root\)/);
  });

  it('Task 11 item 9: with no .git, a real yarn workspace member (root package.json workspaces include it) is still yarn', async () => {
    const outer = tempProject();
    writeFileSync(join(outer, 'package.json'), '{"name":"root","private":true,"workspaces":{"packages":["apps/*"]}}', 'utf8');
    writeFileSync(join(outer, 'yarn.lock'), '# yarn lockfile v1\n', 'utf8');
    const project = join(outer, 'apps', 'api');
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, 'package.json'), '{"name":"api","dependencies":{"lodash":"4.17.20"}}', 'utf8');

    const { calls, r } = await planWithoutGit(project);
    expect(calls).toEqual([]);
    expect(r.unsupported_ecosystems_present).toContain('yarn');
    expect(r.unplanned[0]?.reason).toMatch(/^yarn project \(\.\.\/\.\.\/yarn\.lock, the workspace root\)/);
  });

  /**
   * Review R7-I5: the advice was always `"pnpm": { "overrides" }` in
   * package.json, which pnpm 11 and later no longer read — measured with
   * pnpm 12.8.1: `[WARN] The "pnpm" field in package.json is no longer read
   * by pnpm. The following keys were ignored: "pnpm.overrides"`, and the
   * lock kept minimist@0.0.8. The mechanism follows the project's pnpm:
   *   - pnpm 10.5.0 added `pnpm.*` settings in pnpm-workspace.yaml ("The
   *     `pnpm.*` settings from `package.json` can now be specified in the
   *     `pnpm-workspace.yaml` file instead", #9121), and made its `packages`
   *     field optional — before, a pnpm-workspace.yaml without `packages`
   *     fails ("packages field missing or empty", measured on 9.15.9 and
   *     10.4.1);
   *   - pnpm 11.0.0 stopped reading the "pnpm" field ("pnpm no longer reads
   *     settings from the `pnpm` field of `package.json`", #10086).
   */
  describe('pnpm overrides follow the project’s pnpm version', () => {
    const LOCK_9 = "lockfileVersion: '9.0'\n\npackages:\n\n  minimist@0.0.8:\n    resolution: {integrity: sha512-x}\n";
    const LOCK_6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /minimist@0.0.8:\n    resolution: {integrity: sha512-x}\n";

    async function pnpmReason(opts: {
      packageManager?: string;
      lock: string;
      pnpmVersion?: string | null;
    }): Promise<{ reason: string; calls: string[] }> {
      const project = tempProject();
      const manifest: Record<string, unknown> = { name: 'x', dependencies: { mkdirp: '0.5.1' } };
      if (opts.packageManager !== undefined) manifest['packageManager'] = opts.packageManager;
      writeFileSync(join(project, 'package.json'), JSON.stringify(manifest), 'utf8');
      writeFileSync(join(project, 'pnpm-lock.yaml'), opts.lock, 'utf8');
      const plugin = makePlugin(project);
      seedCve(plugin, project, { cve_id: 'CVE-MM', package_name: 'minimist', installed_version: '0.0.8', fixed_version: '1.2.6' });
      const calls: string[] = [];
      vi.mocked(execa).mockImplementation((async (cmd: string, args: string[]) => {
        calls.push([cmd, ...args].join(' '));
        if (cmd === 'pnpm' && args[0] === '--version') {
          return opts.pnpmVersion === undefined || opts.pnpmVersion === null
            ? { exitCode: 1, stdout: '', stderr: 'pnpm: not found' }
            : { exitCode: 0, stdout: `${opts.pnpmVersion}\n`, stderr: '' };
        }
        return { exitCode: 1, stdout: '', stderr: '' };
      }) as unknown as typeof execa);
      const r = okResult<{ unplanned: Array<{ package_name: string; reason: string }> }>(
        await getTool('deps_update_plan').handler({ project_path: project }, plugin),
      );
      return { reason: r.unplanned.find((u) => u.package_name === 'minimist')?.reason ?? '', calls };
    }

    const YAML_FIX = 'add `overrides: { "minimist": "1.2.6" }` to pnpm-workspace.yaml';
    const JSON_FIX = 'add "pnpm": { "overrides": { "minimist": "1.2.6" } } to package.json';

    it('pnpm 12 from "packageManager": pnpm-workspace.yaml, never the ignored package.json field', async () => {
      const { reason, calls } = await pnpmReason({ packageManager: 'pnpm@12.8.1+sha512.abc', lock: LOCK_9 });
      expect(reason).toContain(YAML_FIX);
      expect(reason).not.toContain('"pnpm": { "overrides"');
      expect(reason).toContain('pnpm 12.8.1 (package.json "packageManager")');
      expect(calls.some((c) => c.startsWith('pnpm --version'))).toBe(false);
    });

    it('pnpm 10.5 or later: pnpm-workspace.yaml', async () => {
      const { reason } = await pnpmReason({ packageManager: 'pnpm@10.5.0', lock: LOCK_9 });
      expect(reason).toContain(YAML_FIX);
    });

    it('pnpm before 10.5 from "packageManager": package.json', async () => {
      const { reason } = await pnpmReason({ packageManager: 'pnpm@10.4.1', lock: LOCK_9 });
      expect(reason).toContain(JSON_FIX);
      expect(reason).not.toContain(YAML_FIX);
    });

    it('a lockfileVersion 6.0 (pnpm 8) decides without asking pnpm: package.json', async () => {
      const { reason, calls } = await pnpmReason({ lock: LOCK_6, pnpmVersion: '12.8.1' });
      expect(reason).toContain(JSON_FIX);
      expect(reason).toMatch(/pnpm-lock\.yaml lockfileVersion 6\.0/);
      expect(calls.some((c) => c.startsWith('pnpm --version'))).toBe(false);
    });

    it('lockfileVersion 9.0 (every pnpm since 9) asks `pnpm --version`', async () => {
      const { reason, calls } = await pnpmReason({ lock: LOCK_9, pnpmVersion: '12.8.1' });
      expect(calls).toContain('pnpm --version');
      expect(reason).toContain(YAML_FIX);
      expect(reason).toContain('pnpm 12.8.1 (`pnpm --version`)');
    });

    it('an unknown version names both, and where each applies', async () => {
      const { reason } = await pnpmReason({ lock: LOCK_9, pnpmVersion: null });
      expect(reason).toMatch(/pnpm version unknown/);
      expect(reason).toContain(YAML_FIX);
      expect(reason).toContain(JSON_FIX);
      expect(reason).toMatch(/pnpm 10\.5 or later.*before 10\.5/);
    });
  });
});
