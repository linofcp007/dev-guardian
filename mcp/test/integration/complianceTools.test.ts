/**
 * Integration tests for compliance_check and generate_sbom.
 *
 * compliance_check goes through the scan-tool factory → mock runProcess +
 * scannerAvailable. generate_sbom is standalone and also uses runProcess +
 * scannerAvailable. The Syft summariser is exercised against fixture data.
 */

import Database from 'better-sqlite3';
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

import { runProcess } from '../../src/runners/processRunner.js';
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
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'compliance-tools-'));
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

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('compliance_check', () => {
  it('summarises licenses by risk and surfaces risky_licenses', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) {
        const fxRaw = readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
        writeFileSync(path, fxRaw, 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('compliance_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      licenses_summary: { license: string; risk: string }[];
      risky_licenses: { license: string }[];
    };
    expect(r.ok).toBe(true);
    // Trivy fixture has AGPL-3.0-or-later → should be flagged as high risk.
    expect(r.risky_licenses.some((e) => /AGPL/i.test(e.license))).toBe(true);
  });

  it('detects PRIVACY.md, TERMS.md, and SECURITY.md at the project root', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'PRIVACY.md'), '# Privacy', 'utf8');
    writeFileSync(join(project, 'TERMS.md'), '# Terms', 'utf8');
    writeFileSync(join(project, 'SECURITY.md'), '# Security', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('compliance_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      policy_documents_found: {
        privacy_policy: boolean;
        terms_of_service: boolean;
        security_policy: boolean;
        cookie_policy: boolean;
        paths: string[];
      };
    };
    expect(r.ok).toBe(true);
    expect(r.policy_documents_found.privacy_policy).toBe(true);
    expect(r.policy_documents_found.terms_of_service).toBe(true);
    expect(r.policy_documents_found.security_policy).toBe(true);
    expect(r.policy_documents_found.cookie_policy).toBe(false);
    expect(r.policy_documents_found.paths.sort()).toEqual(['PRIVACY.md', 'SECURITY.md', 'TERMS.md']);
  });
});

describe('generate_sbom', () => {
  it('inlines the SBOM when below inline_max_kb (default 256)', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'syft' ? '/fake/bin/syft' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      // Syft is invoked with `-o cyclonedx-json=<outFile>`.
      const oFlag = opts.args?.find((a) => a.startsWith('cyclonedx-json='));
      if (oFlag) {
        const outFile = oFlag.replace('cyclonedx-json=', '');
        const fxRaw = readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8');
        writeFileSync(outFile, fxRaw, 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      format: string;
      produced_by: string;
      components_count: number;
      inline?: unknown;
      file_path: string;
    };
    expect(r.ok).toBe(true);
    expect(r.format).toBe('cyclonedx-json');
    expect(r.produced_by).toBe('syft');
    expect(r.components_count).toBe(3);
    expect(r.inline).toBeDefined();
  });

  it('omits inline when inline_max_kb is below the SBOM size', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'syft' ? '/fake/bin/syft' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const oFlag = opts.args?.find((a) => a.startsWith('cyclonedx-json='));
      if (oFlag) {
        const outFile = oFlag.replace('cyclonedx-json=', '');
        writeFileSync(outFile, readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8'), 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project, inline_max_kb: 0 }, plugin)) as {
      ok: true;
      inline?: unknown;
    };
    expect(r.ok).toBe(true);
    expect(r.inline).toBeUndefined();
  });

  it('falls back to Trivy when Syft is missing', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      // Trivy is invoked with `--output <outFile>`.
      const oIdx = opts.args?.findIndex((a) => a === '--output');
      const outFile = oIdx !== undefined && oIdx >= 0 ? opts.args?.[oIdx + 1] : undefined;
      if (outFile) {
        writeFileSync(outFile, readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8'), 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      produced_by: string;
    };
    expect(r.ok).toBe(true);
    expect(r.produced_by).toBe('trivy');
  });

  it('returns missing_scanner when neither Syft nor Trivy is available', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('missing_scanner');
  });
});

// Suppress unused-import warning if some helpers aren't used.
void mkdirSync;
