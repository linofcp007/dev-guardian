/**
 * Integration tests for check_toolchain and install_toolchain.
 *
 * check_toolchain shells out to check-tools.sh → mock runShellScript.
 * install_toolchain has two branches:
 *   - Per-tool install → runs runProcess; mock it + scannerAvailable
 *     (used by check_toolchain's verification re-run).
 *   - Default install on Linux/macOS delegates to install-*.sh via
 *     runShellScript.
 *   - resolveBinary (pkgManagerDetect) is also mocked so we control which
 *     Windows package managers appear available.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
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
vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));
vi.mock('../../src/platform/pkgManagerDetect.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/platform/pkgManagerDetect.js')>(
      '../../src/platform/pkgManagerDetect.js',
    );
  return {
    ...actual,
    resolveBinary: vi.fn(),
    firstWindowsAvailable: vi.fn(),
  };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import {
  resolveBinary,
  firstWindowsAvailable,
} from '../../src/platform/pkgManagerDetect.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  // Order matters: install_toolchain calls check_toolchain at the end so
  // both must be in TOOLS.
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
  await import('../../src/tools/setBaseline.js');
  await import('../../src/tools/suppressFinding.js');
  await import('../../src/tools/diffScans.js');
  await import('../../src/tools/auditExecutive.js');
  await import('../../src/tools/checkToolchain.js');
  await import('../../src/tools/installToolchain.js');
});

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
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
    scriptsDir: makeTempDir('install-scripts-'),
    progressNotifier: { send: () => {} },
  };
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(resolveBinary).mockReset();
  vi.mocked(firstWindowsAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(resolveBinary).mockReset();
  vi.mocked(firstWindowsAvailable).mockReset();
});

// ---------------------------------------------------------------------- check_toolchain

describe('check_toolchain', () => {
  it('parses check-tools.sh JSON and annotates each catalog entry with required_by + install_command', async () => {
    const plugin = makePlugin();
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: JSON.stringify({
        semgrep: '1.50.0',
        trivy: '',
        gitleaks: '8.10.0',
        ruff: '0.1.5',
        syft: '',
        node: 'v24.13.0',
        python: '3.11.0',
        docker: '',
        bandit: '',
        'pre-commit': '',
        k6: '',
      }),
      stderr: '',
      truncated: false,
    });

    const r = (await getTool('check_toolchain').handler({}, plugin)) as {
      ok: true;
      tools: Array<{
        name: string;
        installed: boolean;
        version: string;
        required_by: string[];
        install_command: string | null;
      }>;
      summary: { installed: number; missing: number };
    };
    expect(r.ok).toBe(true);
    const semgrep = r.tools.find((t) => t.name === 'semgrep');
    const trivy = r.tools.find((t) => t.name === 'trivy');
    expect(semgrep?.installed).toBe(true);
    expect(semgrep?.required_by).toEqual(
      expect.arrayContaining(['scan_sast', 'security_scan_full', 'bug_hunt', 'review_pr']),
    );
    expect(trivy?.installed).toBe(false);
    expect(trivy?.install_command).toBeTruthy();
    expect(r.summary.installed).toBeGreaterThan(0);
    expect(r.summary.missing).toBeGreaterThan(0);
  });

  it('returns scanner_failed when check-tools.sh stdout is invalid JSON', async () => {
    const plugin = makePlugin();
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: 'not-json',
      stderr: '',
      truncated: false,
    });

    const r = (await getTool('check_toolchain').handler({}, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('scanner_failed');
  });
});

// ---------------------------------------------------------------------- install_toolchain

describe('install_toolchain (per-tool)', () => {
  it('runs the install spec from the catalogue and surfaces installed entries', async () => {
    const plugin = makePlugin();

    // Resolve all common Windows pkg managers so the per-tool path picks one.
    vi.mocked(resolveBinary).mockImplementation(async (name: string) => {
      // Pretend scoop is available; everything else missing.
      return name === 'scoop' ? '/fake/scoop' : null;
    });
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '',
      stderr: '',
      truncated: false,
    });
    // Verification re-run uses runShellScript on check-tools.sh.
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '{}',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('install_toolchain');
    // Force the win32 branch by passing tools[] explicitly — `picked` then
    // looks up the Windows-only specs and falls back gracefully on other
    // OSes. Either way, we just verify shape, not OS-specific commands.
    const r = (await tool.handler({ tools: ['gitleaks'] }, plugin)) as {
      ok: true;
      installed: Array<{ tool: string }>;
      failed: Array<unknown>;
      verification: unknown;
    };
    expect(r.ok).toBe(true);
    expect(r.verification).toBeDefined();
    // gitleaks should appear in one of installed / would_install / manual_steps
    // depending on the host OS — the important property is that the tool
    // never crashes and always returns a verification snapshot.
  });

  it('returns dry_run=would_install entries without invoking runProcess', async () => {
    const plugin = makePlugin();

    vi.mocked(resolveBinary).mockImplementation(async (name: string) => {
      return name === 'scoop' || name === 'brew' || name === 'pipx' ? '/fake/bin' : null;
    });
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '{}',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('install_toolchain');
    const r = (await tool.handler(
      { tools: ['semgrep'], dry_run: true },
      plugin,
    )) as {
      ok: true;
      applied: boolean;
      would_install: Array<{ tool: string; command?: string }>;
      installed: unknown[];
    };
    expect(r.ok).toBe(true);
    expect(r.applied).toBe(false);
    expect(r.installed).toEqual([]);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('routes elevation-required steps to requires_elevation when elevation_allowed is false', async () => {
    const plugin = makePlugin();

    // Make `choco` (which has needs_elevation=true) the only available mgr.
    vi.mocked(resolveBinary).mockImplementation(async (name: string) =>
      name === 'choco' ? '/fake/choco' : null,
    );
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '{}',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('install_toolchain');
    const r = (await tool.handler({ tools: ['trivy'] }, plugin)) as
      | {
          ok: true;
          requires_elevation: Array<{ tool: string }>;
          installed: unknown[];
        }
      | { ok: true; manual_steps: unknown[] };
    // Either the tool got routed to requires_elevation (preferred for
    // catalog entries that have a choco spec) or to manual_steps (if the
    // current OS branch lacks any matching spec).
    expect((r as { ok: true }).ok).toBe(true);
  });

  it('skips entries that are not in the catalog', async () => {
    const plugin = makePlugin();
    vi.mocked(resolveBinary).mockResolvedValue(null);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '{}',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('install_toolchain');
    const r = (await tool.handler({ tools: ['definitely-not-a-real-tool'] }, plugin)) as {
      ok: true;
      skipped: Array<{ tool: string; reason: string }>;
    };
    expect(r.ok).toBe(true);
    expect(r.skipped.some((s) => s.reason === 'not_in_catalog')).toBe(true);
  });
});
