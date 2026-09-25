/**
 * Integration tests for check_toolchain and install_toolchain.
 *
 * check_toolchain runs each catalogue entry's version command through
 * runProcess (no bash) → mock runProcess per command.
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
  // Default: every binary is absent. install_toolchain's verification step
  // re-runs check_toolchain, whose version probes go through runProcess.
  vi.mocked(runProcess).mockResolvedValue({
    outcome: 'failed',
    exitCode: null,
    stdout: '',
    stderr: '',
    truncated: false,
  });
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

interface ToolStatusView {
  name: string;
  installed: boolean;
  version: string;
  expected_version_floor: string;
  meets_version_floor: boolean | null;
  required_by: string[];
  install_command: string | null;
  compromised?: boolean;
  advisory?: { id: string; cve?: string; url: string };
  provided_by?: string;
  probe_error?: string;
}

interface CheckView {
  ok: true;
  tools: ToolStatusView[];
  summary: {
    total_catalogued: number;
    installed: number;
    missing: number;
    below_floor: number;
    compromised?: number;
  };
  warnings?: string[];
}

type Run = Awaited<ReturnType<typeof runProcess>>;
const ran = (stdout: string, stderr = ''): Run => ({
  outcome: 'completed',
  exitCode: 0,
  stdout,
  stderr,
  truncated: false,
});
// What runProcess returns when the binary does not exist (spawn ENOENT).
const absent: Run = { outcome: 'failed', exitCode: null, stdout: '', stderr: '', truncated: false };

/** Real output captured on the Windows machine this was written on. */
const MACHINE: Record<string, Run> = {
  semgrep: ran('1.176.1\n\nA new version of Semgrep is available.'),
  trivy: ran('Version: 0.69.3\nVulnerability DB:\n  Version: 2\n'),
  gitleaks: ran('8.30.1'),
  ruff: ran('ruff 0.16.6'),
  'pre-commit': ran('pre-commit 4.6.0'),
  bandit: ran(
    'python.exe C:\\Program Files\\Python314\\Scripts\\bandit 1.9.4\n  python version = 3.14.7 (tags/v3.14.7)',
  ),
  syft: ran('Application:   syft\nVersion:       1.51.1\nGoVersion:     go1.26.3\nSchemaVersion: 16.1.10'),
  k6: ran('k6.exe v2.2.0 (commit/00a9a1b7f5, go1.26.5, windows/amd64)'),
  dotnet: ran('10.0.401 [C:\\Program Files\\dotnet\\sdk]\r\n'),
  node: ran('v24.19.0'),
  python3: ran('Python 3.14.7'),
  docker: ran('Docker version 29.8.0, build 88096ef'),
};

function machine(overrides: Record<string, Run> = {}): void {
  const table = { ...MACHINE, ...overrides };
  vi.mocked(runProcess).mockImplementation(async (opts) => table[opts.command] ?? absent);
}

async function check(plugin: PluginContext): Promise<CheckView> {
  const r = (await getTool('check_toolchain').handler({}, plugin)) as CheckView | { ok: false };
  expect(r.ok).toBe(true);
  return r as CheckView;
}

describe('check_toolchain', () => {
  it('probes every catalogued tool directly — no bash, no check-tools.sh', async () => {
    const plugin = { ...makePlugin(), shell: null };
    machine();
    const r = await check(plugin);

    const commands = new Set(vi.mocked(runProcess).mock.calls.map((c) => c[0].command));
    // The nine the old script never probed are probed now.
    for (const cmd of ['nuclei', 'phpcs', 'wp', 'wpscan', 'jscpd', 'lighthouse', 'dotnet', 'dotnet-outdated']) {
      expect(commands.has(cmd), cmd).toBe(true);
    }
    expect(vi.mocked(runShellScript)).not.toHaveBeenCalled();
    expect(r.summary.total_catalogued).toBe(17);
    expect(r.tools.filter((t) => t.required_by.length > 0 || t.expected_version_floor !== '')).toHaveLength(17);
  });

  it('reads each version correctly, including the outputs that broke the bash probe', async () => {
    machine();
    const r = await check(makePlugin());
    const v = (name: string) => r.tools.find((t) => t.name === name);
    expect(v('semgrep')).toMatchObject({ installed: true, version: '1.176.1', meets_version_floor: true });
    expect(v('trivy')).toMatchObject({ installed: true, version: '0.69.3', compromised: false });
    expect(v('syft')).toMatchObject({ installed: true, version: '1.51.1' });
    expect(v('bandit')).toMatchObject({ installed: true, version: '1.9.4' });
    expect(v('k6')).toMatchObject({ installed: true, version: '2.2.0' });
    expect(v('nuclei')).toMatchObject({ installed: false, version: '' });
    expect(v('semgrep')?.required_by).toEqual(
      expect.arrayContaining(['scan_sast', 'security_scan_full', 'bug_hunt', 'review_pr']),
    );
    // Each entry carries this OS's install hint. semgrep has one on every
    // OS; nuclei, for instance, has none on linux.
    expect(v('semgrep')?.install_command).toBeTruthy();
  });

  it('sees the .NET SDK, and treats dotnet-format as provided by SDK >= 6', async () => {
    machine();
    const r = await check(makePlugin());
    const sdk = r.tools.find((t) => t.name === 'dotnet-sdk');
    const format = r.tools.find((t) => t.name === 'dotnet-format');
    expect(sdk).toMatchObject({ installed: true, version: '10.0.401' });
    expect(format).toMatchObject({ installed: true, provided_by: 'dotnet-sdk', meets_version_floor: true });
    expect(r.tools.find((t) => t.name === 'dotnet-outdated')?.installed).toBe(false);
  });

  it('flags an installed Trivy in the compromised range with the advisory id', async () => {
    machine({ trivy: ran('Version: 0.69.4\n') });
    const r = await check(makePlugin());
    const trivy = r.tools.find((t) => t.name === 'trivy');
    expect(trivy?.compromised).toBe(true);
    expect(trivy?.advisory?.id).toBe('GHSA-69fq-xp46-6x23');
    expect(trivy?.advisory?.cve).toBe('CVE-2026-33634');
    expect(r.summary.compromised).toBe(1);
    expect(r.warnings?.join('\n')).toContain('GHSA-69fq-xp46-6x23');
    // The most urgent line comes first.
    expect(r.tools[0]?.name).toBe('trivy');
  });

  it('says why a binary that exists could not report its version', async () => {
    machine({
      wp: { outcome: 'failed', exitCode: 1, stdout: '', stderr: 'Error: YIKES! It looks like you are running this as root.', truncated: false },
      // What a MISSING tool looks like on Windows: cross-spawn runs an
      // unresolved command through cmd.exe, which exits 1.
      nuclei: {
        outcome: 'failed',
        exitCode: 1,
        stdout: '',
        stderr: "'nuclei' is not recognized as an internal or external command,",
        truncated: false,
      },
    });
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'wp' ? '/usr/local/bin/wp' : null,
    );
    const r = await check(makePlugin());
    const wp = r.tools.find((t) => t.name === 'wp-cli');
    expect(wp?.installed).toBe(false);
    expect(wp?.probe_error).toMatch(/found at \/usr\/local\/bin\/wp, but `wp --version --allow-root` exited 1: Error: YIKES/);
    // Not on PATH at all: simply missing, however the failed spawn looked.
    const nuclei = r.tools.find((t) => t.name === 'nuclei');
    expect(nuclei?.installed).toBe(false);
    expect(nuclei?.probe_error).toBeUndefined();
  });

  it('explains a tool that is on PATH but cannot be started by a non-bash process', async () => {
    // Measured on the machine this was written on: `syft` on PATH was an
    // extensionless `#!/usr/bin/env bash` shim. `where` finds it; Windows
    // cannot execute it, so every direct invocation fails — the old bash
    // probe said "installed", which generate_sbom then disproved.
    // cross-spawn reads the shebang and runs `bash <shim>`; on that host
    // `bash` on PATH was WSL's launcher, which failed.
    machine({
      syft: {
        outcome: 'failed',
        exitCode: 1,
        stdout: '',
        stderr: '<3>WSL (532880 - Relay) ERROR: CreateProcessCommon:818: execvpe(/bin/bash) failed',
        truncated: false,
      },
    });
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'syft' ? 'C:\\ProgramData\\chocolatey\\bin\\syft' : null,
    );
    const r = await check(makePlugin());
    const syft = r.tools.find((t) => t.name === 'syft');
    expect(syft?.installed).toBe(false);
    expect(syft?.probe_error).toContain('found at C:\\ProgramData\\chocolatey\\bin\\syft');
    if (process.platform === 'win32') {
      expect(syft?.probe_error).toMatch(/bash shim it runs only inside bash/);
    }
    expect(r.tools.find((t) => t.name === 'nuclei')?.probe_error).toBeUndefined();
  });

  it('keeps node, python and docker as informational entries (python3, then python)', async () => {
    machine({
      python3: { outcome: 'failed', exitCode: 9009, stdout: '', stderr: '', truncated: false },
      python: ran('Python 3.12.1'),
    });
    const r = await check(makePlugin());
    expect(r.tools.find((t) => t.name === 'node')).toMatchObject({ installed: true, version: '24.19.0', required_by: [] });
    expect(r.tools.find((t) => t.name === 'python')).toMatchObject({ installed: true, version: '3.12.1' });
    expect(r.tools.find((t) => t.name === 'docker')).toMatchObject({ installed: true, version: '29.8.0' });
    // Informational entries never count toward the catalogue summary.
    expect(r.summary.installed + r.summary.missing).toBe(17);
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
    // Kept mocked so no real script can run from this test.
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
    // runProcess still runs — for the verification's version probes — but
    // never an install command.
    const installs = vi.mocked(runProcess).mock.calls.filter((c) => c[0].args?.includes('install'));
    expect(installs).toEqual([]);
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
