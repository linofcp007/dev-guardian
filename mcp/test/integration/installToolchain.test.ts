/**
 * install_toolchain: the WSL fallback's paths, and what the rest of the
 * server sees after an install.
 *
 * Mocks sit at the process boundary only — `runProcess` (so nothing is
 * installed), `captureOutput` (the `wsl -l` probe), the OS and the PATH lookups —
 * while `runShellScript` and `scanHelpers` are the real ones, because the
 * defects under test live in them: the WSL argv, and the scanner cache.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/platform/osDetect.js', () => ({
  detectOs: vi.fn(() => 'win32'),
}));
vi.mock('../../src/platform/pkgManagerDetect.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/platform/pkgManagerDetect.js')>(
    '../../src/platform/pkgManagerDetect.js',
  );
  return { ...actual, resolveBinary: vi.fn(), firstWindowsAvailable: vi.fn() };
});
vi.mock('../../src/runners/spawn.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/runners/spawn.js')>('../../src/runners/spawn.js');
  return { ...actual, captureOutput: vi.fn() };
});

import { captureOutput } from '../../src/runners/spawn.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { firstWindowsAvailable, resolveBinary } from '../../src/platform/pkgManagerDetect.js';
import { resetScannerCache, scannerAvailable } from '../../src/tools/scanHelpers.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import type { PluginContext } from '../../src/context.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/tools/checkToolchain.js');
  await import('../../src/tools/installToolchain.js');
});

const SCRIPTS_DIR = 'C:\\Users\\me\\CLAUDE SKILLS\\dev-guardian\\scripts';

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: SCRIPTS_DIR,
    progressNotifier: { send: () => {} },
  };
}

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

const ok = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };

beforeEach(() => {
  resetScannerCache();
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockResolvedValue(ok);
  vi.mocked(resolveBinary).mockReset();
  vi.mocked(firstWindowsAvailable).mockReset();
  vi.mocked(captureOutput).mockReset();
  vi.mocked(detectOs).mockReturnValue('win32');
});

describe('install_toolchain WSL fallback', () => {
  it('hands WSL the install script as a /mnt path, not C:\\…', async () => {
    // No winget/scoop/choco; WSL present with a distro.
    vi.mocked(firstWindowsAvailable).mockResolvedValue(null);
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'wsl' ? 'C:\\wsl.exe' : null));
    vi.mocked(captureOutput).mockResolvedValue({ exitCode: 0, stdout: 'Ubuntu\n' } as never);

    const r = (await tool('install_toolchain').handler({}, plugin())) as { ok: boolean };
    expect(r.ok).toBe(true);

    const wslCall = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'wsl');
    expect(wslCall?.[0].args).toEqual([
      'bash',
      '/mnt/c/Users/me/CLAUDE SKILLS/dev-guardian/scripts/install/install-linux.sh',
      '--no-sudo',
    ]);
  });
});

/**
 * Review 3.0, wave 2, round 2: on Windows, scoop and choco installed
 * whatever upstream released last. The pinned, sha256-checked release ZIP
 * (through PowerShell) comes first; a package manager is the fallback, and
 * it names the pinned version.
 */
describe('install_toolchain on Windows: pinned release archives first', () => {
  interface DryRun {
    would_install: Array<{ tool: string; manager?: string; command?: string }>;
  }

  it('picks the pinned, sha256-checked ZIP through PowerShell over scoop', async () => {
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'powershell' ? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' : name === 'scoop' ? 'C:\\scoop.cmd' : null,
    );
    const r = (await tool('install_toolchain').handler({ tools: ['trivy', 'gitleaks', 'syft'], dry_run: true }, plugin())) as unknown as DryRun;
    expect(r.would_install.map((e) => [e.tool, e.manager])).toEqual([
      ['trivy', 'release'],
      ['gitleaks', 'release'],
      ['syft', 'release'],
    ]);
    expect(r.would_install[0]?.command).toMatch(/trivy v0\.76\.1 release archive \(windows, sha256-checked\)/);
  });

  it('gosec through its pinned archive; the Go toolchain it needs is a manual step, never installed', async () => {
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'powershell' ? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' : name === 'winget' ? 'C:\\winget.exe' : null,
    );
    const r = (await tool('install_toolchain').handler({ tools: ['gosec', 'go'], dry_run: true }, plugin())) as unknown as DryRun & {
      manual_steps: Array<{ tool: string; instructions: string }>;
    };
    expect(r.would_install.map((e) => [e.tool, e.manager])).toEqual([['gosec', 'release']]);
    expect(r.would_install[0]?.command).toMatch(/gosec v2\.30\.0 release archive \(windows, sha256-checked\)/);
    expect(r.manual_steps).toEqual([
      { tool: 'go', instructions: 'dev-guardian never auto-installs the Go toolchain. winget install GoLang.Go' },
    ]);
    // Probes only: nothing ever asks winget for Go.
    expect(vi.mocked(runProcess).mock.calls.some((c) => (c[0].args ?? []).includes('GoLang.Go'))).toBe(false);
  });

  it('without PowerShell, scoop installs the pinned version — never latest', async () => {
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'scoop' ? 'C:\\scoop.cmd' : null));
    const r = (await tool('install_toolchain').handler({ tools: ['trivy'], dry_run: true }, plugin())) as unknown as DryRun;
    expect(r.would_install).toEqual([expect.objectContaining({ tool: 'trivy', manager: 'scoop', command: 'scoop install trivy@0.76.1' })]);
  });
});

describe('install_toolchain and the scanner cache', () => {
  it('a scanner installed by install_toolchain is visible to the next scan at once', async () => {
    // Before: not on PATH, and that answer is cached.
    vi.mocked(resolveBinary).mockResolvedValue(null);
    expect(await scannerAvailable('gitleaks')).toBeNull();

    // The install puts it on PATH…
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'gitleaks' ? 'C:\\bin\\gitleaks.exe' : name === 'scoop' ? 'C:\\scoop.cmd' : null,
    );
    vi.mocked(captureOutput).mockResolvedValue({ exitCode: 0, stdout: '' } as never);
    await tool('install_toolchain').handler({ tools: ['gitleaks'] }, plugin());

    // …and the cached "missing" must not outlive it.
    expect(await scannerAvailable('gitleaks')).toBe('C:\\bin\\gitleaks.exe');
  });
});

describe('install_toolchain changes nothing on a dry run, and survives any tool name', () => {
  it('a dry run never runs `pipx ensurepath`, which edits the shell rc and the user PATH', async () => {
    // Review of 3.6, finding 12: the verification step ran it on every call.
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'pipx' ? 'C:\\pipx.exe' : null));
    vi.mocked(captureOutput).mockResolvedValue({ exitCode: 0, stdout: '' } as never);
    await tool('install_toolchain').handler({ dry_run: true }, plugin());
    await tool('install_toolchain').handler({ tools: ['semgrep'], dry_run: true }, plugin());
    const pipx = vi.mocked(runProcess).mock.calls.filter((c) => c[0].args?.includes('ensurepath'));
    expect(pipx).toEqual([]);
  });

  it('a name that is an Object.prototype key is not in the catalogue — never a crash', async () => {
    // Review of 3.6, finding 13: `constructor` passed both plain-object
    // lookups, then `undefined[os]` threw out of the tool.
    vi.mocked(resolveBinary).mockResolvedValue(null);
    vi.mocked(captureOutput).mockResolvedValue({ exitCode: 0, stdout: '' } as never);
    const r = (await tool('install_toolchain').handler(
      { tools: ['constructor', '__proto__', 'toString', 'hasOwnProperty'], dry_run: true },
      plugin(),
    )) as unknown as { ok: boolean; skipped: Array<{ tool: string; reason: string }> };
    expect(r.ok).toBe(true);
    expect(r.skipped.map((s) => [s.tool, s.reason])).toEqual([
      ['constructor', 'not_in_catalog'],
      ['__proto__', 'not_in_catalog'],
      ['toString', 'not_in_catalog'],
      ['hasOwnProperty', 'not_in_catalog'],
    ]);
  });
});
