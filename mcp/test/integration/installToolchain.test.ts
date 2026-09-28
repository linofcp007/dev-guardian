/**
 * install_toolchain: the WSL fallback's paths, and what the rest of the
 * server sees after an install.
 *
 * Mocks sit at the process boundary only — `runProcess` (so nothing is
 * installed), `execa` (the `wsl -l` probe), the OS and the PATH lookups —
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
vi.mock('execa', () => ({ execa: vi.fn() }));

import { execa } from 'execa';
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
  vi.mocked(execa).mockReset();
  vi.mocked(detectOs).mockReturnValue('win32');
});

describe('install_toolchain WSL fallback', () => {
  it('hands WSL the install script as a /mnt path, not C:\\…', async () => {
    // No winget/scoop/choco; WSL present with a distro.
    vi.mocked(firstWindowsAvailable).mockResolvedValue(null);
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'wsl' ? 'C:\\wsl.exe' : null));
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Ubuntu\n' } as never);

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

describe('install_toolchain and the scanner cache', () => {
  it('a scanner installed by install_toolchain is visible to the next scan at once', async () => {
    // Before: not on PATH, and that answer is cached.
    vi.mocked(resolveBinary).mockResolvedValue(null);
    expect(await scannerAvailable('gitleaks')).toBeNull();

    // The install puts it on PATH…
    vi.mocked(resolveBinary).mockImplementation(async (name) =>
      name === 'gitleaks' ? 'C:\\bin\\gitleaks.exe' : name === 'scoop' ? 'C:\\scoop.cmd' : null,
    );
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: '' } as never);
    await tool('install_toolchain').handler({ tools: ['gitleaks'] }, plugin());

    // …and the cached "missing" must not outlive it.
    expect(await scannerAvailable('gitleaks')).toBe('C:\\bin\\gitleaks.exe');
  });
});
