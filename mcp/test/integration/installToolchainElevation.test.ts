/**
 * `install_toolchain`'s hint for a step that needs elevation (final review
 * I8). It said "Re-call with elevation_allowed=true to run this step." —
 * but install steps run without a terminal, so `sudo` can only succeed
 * without a password (the schema text already said so; the hint did not),
 * and `choco` only from a server that already runs elevated. Otherwise the
 * user has to run the command themselves, and the hint must say which one.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/platform/osDetect.js', () => ({ detectOs: vi.fn() }));
vi.mock('../../src/platform/pkgManagerDetect.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/platform/pkgManagerDetect.js')>(
    '../../src/platform/pkgManagerDetect.js',
  );
  return { ...actual, resolveBinary: vi.fn(), firstWindowsAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { resolveBinary } from '../../src/platform/pkgManagerDetect.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { elevationHint } from '../../src/tools/installToolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/checkToolchain.js');
  await import('../../src/tools/installToolchain.js');
});

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: makeTempDir('install-hint-'),
    progressNotifier: { send: () => {} },
  };
}

type InstallOut = {
  ok: true;
  requires_elevation: Array<{ tool: string; command?: string; hint?: string }>;
};

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockResolvedValue({ outcome: 'failed', exitCode: null, stdout: '', stderr: '', truncated: false });
  vi.mocked(resolveBinary).mockReset();
});

describe('install_toolchain: the elevation hint says when elevation_allowed can work, and what to run instead', () => {
  it('Linux (apt via sudo): only with passwordless sudo, else run the full sudo command yourself', async () => {
    vi.mocked(detectOs).mockReturnValue('linux');
    vi.mocked(resolveBinary).mockImplementation(async (name: string) => (name === 'apt-get' ? '/usr/bin/apt-get' : null));

    const tool = TOOLS.find((t) => t.name === 'install_toolchain');
    if (!tool) throw new Error('install_toolchain not registered');
    // k6: Trivy has no apt entry any more (a pinned release archive, review
    // 3.0 wave 2), and k6's is still an apt install.
    const r = (await tool.handler({ tools: ['k6'] }, plugin())) as InstallOut;

    const step = r.requires_elevation.find((s) => s.tool === 'k6');
    expect(step?.hint).toMatch(/passwordless sudo/);
    expect(step?.hint).toContain('`sudo apt-get install -y k6`');
    expect(step?.hint).toMatch(/yourself in a terminal/);
    expect(step?.hint).not.toMatch(/^Re-call with elevation_allowed=true to run this step\.$/);
  });

  it('Windows (choco): only from an elevated server, else run it in an administrator terminal', () => {
    const hint = elevationHint('win32', 'choco install -y trivy');
    expect(hint).toMatch(/runs elevated/);
    expect(hint).toContain('`choco install -y trivy`');
    expect(hint).toMatch(/administrator terminal/);
  });
});
