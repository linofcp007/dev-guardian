/**
 * install_toolchain names where a pinned release went — `~/.local/bin`,
 * `%USERPROFILE%\.local\bin` on Windows — and says when a terminal will not
 * find it there (review of 3.0, W2E); and on macOS Trivy takes the pinned
 * archive before Homebrew. Mocks at the process boundary only, as in
 * `installToolchain.test.ts`: `runProcess` (nothing is installed), the OS and
 * the PATH lookups.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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

import { runProcess } from '../../src/runners/processRunner.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { resolveBinary } from '../../src/platform/pkgManagerDetect.js';
import { PINNED_RELEASES } from '../../src/runners/installCatalog.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import type { PluginContext } from '../../src/context.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/checkToolchain.js');
  await import('../../src/tools/installToolchain.js');
});
afterAll(cleanupTempDirs);

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: makeTempDir('ubin-scripts-'), progressNotifier: { send: () => {} } };
}

async function install(input: Record<string, unknown>): Promise<Record<string, Array<Record<string, unknown>>>> {
  const t = TOOLS.find((x) => x.name === 'install_toolchain');
  if (t === undefined) throw new Error('install_toolchain not registered');
  const r = (await t.handler(input, plugin())) as unknown as { ok: boolean } & Record<string, Array<Record<string, unknown>>>;
  expect(r.ok).toBe(true);
  return r;
}

let home: string;

beforeEach(() => {
  resetScannerCache();
  home = makeTempDir('ubin-home-');
  mkdirSync(join(home, '.local', 'bin'), { recursive: true });
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
  vi.stubEnv('PATH', process.env['PATH'] ?? '');
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
  vi.mocked(resolveBinary).mockReset();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

const note = (dir: string, binary: string): string =>
  `${dir} is not on your PATH: dev-guardian looks there itself, so its scans find ${binary}, but a terminal will not until you add that directory to PATH`;

describe('install_toolchain says where a pinned release went', () => {
  it('Windows: the release ZIP into %USERPROFILE%\\.local\\bin, named, with the PATH note', async () => {
    vi.mocked(detectOs).mockReturnValue('win32');
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'powershell' ? 'C:\\ps.exe' : null));
    const bin = join(home, '.local', 'bin');

    const r = await install({ tools: ['trivy', 'gitleaks'] });

    expect(r['installed']).toEqual([
      expect.objectContaining({ tool: 'trivy', manager: 'release', binary_path: join(bin, 'trivy.exe'), path_note: note(bin, 'trivy.exe') }),
      expect.objectContaining({ tool: 'gitleaks', manager: 'release', binary_path: join(bin, 'gitleaks.exe'), path_note: note(bin, 'gitleaks.exe') }),
    ]);
  });

  it('a dry run says where it would go', async () => {
    vi.mocked(detectOs).mockReturnValue('linux');
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'curl' ? '/usr/bin/curl' : null));
    const r = await install({ tools: ['syft'], dry_run: true });
    expect(r['would_install']).toEqual([
      expect.objectContaining({ tool: 'syft', manager: 'curl', binary_path: join(home, '.local', 'bin', 'syft') }),
    ]);
    expect(vi.mocked(runProcess).mock.calls.filter(([o]) => o.command === 'bash')).toEqual([]);
  });

  it('macOS: Trivy takes the pinned archive though Homebrew is there; gitleaks keeps Homebrew, with no binary_path', async () => {
    vi.mocked(detectOs).mockReturnValue('darwin');
    vi.mocked(resolveBinary).mockImplementation(async (name) => (name === 'brew' || name === 'curl' ? `/usr/local/bin/${name}` : null));

    const r = await install({ tools: ['trivy', 'gitleaks'], dry_run: true });

    const [trivy, gitleaks] = r['would_install'] ?? [];
    expect(trivy).toEqual(
      expect.objectContaining({
        tool: 'trivy',
        manager: 'curl',
        command: `trivy v${PINNED_RELEASES.trivy.version} release archive (darwin, sha256-checked) → ~/.local/bin/trivy`,
        binary_path: join(home, '.local', 'bin', 'trivy'),
      }),
    );
    expect(gitleaks).toEqual({ tool: 'gitleaks', manager: 'brew', command: 'brew install gitleaks', needs_elevation: false });
  });
});
