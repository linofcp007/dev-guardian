/**
 * `platform/userBin.ts` — the per-user tools directory install_toolchain's
 * pinned installers write to (`~/.local/bin`, `%USERPROFILE%\.local\bin`),
 * which is on no default PATH on Windows or macOS: a Trivy installed there
 * was reported missing by the next scan (review of 3.0, W2E). The server
 * appends it to its own PATH, and its scanner lookups and version probes
 * find what is there.
 */
import { randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { resolveBinary } from '../../../src/platform/pkgManagerDetect.js';
import { ensureUserBinOnPath, pathHasDir, userBinDir, userBinPlacement } from '../../../src/platform/userBin.js';
import { runVersionProbe } from '../../../src/runners/toolProbe.js';
import { resetScannerCache, scannerAvailable } from '../../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
  resetScannerCache();
});

const WIN = process.platform === 'win32';

function homeWithBin(): { home: string; bin: string } {
  const home = makeTempDir('ubin-home-');
  const bin = join(home, '.local', 'bin');
  mkdirSync(bin, { recursive: true });
  return { home, bin };
}

describe('userBinDir and pathHasDir', () => {
  it('is <home>/.local/bin, and null with no home', () => {
    expect(userBinDir(join('h', 'u'))).toBe(join('h', 'u', '.local', 'bin'));
    expect(userBinDir('  ')).toBeNull();
  });

  it('finds an entry resolved and without a trailing separator', () => {
    const { bin } = homeWithBin();
    expect(pathHasDir(bin, ['x', `${bin}${WIN ? '\\' : '/'}`].join(delimiter))).toBe(true);
    expect(pathHasDir(bin, ['x', 'y'].join(delimiter))).toBe(false);
  });

  it.runIf(WIN)('compares case-insensitively and unquoted on Windows', () => {
    const { bin } = homeWithBin();
    expect(pathHasDir(bin, `C:\\x;"${bin.toUpperCase()}"`, 'win32')).toBe(true);
  });
});

describe('ensureUserBinOnPath', () => {
  it('appends an existing ~/.local/bin once, after every other entry', () => {
    const { home, bin } = homeWithBin();
    const env: NodeJS.ProcessEnv = { PATH: ['a', 'b'].join(delimiter) };
    expect(ensureUserBinOnPath(env, home)).toEqual({ dir: bin, added: true, onUserPath: false });
    expect(env['PATH']).toBe(['a', 'b', bin].join(delimiter));
    expect(ensureUserBinOnPath(env, home).added).toBe(false);
    expect(env['PATH']).toBe(['a', 'b', bin].join(delimiter));
  });

  it('adds nothing for a directory that does not exist, or one PATH already has', () => {
    const home = makeTempDir('ubin-home-');
    const env: NodeJS.ProcessEnv = { PATH: 'a' };
    expect(ensureUserBinOnPath(env, home).added).toBe(false);
    expect(env['PATH']).toBe('a');
    const { home: h2, bin } = homeWithBin();
    const env2: NodeJS.ProcessEnv = { PATH: [bin, 'a'].join(delimiter) };
    expect(ensureUserBinOnPath(env2, h2).added).toBe(false);
    expect(env2['PATH']).toBe([bin, 'a'].join(delimiter));
  });

  it('an empty PATH becomes the directory alone', () => {
    const { home, bin } = homeWithBin();
    const env: NodeJS.ProcessEnv = {};
    ensureUserBinOnPath(env, home);
    expect(env['PATH']).toBe(bin);
  });
});

describe('the scanner resolver finds a tool installed only in ~/.local/bin', () => {
  it('scannerAvailable resolves it and runVersionProbe runs it', async () => {
    const { home, bin } = homeWithBin();
    const name = `dg-fake-tool-${randomUUID().slice(0, 8)}`;
    if (WIN) {
      writeFileSync(join(bin, `${name}.cmd`), '@echo off\r\necho dg-fake-tool 1.2.3\r\n');
    } else {
      writeFileSync(join(bin, name), '#!/bin/sh\necho "dg-fake-tool 1.2.3"\n');
      chmodSync(join(bin, name), 0o755);
    }
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    // Restored after the test: the resolver appends to this process's PATH.
    vi.stubEnv('PATH', process.env['PATH'] ?? '');

    expect(await resolveBinary(name)).toBeNull();
    const found = await scannerAvailable(name);
    expect(found?.toLowerCase().startsWith(bin.toLowerCase())).toBe(true);
    expect(pathHasDir(bin, process.env['PATH'] ?? '')).toBe(true);
    expect(await runVersionProbe({ command: name, args: ['--version'] }, home)).toEqual({ installed: true, version: '1.2.3' });
  }, 30_000);
});

describe('userBinPlacement — what install_toolchain says about where a binary went', () => {
  it('names the path, and when the directory is not on the user PATH, says a terminal will not find it', () => {
    const { home, bin } = homeWithBin();
    expect(userBinPlacement('trivy.exe', home)).toEqual({
      binary_path: join(bin, 'trivy.exe'),
      path_note: `${bin} is not on your PATH: dev-guardian looks there itself, so its scans find trivy.exe, but a terminal will not until you add that directory to PATH`,
    });
  });
});
