/**
 * `scannerAvailable`'s cache: a found scanner stays found for the process
 * lifetime (it saves ~10 PATH lookups per executive audit), but "not
 * installed" must not: it was cached for the life of the server, so a
 * scanner installed from another terminal — or by install_toolchain itself —
 * kept reading `not_installed` until a restart.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/platform/pkgManagerDetect.js', async () => {
  const actual = await vi.importActual<typeof import('../../../src/platform/pkgManagerDetect.js')>(
    '../../../src/platform/pkgManagerDetect.js',
  );
  return { ...actual, resolveBinary: vi.fn() };
});

import { resolveBinary } from '../../../src/platform/pkgManagerDetect.js';
import {
  NEGATIVE_SCANNER_CACHE_TTL_MS,
  resetScannerCache,
  scannerAvailable,
} from '../../../src/tools/scanHelpers.js';

beforeEach(() => {
  resetScannerCache();
  vi.mocked(resolveBinary).mockReset();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('scannerAvailable cache', () => {
  it('expires a negative answer after 60 s', async () => {
    expect(NEGATIVE_SCANNER_CACHE_TTL_MS).toBe(60_000);
    vi.mocked(resolveBinary).mockResolvedValue(null);
    expect(await scannerAvailable('trivy')).toBeNull();

    vi.mocked(resolveBinary).mockResolvedValue('/usr/local/bin/trivy');
    vi.advanceTimersByTime(59_000);
    expect(await scannerAvailable('trivy')).toBeNull(); // still cached
    vi.advanceTimersByTime(2_000);
    expect(await scannerAvailable('trivy')).toBe('/usr/local/bin/trivy');
  });

  it('keeps a positive answer without re-probing', async () => {
    vi.mocked(resolveBinary).mockResolvedValue('/usr/local/bin/semgrep');
    expect(await scannerAvailable('semgrep')).toBe('/usr/local/bin/semgrep');
    vi.advanceTimersByTime(10 * 60_000);
    expect(await scannerAvailable('semgrep')).toBe('/usr/local/bin/semgrep');
    expect(vi.mocked(resolveBinary)).toHaveBeenCalledTimes(1);
  });

  it('resetScannerCache forgets a negative answer immediately', async () => {
    vi.mocked(resolveBinary).mockResolvedValue(null);
    expect(await scannerAvailable('gitleaks')).toBeNull();
    vi.mocked(resolveBinary).mockResolvedValue('/usr/bin/gitleaks');
    resetScannerCache();
    expect(await scannerAvailable('gitleaks')).toBe('/usr/bin/gitleaks');
  });
});
