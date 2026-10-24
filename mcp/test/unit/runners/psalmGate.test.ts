/**
 * `psalmTaint`'s gates (`runners/psalmRun.ts`): Psalm 6 or newer, run by
 * PHP 8.2 or newer (Psalm 6's PHAR refuses 8.1), each a named gap — and the
 * run itself never given the project as its root or working directory.
 */
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/platform/binaryPath.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/platform/binaryPath.js')>();
  return { ...actual, findFileOnPath: vi.fn() };
});
vi.mock('../../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../../src/platform/pkgManagerDetect.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/platform/pkgManagerDetect.js')>();
  return { ...actual, resolveBinary: vi.fn() };
});

import { findFileOnPath } from '../../../src/platform/binaryPath.js';
import { runProcess } from '../../../src/runners/processRunner.js';
import { psalmTaint } from '../../../src/runners/psalmRun.js';
import { scannerAvailable } from '../../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeEach(() => {
  vi.mocked(findFileOnPath).mockReset().mockImplementation((name: string) => (name === 'psalm.phar' ? '/home/u/.local/bin/psalm.phar' : null));
  vi.mocked(scannerAvailable).mockReset().mockResolvedValue('/usr/bin/php');
  vi.mocked(runProcess).mockReset();
});

const answers = (...stdouts: string[]): void => {
  for (const stdout of stdouts) vi.mocked(runProcess).mockResolvedValueOnce({ outcome: 'completed', exitCode: 0, stdout, stderr: '', truncated: false });
  vi.mocked(runProcess).mockResolvedValue({ outcome: 'failed', exitCode: 2, stdout: 'TaintedSql: 1\n', stderr: '', truncated: false });
};

const project = makeTempDir('psalm-gate-');
const pass = (files: string[] = ['src/a.php']) =>
  psalmTaint({ projectPath: project, files, wordpress: false, reportDir: makeTempDir('psalm-gate-report-'), env: {}, signal: new AbortController().signal });

describe('psalmTaint: the gates', () => {
  it('no PHP outside vendor/: no entry, nothing looked up', async () => {
    expect(await pass(['vendor/a.php', 'x.inc', 'README.md'])).toEqual({ toolRun: null, missing: [], report: null, cancelled: false });
    expect(vi.mocked(findFileOnPath)).not.toHaveBeenCalled();
  });

  it('no Psalm: not_installed, psalm missing; no PHP: php missing', async () => {
    vi.mocked(findFileOnPath).mockReturnValue(null);
    expect(await pass()).toMatchObject({ toolRun: { name: 'psalm', status: 'skipped', reason: 'not_installed' }, missing: ['psalm'] });
    vi.mocked(findFileOnPath).mockImplementation((name: string) => (name === 'psalm' ? '/c/composer/vendor/bin/psalm' : null));
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    expect(await pass()).toMatchObject({ toolRun: { status: 'skipped', reason: 'php is not installed: Psalm runs on PHP 8.2 or newer' }, missing: ['php'] });
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it.each([
    [['8.1.34'], 'Psalm needs PHP 8.2 or newer and it is 8.1', 'php'],
    [['nope'], 'Psalm needs PHP 8.2 or newer and its version could not be read', 'php'],
    [['8.4.4', 'Psalm 5.26.1@abc'], 'Psalm 6 or newer is needed and it is 5.26', 'psalm'],
    [['8.4.4', '#!/bin/sh\nexec psalm "$@"'], 'Psalm 6 or newer is needed and its version could not be read (/home/u/.local/bin/psalm.phar)', 'psalm'],
  ])('%j: skipped, the gap named, never run', async (versions, reason, missing) => {
    answers(...versions);
    expect(await pass()).toMatchObject({ toolRun: { name: 'psalm', status: 'skipped', reason }, missing: [missing] });
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(versions.length);
  });

  it('the run: php runs the PHAR, taint mode, counts on stdout, never the project as root or working directory, never --shepherd', async () => {
    answers('8.4.4', 'Psalm 6.20.1@376425b8');
    const r = await pass();
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(3);
    const run = vi.mocked(runProcess).mock.calls[2]?.[0];
    expect(run?.command).toBe('php');
    expect(run?.args?.[0]).toBe('/home/u/.local/bin/psalm.phar');
    expect(run?.args).toEqual(expect.arrayContaining(['--no-cache', '--taint-analysis', '--output-format=count', '--no-progress']));
    expect(run?.args?.some((a) => a.startsWith('--shepherd'))).toBe(false);
    const root = run?.args?.find((a) => a.startsWith('--root='))?.slice('--root='.length) ?? '';
    expect(root).not.toBe(project);
    expect(root.startsWith(project)).toBe(false);
    expect(run?.cwd).toBe(root);
    // The mocked run wrote no report: a failure, never a clean run.
    expect(r.toolRun).toEqual({ name: 'psalm', version: '6.20', status: 'failed', reason: 'Psalm wrote no report' });
  });
});

describe('check_toolchain’s probe of a PHAR (runners/toolProbe.ts)', () => {
  it('psalm.phar found on the PATH is run by php; without php, the error says so; not found, not installed', async () => {
    const { runVersionProbe } = await import('../../../src/runners/toolProbe.js');
    const { resolveBinary } = await import('../../../src/platform/pkgManagerDetect.js');
    vi.mocked(runProcess).mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: 'Psalm 6.20.1@376425b8\n', stderr: '', truncated: false });
    vi.mocked(resolveBinary).mockResolvedValue('/usr/bin/php');
    expect(await runVersionProbe({ command: 'psalm.phar', args: ['--version'], phar: true }, '/')).toEqual({ installed: true, version: '6.20.1' });
    expect(vi.mocked(runProcess).mock.calls[0]?.[0]).toMatchObject({ command: 'php', args: ['/home/u/.local/bin/psalm.phar', '--version'] });
    vi.mocked(resolveBinary).mockResolvedValue(null);
    expect(await runVersionProbe({ command: 'psalm.phar', args: ['--version'], phar: true }, '/')).toEqual({
      installed: false,
      version: '',
      error: 'found at /home/u/.local/bin/psalm.phar, but php is not on PATH to run it',
    });
    vi.mocked(findFileOnPath).mockReturnValue(null);
    expect(await runVersionProbe({ command: 'psalm.phar', args: ['--version'], phar: true }, '/')).toEqual({ installed: false, version: '' });
  });
});
