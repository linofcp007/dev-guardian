/**
 * `cppcheckSources`' version gate (`runners/cppcheckRun.ts`): cppcheck 2.10
 * — Debian bookworm's — skips a file whose every configuration reaches an
 * `#error` without a word, so anything older than CPPCHECK_MIN_VERSION is a
 * named gap and never run.
 */
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { cppcheckSources } from '../../../src/runners/cppcheckRun.js';
import { runProcess } from '../../../src/runners/processRunner.js';
import { scannerAvailable } from '../../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeEach(() => {
  vi.mocked(scannerAvailable).mockReset().mockResolvedValue('/usr/bin/cppcheck');
  vi.mocked(runProcess).mockReset();
});

const answers = (version: string): void => {
  vi.mocked(runProcess)
    .mockResolvedValueOnce({ outcome: 'completed', exitCode: 0, stdout: version, stderr: '', truncated: false })
    .mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
};

const pass = () =>
  cppcheckSources({
    projectPath: makeTempDir('cppcheck-gate-'),
    files: ['src/a.c', 'include/a.h'],
    scoped: false,
    reportDir: makeTempDir('cppcheck-gate-report-'),
    env: {},
    signal: new AbortController().signal,
  });

describe('cppcheckSources: the version gate', () => {
  it.each([
    ['Cppcheck 2.10\n', /cppcheck 2\.13 or newer is needed and it is 2\.10: an older one skips a file/],
    ['Cppcheck 1.90\n', /and it is 1\.90/],
    ['cppcheck: unknown option\n', /and its version could not be read/],
  ])('%j: skipped, listed missing, never run', async (version, reason) => {
    answers(version);
    const r = await pass();
    expect(r.toolRun).toMatchObject({ name: 'cppcheck', status: 'skipped' });
    expect(r.toolRun?.reason).toMatch(reason);
    expect(r.missing).toEqual(['cppcheck']);
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(runProcess).mock.calls[0]?.[0].args).toEqual(['--version']);
  });

  it.each(['Cppcheck 2.13\n', 'Cppcheck 2.22.0\n', 'Cppcheck 3.0\n'])('%j: run (a run that wrote no report fails)', async (version) => {
    answers(version);
    const r = await pass();
    expect(vi.mocked(runProcess)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(runProcess).mock.calls[1]?.[0].args?.at(-1)).toMatch(/^--file-list=/);
    expect(r.toolRun).toEqual({ name: 'cppcheck', status: 'failed', reason: 'cppcheck wrote no XML report' });
  });

  const filesOnly = (files: string[]) =>
    cppcheckSources({
      projectPath: makeTempDir('cppcheck-gate-'),
      files,
      scoped: false,
      reportDir: makeTempDir('cppcheck-gate-report-'),
      env: {},
      signal: new AbortController().signal,
    });

  it('no C or C++ at all: no entry, nothing probed', async () => {
    const r = await filesOnly(['README.md', 'main.go']);
    expect(r).toEqual({ toolRun: null, missing: [], reports: [], cancelled: false });
    expect(vi.mocked(scannerAvailable)).not.toHaveBeenCalled();
  });

  // 3.6.1: a header-only library produced no entry at all — its code checked
  // by nothing, and nothing said so. Not a gap (an Objective-C project has
  // `.h` files too), but named.
  it('headers and no translation unit: a skipped entry that says so, no gap, nothing probed', async () => {
    const r = await filesOnly(['include/lib.hpp', 'include/detail/impl.h', 'README.md']);
    expect(r.toolRun).toMatchObject({ name: 'cppcheck', status: 'skipped' });
    expect(r.toolRun?.reason).toMatch(/^2 C\/C\+\+ header\(s\) and no translation unit/);
    expect(r.missing).toEqual([]);
    expect(vi.mocked(scannerAvailable)).not.toHaveBeenCalled();
  });
});
