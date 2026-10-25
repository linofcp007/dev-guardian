/**
 * `banditOnFiles` against the REAL Bandit on PATH (review 3.6.1, finding 4).
 *
 * Bandit tests its exclusion list — its built-in
 * `.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg` unless `-x` or an
 * ini's `exclude` replaces it — as a SUBSTRING of every path, files handed by
 * name included. Measured on Bandit 1.9.4 in a directory with no `.git`: of
 * `src/CVSImport.py`, `lib/x.tox_util.py`, `pkg/my.eggs_helper.py`,
 * `a/.hg_tools.py`, `.github/scripts/ci.py`, `.gitlab/ci.py` and two plain
 * files, two were analysed — the rest left out of `metrics` with no error.
 *
 * Gated on Bandit being on PATH.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { banditOnFiles } from '../../src/runners/fileBatchScan.js';
import { NEUTRAL_BANDIT_INI_TEXT } from '../../src/tools/scanSast.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });
afterAll(cleanupTempDirs);

const BANDIT_INSTALLED = await isInstalled('bandit');
const CODE = 'import subprocess\nsubprocess.call(input(), shell=True)\n';
const FILES = ['src/CVSImport.py', 'lib/x.tox_util.py', 'pkg/my.eggs_helper.py', 'a/.hg_tools.py', '.github/scripts/ci.py', '.gitlab/ci.py', 'app/ok.py', 'pkg/wheel.egg/inner.py'];

function project(): string {
  const dir = makeTempDir('bandit-handed-');
  for (const rel of FILES) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), CODE);
  }
  return dir;
}

describe.skipIf(!BANDIT_INSTALLED)('banditOnFiles: every file it is handed is analysed, or named', () => {
  it('with no configuration, a file whose path holds one of its exclusions is analysed all the same', async () => {
    const dir = project();
    const run = await banditOnFiles({ files: FILES, cwd: dir, reportDir: makeTempDir('bandit-handed-out-'), env: process.env, signal: new AbortController().signal });
    expect(run.toolRun.status).toBe('ok');
    expect(run.partial).toEqual([]);
    const analysed = run.reports.flatMap((r) => Object.keys((JSON.parse(r) as { metrics: Record<string, unknown> }).metrics)).filter((k) => k !== '_totals');
    // Bandit names a relative file `./<path>`.
    expect(analysed.map((k) => k.split('\\').join('/').replace(/^\.\//, '')).sort()).toEqual([...FILES].sort());
  });

  it('with an ini whose exclusions apply (an empty one: Bandit falls back to its list), each file left out is a named gap', async () => {
    const dir = project();
    const ini = join(dir, 'neutral.ini');
    writeFileSync(ini, '[bandit]\n');
    const run = await banditOnFiles({ files: FILES, ini, cwd: dir, reportDir: makeTempDir('bandit-handed-out-'), env: process.env, signal: new AbortController().signal });
    expect(run.toolRun.status).toBe('ok');
    const left = run.partial.filter((p) => p.type === 'Not analysed').map((p) => p.file);
    expect(left).toEqual(expect.arrayContaining(['src/CVSImport.py', 'lib/x.tox_util.py', 'pkg/my.eggs_helper.py', 'a/.hg_tools.py']));
    expect(left).not.toContain('app/ok.py');
    expect(run.toolRun.partially_parsed?.length).toBe(left.length);
  });

  it("scan_sast's neutral ini (no root .bandit) replaces that list too: every handed file is analysed", async () => {
    const dir = project();
    const ini = join(dir, 'bandit-neutral.ini');
    writeFileSync(ini, NEUTRAL_BANDIT_INI_TEXT);
    const run = await banditOnFiles({ files: FILES, ini, cwd: dir, reportDir: makeTempDir('bandit-handed-out-'), env: process.env, signal: new AbortController().signal });
    expect(run.toolRun.status).toBe('ok');
    expect(run.partial).toEqual([]);
  });
});
