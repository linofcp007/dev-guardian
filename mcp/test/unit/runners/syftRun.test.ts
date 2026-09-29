/**
 * `runners/syftRun.ts` — every Syft spawn runs in a directory this scan
 * created, with `-c` pointing at an empty file, so the scanned repository's
 * own `.syft.yaml` is never read, and with Syft's update check off. See the
 * module comment for the reproduction.
 *
 * The last test holds the rule for the whole tree: a Syft spawn anywhere in
 * `src/` outside the helper fails it.
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess } from '../../../src/runners/processRunner.js';
import { NEUTRAL_SYFT_CONFIG, runSyft, syftArgv, SYFT_NO_PHONE_HOME_ENV } from '../../../src/runners/syftRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const mockedRun = vi.mocked(runProcess);

beforeEach(() => {
  mockedRun.mockReset();
  mockedRun.mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
});

describe('syftArgv', () => {
  it('names the target, the output, and the empty config explicitly', () => {
    expect(syftArgv({ target: '/p', format: 'cyclonedx-json', outFile: '/r/sbom.cdx.json' }, '/r/cfg.yaml')).toEqual([
      '/p',
      '-o',
      'cyclonedx-json=/r/sbom.cdx.json',
      '--quiet',
      '-c',
      '/r/cfg.yaml',
    ]);
  });
});

describe('runSyft', () => {
  it('runs in the work directory, never the project, with an empty config it wrote there, update check off', async () => {
    const project = makeTempDir('syft-run-project-');
    const work = makeTempDir('syft-run-work-');
    writeFileSync(join(project, '.syft.yaml'), "select-catalogers:\n  - '-javascript'\n");
    await runSyft({ target: project, format: 'spdx-json', outFile: join(work, 'sbom.spdx.json'), workDir: work });

    expect(mockedRun).toHaveBeenCalledTimes(1);
    const call = mockedRun.mock.calls[0]?.[0];
    expect(call?.command).toBe('syft');
    expect(call?.cwd).toBe(work);
    const config = join(work, NEUTRAL_SYFT_CONFIG);
    expect(call?.args).toEqual([project, '-o', `spdx-json=${join(work, 'sbom.spdx.json')}`, '--quiet', '-c', config]);
    const text = readFileSync(config, 'utf8');
    expect(text.split('\n').every((l) => l === '' || l.startsWith('#'))).toBe(true);
    expect(call?.env?.['SYFT_CHECK_FOR_APP_UPDATE']).toBe('false');
    expect(SYFT_NO_PHONE_HOME_ENV).toEqual({ SYFT_CHECK_FOR_APP_UPDATE: 'false' });
  });

  it('a config that cannot be written is a failed run, and Syft is never started without it', async () => {
    const project = makeTempDir('syft-run-project-');
    const blocker = join(project, 'not-a-dir');
    writeFileSync(blocker, 'x');
    const r = await runSyft({ target: project, format: 'cyclonedx-json', outFile: join(blocker, 'o.json'), workDir: join(blocker, 'sub') });
    expect(r.outcome).toBe('failed');
    expect(r.stderr).toMatch(/neutral Syft configuration/);
    expect(mockedRun).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------- the whole tree

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/** A process spawn that names Syft: `command: 'syft'`, or `execa('syft'` / `spawn('syft'` and kin. */
const SYFT_SPAWN = /command:\s*['"`]syft['"`]|\b(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync)\(\s*['"`]syft['"`]/;

/** The one exemption: the toolchain catalogue's `syft version` probe, which reads no project. */
const PROBE_LINE = /probe:\s*\{\s*command:\s*'syft',\s*args:\s*\['version'\][^}]*\}/;

describe('every Syft spawn in src/ goes through runners/syftRun.ts', () => {
  it('no file but the helper spawns Syft', () => {
    const offenders: string[] = [];
    for (const path of tsFiles(SRC)) {
      const rel = relative(SRC, path).split('\\').join('/');
      if (rel === 'runners/syftRun.ts') continue;
      readFileSync(path, 'utf8')
        .split(/\r?\n/)
        .forEach((line, i) => {
          if (SYFT_SPAWN.test(line) && !PROBE_LINE.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it('the pattern catches what it is for (positive control)', () => {
    expect(SYFT_SPAWN.test("      command: 'syft',")).toBe(true);
    expect(SYFT_SPAWN.test("await execa('syft', ['version'])")).toBe(true);
    expect(SYFT_SPAWN.test("producedBy = 'syft';")).toBe(false);
  });
});
