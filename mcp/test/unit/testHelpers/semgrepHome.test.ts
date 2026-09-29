/**
 * `test/setup/semgrepHome.ts` and `semgrepSettings.ts` — the suite's Semgrep
 * runs keep out of the home directory (review 3.0, W2D: the repo's own test
 * runs rewrote the developer's `~/.semgrep/semgrep.log` and
 * `~/.cache/semgrep_version`).
 */

import { mkdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, isAbsolute } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { runSemgrep, semgrepAvailable } from '../../helpers/semgrep.js';
import { spawnSyncCapped } from '../../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { semgrepHomeFiles, snapshot, sweepLegacySettingsDirs, touched } from '../../setup/semgrepHome.js';

afterAll(cleanupTempDirs);

const AVAILABLE = semgrepAvailable();
const inside = (outer: string, inner: string): boolean => {
  const rel = relative(outer, inner);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
};

describe('every worker points Semgrep away from the home directory', () => {
  it.each(['SEMGREP_SETTINGS_FILE', 'SEMGREP_LOG_FILE', 'SEMGREP_VERSION_CACHE_PATH'])(
    '%s is set, inside the run directory, and not where Semgrep keeps its own files',
    (name) => {
      const value = process.env[name];
      expect(value, name).toBeTypeOf('string');
      const runDir = process.env['GUARDIAN_TEST_RUN_DIR'];
      expect(runDir, 'GUARDIAN_TEST_RUN_DIR (the global setup) is set').toBeTypeOf('string');
      expect(inside(String(runDir), String(value)), `${name}=${String(value)}`).toBe(true);
      // Not "not under the home directory": on Windows the temp directory is
      // itself under it (AppData\Local\Temp).
      for (const dir of [join(homedir(), '.semgrep'), join(homedir(), '.cache')]) {
        expect(inside(dir, String(value)), `${name}=${String(value)}`).toBe(false);
      }
    },
  );

  it('the version check is off', () => {
    expect(process.env['SEMGREP_ENABLE_VERSION_CHECK']).toBe('0');
  });

  it.skipIf(!AVAILABLE)('a real Semgrep started with the inherited environment logs into the worker directory', () => {
    const log = String(process.env['SEMGREP_LOG_FILE']);
    const before = snapshot([log]);
    expect(runSemgrep(['--version']).status).toBe(0);
    expect(touched(before, snapshot([log]))).toEqual([log]);
  });

  // The guard's positive control: a Semgrep whose environment drops the
  // redirection writes the home directory it is given, and `touched` names it.
  it.skipIf(!AVAILABLE)('a Semgrep started WITHOUT the redirection writes its home, and the guard names the file', () => {
    const home = makeTempDir('guardian-semgrep-fake-home-');
    const watched = semgrepHomeFiles(home);
    const before = snapshot(watched);
    const {
      SEMGREP_LOG_FILE: _log,
      SEMGREP_SETTINGS_FILE: _settings,
      SEMGREP_VERSION_CACHE_PATH: _version,
      XDG_CONFIG_HOME: _config,
      XDG_CACHE_HOME: _cache,
      ...rest
    } = process.env;
    const run = spawnSyncCapped('semgrep', ['--version'], {
      encoding: 'utf8',
      env: { ...rest, HOME: home, USERPROFILE: home },
      timeout: 60_000,
      windowsHide: true,
    });
    expect(run.status, run.stderr).toBe(0);
    expect(touched(before, snapshot(watched))).toContain(join(home, '.semgrep', 'semgrep.log'));
  });
});

describe('the guard and the sweep (pure)', () => {
  it('snapshot records absence, and touched names a file that appeared or changed', () => {
    const dir = makeTempDir('guardian-home-guard-');
    const a = join(dir, 'a');
    const b = join(dir, 'b');
    writeFileSync(a, 'x');
    const before = snapshot([a, b]);
    expect(before.get(b)).toBe('absent');
    expect(touched(before, snapshot([a, b]))).toEqual([]);
    writeFileSync(b, 'new');
    writeFileSync(a, 'xx');
    expect(touched(before, snapshot([a, b]))).toEqual([a, b]);
  });

  it('removes a legacy settings directory whose process is gone, and keeps a live one', () => {
    const root = join(makeTempDir('guardian-legacy-settings-'), 'guardian-semgrep-settings');
    // A pid far above any real one is not running.
    const dead = join(root, '2147483646-0');
    const live = join(root, `${String(process.pid)}-0`);
    const other = join(root, 'not-a-worker-dir');
    for (const d of [dead, live, other]) mkdirSync(d, { recursive: true });
    sweepLegacySettingsDirs(root);
    expect(() => statSync(dead)).toThrow();
    expect(statSync(live).isDirectory()).toBe(true);
    expect(statSync(other).isDirectory()).toBe(true);
  });

  it('removes the legacy root once it is empty', () => {
    const root = join(makeTempDir('guardian-legacy-settings-'), 'guardian-semgrep-settings');
    mkdirSync(join(root, '2147483646-3'), { recursive: true });
    sweepLegacySettingsDirs(root);
    expect(() => statSync(root)).toThrow();
  });
});
