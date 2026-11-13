/**
 * The environment the selftest's real runners start a scanner with
 * (`src/selftest/defaultRunners.ts#scannerEnv`).
 *
 * Measured before this existed: a selftest handed a COPY of the environment —
 * which the orchestrator makes for every Semgrep run and every caller may —
 * found gitleaks and Trivy with the probe (which looks in the per-user tools
 * directory) and then could not start them: "not found on PATH". Three
 * controls came out `unverified` on a machine where all three detect.
 *
 * The runs with the real scanners are `test/e2e/selftestCli.test.ts`'s.
 */

import { existsSync } from 'node:fs';
import { delimiter } from 'node:path';
import { describe, expect, it } from 'vitest';
import { pathHasDir, userBinDir } from '../../../src/platform/userBin.js';
import { scannerEnv } from '../../../src/selftest/defaultRunners.js';

const pathKeys = (env: NodeJS.ProcessEnv): string[] => Object.keys(env).filter((key) => key.toUpperCase() === 'PATH');
const userBin = userBinDir();
const userBinThere = userBin !== null && existsSync(userBin);

describe('the environment a scanner is started with', () => {
  it('a copy of the environment keeps its entries, in order, and gains the per-user tools directory', () => {
    const base = ['/opt/one', '/opt/two'].join(delimiter);
    const copy: NodeJS.ProcessEnv = { PATH: base, GUARDIAN_OFFLINE: '1', SEMGREP_SETTINGS_FILE: '/tmp/x.yml' };
    const before = JSON.stringify(copy);
    const out = scannerEnv(copy);
    // The caller's object is theirs: never written to.
    expect(JSON.stringify(copy)).toBe(before);
    expect(out).not.toBe(copy);
    expect(out['PATH']?.startsWith(base)).toBe(true);
    expect(out['GUARDIAN_OFFLINE']).toBe('1');
    expect(out['SEMGREP_SETTINGS_FILE']).toBe('/tmp/x.yml');
    // Where the directory exists, a scanner installed there is found again when it is run.
    expect(pathHasDir(userBin ?? '', out['PATH'] ?? '')).toBe(userBinThere);
    // Once on it, never twice.
    const again = scannerEnv(out);
    expect(again['PATH']).toBe(out['PATH']);
  });

  it.runIf(process.platform === 'win32')('a Windows environment that spells it Path comes out with one PATH key', () => {
    const out = scannerEnv({ Path: 'C:\\tools', SystemRoot: 'C:\\Windows' });
    expect(pathKeys(out)).toEqual(['PATH']);
    expect(out['PATH']?.startsWith('C:\\tools')).toBe(true);
    expect(out['SystemRoot']).toBe('C:\\Windows');
    // Both spellings at once: still one key, and a value that one of them had.
    const both = scannerEnv({ Path: 'C:\\from-Path', PATH: 'C:\\from-PATH' });
    expect(pathKeys(both)).toEqual(['PATH']);
    expect(both['PATH']).toMatch(/^C:\\from-PATH/);
  });

  it('an environment with no PATH at all gets this process’s, so that a scanner can still be found', () => {
    const out = scannerEnv({ ONLY: 'this' });
    expect(pathKeys(out)).toEqual(['PATH']);
    expect(out['ONLY']).toBe('this');
    const own = process.env['PATH'] ?? '';
    expect(own.length).toBeGreaterThan(0);
    expect(out['PATH']?.startsWith(own)).toBe(true);
  });
});
