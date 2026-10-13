/**
 * Review 10, finding 1: only the ROOT `.guardian/`'s generated output is left
 * out of a scan, by exact project-relative path — never a `.guardian` folder
 * below the root, which is the project's code.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { GUARDIAN_OUTPUT_PATHS, isGuardianOutput } from '../../../src/platform/guardianOutput.js';
import { directoryConfig } from '../../../src/runners/gitleaksScan.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('isGuardianOutput', () => {
  it('the root reports, database, dashboard and the CLI’s .gitignore — in any separator', () => {
    for (const p of [
      '.guardian/reports/sast-1/sast.json',
      '.guardian\\reports\\x.js',
      './.guardian/reports',
      '.guardian/guardian.db',
      '.guardian/guardian.db-wal',
      '.guardian/dashboard.html',
      '.guardian/last-grill.md',
      '.guardian/.gitignore',
    ]) {
      expect(isGuardianOutput(p), p).toBe(true);
    }
  });

  it('never a .guardian below the root, nor what a team shares or adds at the root', () => {
    for (const p of [
      'lib/.guardian/handler.js',
      'lib/.guardian/reports/x.js',
      'packages/api/.guardian/guardian.db',
      '.guardian/handler.js',
      '.guardian/baseline.json',
      '.guardian/scan.yml',
      '.guardian/reportsx/x.js',
      '.guardian/guardian.dbx',
      '.guardian',
    ]) {
      expect(isGuardianOutput(p), p).toBe(false);
    }
  });

  it('every generated path is under the root .guardian/', () => {
    for (const p of GUARDIAN_OUTPUT_PATHS) expect(p.startsWith('.guardian/'), p).toBe(true);
  });
});

describe("gitleaks' in-place directory config", () => {
  /** The allowlist's path regexes, as JavaScript reads them (the same syntax gitleaks' RE2 does here). */
  function allowlist(): RegExp[] {
    const config = directoryConfig(makeTempDir('gl-dircfg-'));
    const line = config.split('\n').find((l) => l.startsWith('paths = ['));
    expect(line).toBeDefined();
    return [...(line ?? '').matchAll(/'''(.*?)'''/g)].map((m) => new RegExp(m[1] ?? ''));
  }

  it('allowlists the root output, anchored — never lib/.guardian (review 10, finding 1)', () => {
    const res = allowlist();
    const allowed = (p: string): boolean => res.some((re) => re.test(p));
    expect(allowed('.guardian/reports/secrets-1/copy.js')).toBe(true);
    expect(allowed('.guardian/guardian.db')).toBe(true);
    expect(allowed('node_modules/x/index.js')).toBe(true);
    expect(allowed('lib/.guardian/creds.js')).toBe(false);
    expect(allowed('lib/.guardian/reports/creds.js')).toBe(false);
    expect(allowed('.guardian/creds.js')).toBe(false);
    expect(allowed('src/creds.js')).toBe(false);
  });
});
