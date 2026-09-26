/**
 * `wordpress/siteKeys.ts` — the keys a WordPress install's rows are looked up
 * under (Task 24, fix rounds 1 and 2).
 *
 * A relative path is only a spelling of ONE install when it exists here:
 * resolved against the server's working directory, two remote installs both
 * passed as "wp" would share one key — and a nonexistent path could resolve
 * onto a real, unrelated project. So a relative path that does not exist
 * contributes no alias, and a caller rejects it (`wpInstallPathProblem`).
 */

import { isAbsolute, join, relative, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { wpInstallKeys, wpInstallPathProblem, wpSiteKeys } from '../../../src/wordpress/siteKeys.js';

afterAll(cleanupTempDirs);

const MISSING_RELATIVE = 'guardian-no-such-wp-install';

describe('wpInstallKeys', () => {
  it('never resolves a relative path that does not exist against the server cwd', () => {
    const canonical = canonicalPath(makeTempDir('sitekeys-'));
    const keys = wpInstallKeys(canonical, MISSING_RELATIVE);
    expect(keys).toEqual([canonical]);
    expect(keys).not.toContain(resolve(MISSING_RELATIVE));
  });

  it('an existing relative path is a real directory: its raw and resolved spellings are aliases', () => {
    const dir = makeTempDir('sitekeys-');
    const rel = relative(process.cwd(), dir);
    const keys = wpInstallKeys(canonicalPath(dir), rel);
    expect(keys).toEqual(expect.arrayContaining([canonicalPath(dir), rel, resolve(rel)]));
  });

  it('an absolute path is its own key whether or not it exists here (a remote install by its server path)', () => {
    const remote = join(makeTempDir('sitekeys-'), 'remote', 'wp');
    expect(isAbsolute(remote)).toBe(true);
    const keys = wpInstallKeys(canonicalPath(remote), remote);
    expect(keys).toEqual(expect.arrayContaining([canonicalPath(remote), remote]));
  });
});

describe('wpInstallPathProblem', () => {
  it('rejects a relative path that does not exist, and says what to pass instead', () => {
    const problem = wpInstallPathProblem(MISSING_RELATIVE);
    expect(problem).toMatch(/absolute path/);
    expect(problem).toMatch(/target_url/);
  });

  it('accepts an absolute path (existing or not) and an existing relative one', () => {
    const dir = makeTempDir('sitekeys-');
    expect(wpInstallPathProblem(join(dir, 'remote', 'wp'))).toBeNull();
    expect(wpInstallPathProblem(dir)).toBeNull();
    expect(wpInstallPathProblem(relative(process.cwd(), dir))).toBeNull();
  });
});

describe('wpSiteKeys', () => {
  it('a URL with and without its trailing slash, and as given', () => {
    expect(wpSiteKeys('https://site.example/')).toEqual(['https://site.example', 'https://site.example/']);
    expect(wpSiteKeys('https://site.example')).toEqual(['https://site.example', 'https://site.example/']);
  });
});
