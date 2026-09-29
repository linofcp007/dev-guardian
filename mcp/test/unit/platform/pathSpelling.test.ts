/**
 * Whether a project path read from a DATABASE is a spelling of this
 * project's own path — decided without ever touching the path read.
 *
 * The round-4 check stat'ed every stored path (`statSync(stored)`, then a
 * realpath and an lstat per component) to learn what it spelled. A database
 * is the data of whoever wrote it: an archive with its own `.git` whose
 * database listed four scans under `\\192.0.2.x\share\proj` made the server
 * spend 60 541 ms asking the network before it answered, the MCP client timed
 * out, and a reachable host would have been sent the user's NTLM credentials
 * (macOS `/net` automounts are the POSIX analogue). So the spellings are now
 * DERIVED from the project's own path and compared as strings; the stored
 * path is never given to the file system.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const touched = vi.hoisted(() => [] as string[]);

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  const record =
    <A extends unknown[], R>(fn: (p: import('node:fs').PathLike, ...rest: A) => R) =>
    (p: import('node:fs').PathLike, ...rest: A): R => {
      touched.push(String(p));
      return fn(p, ...rest);
    };
  const statSync = record(actual.statSync as (p: import('node:fs').PathLike) => import('node:fs').Stats);
  const lstatSync = record(actual.lstatSync as (p: import('node:fs').PathLike) => import('node:fs').Stats);
  const existsSync = record(actual.existsSync);
  const accessSync = record(actual.accessSync);
  const readdirSync = record(actual.readdirSync as (p: import('node:fs').PathLike) => string[]);
  const realpathSync = Object.assign(record((p: import('node:fs').PathLike) => actual.realpathSync(p)), {
    native: record((p: import('node:fs').PathLike) => actual.realpathSync.native(p)),
  });
  const replaced = { statSync, lstatSync, existsSync, accessSync, readdirSync, realpathSync };
  return { ...actual, ...replaced, default: { ...actual, ...replaced } };
});

import { isNetworkOrDevicePath, isSpellingOf } from '../../../src/platform/pathSpelling.js';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const isWindows = process.platform === 'win32';

beforeEach(() => {
  touched.length = 0;
});

/** Every stored path below that is not the project's own. */
const FOREIGN = isWindows
  ? [
      '\\\\192.0.2.10\\share\\proj',
      '//192.0.2.10/share/proj',
      '\\\\?\\UNC\\192.0.2.10\\share\\proj',
      '\\\\?\\C:\\Users\\victim\\proj',
      '\\\\.\\PhysicalDrive0',
      '\\??\\C:\\Users\\victim\\proj',
      'C:\\Users\\attacker\\app',
      'Z:\\proj',
    ]
  : ['//192.0.2.10/share/proj', '/net/192.0.2.10/proj', '/home/attacker/app', '/proc/self/cwd'];

describe('a path read from a database', () => {
  it('is never given to the file system, whatever it names', () => {
    const project = canonicalPath(makeTempDir('spelling-'));
    touched.length = 0;
    for (const stored of FOREIGN) expect(isSpellingOf(stored, project)).toBe(false);
    // What the check may look at is the project's own path, never a stored one.
    const fromDatabase = touched.filter((p) => !p.startsWith(project));
    expect(fromDatabase).toEqual([]);
  });

  it('naming a network share, a device or an NT namespace is refused before anything else', () => {
    for (const p of [
      '\\\\server\\share',
      '//server/share',
      '\\/server/share',
      '\\\\?\\C:\\x',
      '\\\\.\\pipe\\x',
      '\\??\\C:\\x',
    ]) {
      expect(isNetworkOrDevicePath(p)).toBe(true);
    }
    for (const p of ['C:\\Users\\me\\proj', '/home/me/proj', 'c:/Users/me/proj']) {
      expect(isNetworkOrDevicePath(p)).toBe(false);
    }
  });

  it("matches the spellings derived from the project's own path — lexically", () => {
    const project = canonicalPath(makeTempDir('spelling-'));
    const spellings = isWindows
      ? [
          project,
          project.charAt(0).toLowerCase() + project.slice(1), // 2.0.0: resolve() kept the typed drive letter
          project.replace(/\\/g, '/'),
          `${project}\\`,
          `${project}\\.`,
          project.replace(/\\/g, '\\\\'),
          project.toUpperCase(),
        ]
      : [project, `${project}/`, `${project}/.`, project.replace(/\//g, '//')];
    touched.length = 0;
    for (const s of spellings) expect({ s, match: isSpellingOf(s, project) }).toEqual({ s, match: true });
    expect(touched.filter((p) => !p.startsWith(project))).toEqual([]);
  });

  it('never matches a parent, a child, a sibling or a `..` detour', () => {
    const base = makeTempDir('spelling-');
    mkdirSync(join(base, 'proj', 'sub'), { recursive: true });
    mkdirSync(join(base, 'other'));
    const project = canonicalPath(join(base, 'proj'));
    for (const s of [
      canonicalPath(base),
      join(project, 'sub'),
      canonicalPath(join(base, 'other')),
      // Written out: path.join would fold the `..` away.
      `${project}${isWindows ? '\\sub\\..' : '/sub/..'}`,
      `${project}x`,
    ]) {
      expect({ s, match: isSpellingOf(s, project) }).toEqual({ s, match: false });
    }
  });

  // The 8.3 spelling is derived from the PROJECT's path, through the short
  // name API (cmd's `%~s`), never from the stored one.
  it.runIf(isWindows)("matches the project's own 8.3 short spelling, and nothing else with a tilde", () => {
    const project = canonicalPath(makeTempDir('spelling-long-directory-name-'));
    const r = spawnSync('cmd.exe', ['/d', '/s', '/c', `"for %I in ("${project}") do @echo %~sI"`], {
      encoding: 'utf8',
      windowsVerbatimArguments: true,
    });
    const short = r.stdout.trim();
    if (short === project) return; // 8.3 names are off on this volume
    touched.length = 0;
    expect(isSpellingOf(short, project)).toBe(true);
    expect(isSpellingOf(short.charAt(0).toLowerCase() + short.slice(1), project)).toBe(true);
    expect(isSpellingOf(short.replace(/~\d+/, '~9'), project)).toBe(false);
    expect(touched.filter((p) => !p.startsWith(project))).toEqual([]);
  });
});
