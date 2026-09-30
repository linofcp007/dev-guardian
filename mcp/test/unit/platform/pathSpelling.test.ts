/**
 * Stored project paths: what is never looked at, and where the rest lead.
 *
 * A path in a database is data. Round 5 of the 3.0 review measured what
 * looking one up costs: four scans under `\\192.0.2.x\share\proj` held the
 * server 60 541 ms before it answered, and a reachable host would have been
 * sent the user's NTLM credentials. Since round 6 no stored path is read to
 * judge a database at all (there is no automatic adoption); two readers of
 * the user's OWN database remain — the startup rewrite of 2.0.0 spellings and
 * `db adopt --rehome` — and both refuse network, device and process-relative
 * paths before any look. Proven here by recording every `fs` call.
 */

import { mkdirSync, symlinkSync } from 'node:fs';
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
  const realpathSync = Object.assign(record((p: import('node:fs').PathLike) => actual.realpathSync(p)), {
    native: record((p: import('node:fs').PathLike) => actual.realpathSync.native(p)),
  });
  const replaced = { statSync, lstatSync, existsSync, realpathSync };
  return { ...actual, ...replaced, default: { ...actual, ...replaced } };
});

import {
  isNetworkOrDevicePath,
  isUnresolvablePath,
  spellingOnlyCanonical,
  storedPathTarget,
} from '../../../src/platform/pathSpelling.js';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const isWindows = process.platform === 'win32';

beforeEach(() => {
  touched.length = 0;
});

const NEVER_LOOKED_AT = [
  '\\\\192.0.2.10\\share\\proj',
  '//192.0.2.10/share/proj',
  '\\/192.0.2.10/share/proj',
  '\\\\?\\UNC\\192.0.2.10\\share\\proj',
  '\\\\?\\C:\\Users\\victim\\proj',
  '\\\\.\\PhysicalDrive0',
  '\\??\\C:\\Users\\victim\\proj',
];

describe('a stored path', () => {
  it('naming a network share, a device or an NT namespace is refused before anything else', () => {
    for (const p of NEVER_LOOKED_AT) expect(isNetworkOrDevicePath(p)).toBe(true);
    for (const p of ['C:\\Users\\me\\proj', '/home/me/proj', 'c:/Users/me/proj']) {
      expect(isNetworkOrDevicePath(p)).toBe(false);
    }
  });

  it("whose meaning is the reader's (/proc/self/cwd, /dev/fd) or mounts on a look (/net) is never resolved", () => {
    for (const p of ['/proc/self/cwd', '/proc/1/root/home', '/dev/fd/3', '/net/192.0.2.10/export']) {
      expect(isUnresolvablePath(p)).toBe(true);
    }
    for (const p of ['/home/me/proj', '/network/proj', '/procedures']) expect(isUnresolvablePath(p)).toBe(false);
  });

  it('is never given to the file system by either reader when it is one of those', () => {
    const project = canonicalPath(makeTempDir('spelling-'));
    touched.length = 0;
    for (const stored of [...NEVER_LOOKED_AT, '/proc/self/cwd', '/net/192.0.2.10/export']) {
      expect(spellingOnlyCanonical(stored)).toBeNull();
      expect(storedPathTarget(stored, project)).toBe('unresolved');
    }
    expect(touched).toEqual([]);
  });

  it('db adopt --rehome: where each path leads — links followed — and only this project is "this-project"', () => {
    const base = makeTempDir('spelling-');
    mkdirSync(join(base, 'proj'));
    mkdirSync(join(base, 'other'));
    const project = canonicalPath(join(base, 'proj'));
    const link = join(base, 'lnk');
    symlinkSync(join(base, 'proj'), link, isWindows ? 'junction' : 'dir');
    expect(storedPathTarget(project, project)).toBe('canonical');
    expect(storedPathTarget(link, project)).toBe('this-project');
    expect(storedPathTarget(`${project}${isWindows ? '\\' : '/'}.`, project)).toBe('this-project');
    if (isWindows) expect(storedPathTarget(project.charAt(0).toLowerCase() + project.slice(1), project)).toBe('this-project');
    expect(storedPathTarget(canonicalPath(join(base, 'other')), project)).toBe('elsewhere');
    expect(storedPathTarget(join(base, 'gone'), project)).toBe('missing');
    expect(storedPathTarget('relative/proj', project)).toBe('unresolved');
  });

  it('the startup rewrite: a spelling of the same directory entries, never a path through a link', () => {
    const base = makeTempDir('spelling-');
    mkdirSync(join(base, 'proj'));
    const project = canonicalPath(join(base, 'proj'));
    const link = join(base, 'lnk');
    symlinkSync(join(base, 'proj'), link, isWindows ? 'junction' : 'dir');
    expect(spellingOnlyCanonical(project)).toBeNull(); // already canonical
    expect(spellingOnlyCanonical(link)).toBeNull();
    if (isWindows) expect(spellingOnlyCanonical(project.charAt(0).toLowerCase() + project.slice(1))).toBe(project);
  });
});
