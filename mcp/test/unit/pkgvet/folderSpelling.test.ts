import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  diskSpelling,
  diskStep,
  homeBarrier,
  isShortName,
  rootBarred,
  systemDisk,
  type DiskDeps,
  type SpellingMemo,
} from '../../../src/pkgvet/folderSpelling.js';
import { hangBound } from '../../helpers/timing.js';

// The module of install-vet-path-forms: when two spellings of a path are one folder (T-06; written with the module).

const BS = '\\';
const WINDOWS = process.platform === 'win32';

/** The short (8.3) spelling of an existing folder, as the system says it: `cmd.exe` by its whole path, run in the folder. */
const shortOf = (dir: string): string =>
  (
    spawnSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'cmd.exe'), ['/d', '/c', '"for %I in (.) do @echo %~sI"'], {
      cwd: dir,
      encoding: 'utf8',
      windowsVerbatimArguments: true,
    }).stdout ?? ''
  ).trim();

/** Decided once per file: Windows, a volume that gives short names, and the two spellings are one folder. */
const SHORT_NAMES = ((): boolean => {
  if (!WINDOWS) return false;
  const probe = mkdtempSync(join(tmpdir(), 'dg spelling probe '));
  try {
    const short = shortOf(probe);
    return short !== '' && short.toLowerCase() !== probe.toLowerCase() && realpathSync.native(short) === realpathSync.native(probe);
  } catch {
    // No `cmd.exe`, or a volume without short names: the tests that need them are skipped, with their label saying so.
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();
const ifShort = it.skipIf(!SHORT_NAMES);
const ifWindows = it.skipIf(!WINDOWS);

/** A disk that says every folder is a directory and its own real path, except what a test changes; it counts what it was asked. */
function fakeDisk(change: { links?: readonly string[]; real?: Record<string, string> } = {}): { deps: DiskDeps; lstat: string[]; realpath: string[] } {
  const lstat: string[] = [];
  const realpath: string[] = [];
  const deps: DiskDeps = {
    lstat: (path) => {
      lstat.push(path);
      return { isDirectory: () => true, isSymbolicLink: () => change.links?.includes(path) === true };
    },
    realpath: (path) => {
      realpath.push(path);
      return change.real?.[path] ?? path;
    },
  };
  return { deps, lstat, realpath };
}

describe('install-vet-path-forms', () => {
  let base: string;
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'dg spelling '));
  });
  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  const memo = (): SpellingMemo => new Map();

  ifShort('T-06 (a) (Windows, a volume with 8.3 names; skipped otherwise) the short spelling, and another case, give the real path; a step gives the real path of its short leaf', () => {
    const sub = join(base, 'project with a long name', 'sub folder inside');
    mkdirSync(sub, { recursive: true });
    const real = realpathSync.native(sub);
    expect(diskSpelling(shortOf(sub), memo())).toBe(real);
    expect(diskSpelling(sub.toUpperCase(), memo())).toBe(real);
    const parent = realpathSync.native(join(base, 'project with a long name'));
    const leaf = basename(shortOf(sub));
    expect(diskStep(parent, join(parent, leaf), leaf, memo(), systemDisk)).toBe(real);
  });

  ifWindows('T-06 (b) (Windows; skipped otherwise) a trailing dot or space, a stream suffix and a device prefix give null; 64 components below the drive are accepted, 65 are not', () => {
    const sub = join(base, 'sub folder inside');
    mkdirSync(sub);
    const real = realpathSync.native(sub);
    expect(diskSpelling(sub, memo())).toBe(real);
    expect(diskSpelling(`${sub}.`, memo())).toBeNull();
    expect(diskSpelling(`${sub} `, memo())).toBeNull();
    expect(diskSpelling(`${sub}::$INDEX_ALLOCATION`, memo())).toBeNull();
    expect(diskSpelling(`${BS}${BS}?${BS}${real}`, memo())).toBeNull();
    expect(diskSpelling(`${BS}${BS}.${BS}${real}`, memo())).toBeNull();
    const depth = base.split(BS).length - 1; // components below the drive root
    const chain = (count: number): string => join(base, ...Array.from({ length: count }, () => 'd'));
    const at64 = chain(64 - depth);
    mkdirSync(at64, { recursive: true });
    expect(diskSpelling(at64, memo())).toBe(realpathSync.native(at64));
    const at65 = chain(65 - depth);
    mkdirSync(at65, { recursive: true });
    expect(diskSpelling(at65, memo())).toBeNull();
  });

  it('T-06 (c) a link in the path gives null, and nothing below it is asked', () => {
    const disk = fakeDisk({ links: [`C:${BS}proj${BS}link`] });
    expect(diskSpelling(`C:${BS}proj${BS}link${BS}deep`, memo(), disk.deps, 'win32')).toBeNull();
    expect(disk.lstat).not.toContain(`C:${BS}proj${BS}link${BS}deep`);
    expect(diskSpelling(`C:${BS}proj${BS}plain`, memo(), disk.deps, 'win32')).toBe(`C:${BS}proj${BS}plain`);
  });

  ifWindows('T-06 (c) (Windows; skipped otherwise) a junction on the disk in the path gives null', () => {
    const target = join(base, 'target folder');
    mkdirSync(target);
    const link = join(base, 'a junction');
    symlinkSync(target, link, 'junction');
    try {
      expect(diskSpelling(link, memo())).toBeNull();
      expect(diskSpelling(target, memo())).toBe(realpathSync.native(target));
    } finally {
      rmSync(link, { force: true });
    }
  });

  it.each([`${BS}${BS}198.51.100.7${BS}share${BS}proj`, '//198.51.100.7/share/proj', `${BS}${BS}?${BS}UNC${BS}198.51.100.7${BS}share${BS}proj`])(
    'T-06 (d) the network path %s gives null, and the disk is never asked',
    (path) => {
      const disk = fakeDisk();
      expect(diskSpelling(path, memo(), disk.deps, 'win32')).toBeNull();
      expect(diskStep(path, `${path}${BS}x`, 'x', memo(), disk.deps)).toBeNull();
      expect(disk.lstat).toEqual([]);
      expect(disk.realpath).toEqual([]);
      const t0 = performance.now();
      expect(diskSpelling(path, memo(), systemDisk, 'win32')).toBeNull();
      expect(performance.now() - t0).toBeLessThan(hangBound(2000));
    },
  );

  it('T-06 (e) the same folder of 8 components asked 6 800 times with one Map: the real path is asked at most 9 times', () => {
    const disk = fakeDisk();
    const path = `C:${BS}${['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].join(BS)}`;
    const shared = memo();
    for (let i = 0; i < 6_800; i += 1) expect(diskSpelling(path, shared, disk.deps, 'win32')).toBe(path);
    expect(disk.realpath.length).toBeLessThanOrEqual(9);
  });

  it.each(['linux', 'darwin'] as const)('T-06 (f) on %s every path gives null, and nothing is asked', (platform) => {
    const disk = fakeDisk();
    expect(diskSpelling(`C:${BS}proj`, memo(), disk.deps, platform)).toBeNull();
    expect(diskSpelling('/home/user/proj', memo(), disk.deps, platform)).toBeNull();
    expect(disk.lstat).toEqual([]);
    expect(disk.realpath).toEqual([]);
  });

  it('T-06 (g) isShortName accepts the 8.3 forms and refuses the rest', () => {
    for (const name of ['PROJEC~1', 'projec~1', 'DG9686~1', 'ADMINI~1', 'HOOKSC~1.JSO', 'A~1']) expect(isShortName(name), name).toBe(true);
    for (const name of ['PROJECT~', 'PROJEC~0', 'TOOLONGN~1', 'PROJ~1.ABCD', 'PROJ~1.', 'PRO JE~1', '~1', 'proj.']) expect(isShortName(name), name).toBe(false);
  });

  it('T-06 (h) the home barrier holds the real homes and what is above them, not what is below', () => {
    const disk = fakeDisk({ real: { [`C:${BS}Users${BS}x`]: `D:${BS}Users${BS}x` } });
    const barrier = homeBarrier([`C:${BS}Users${BS}x`, `C:${BS}Users${BS}y`], memo(), disk.deps);
    for (const root of [`D:${BS}Users${BS}x`, `D:${BS}Users`, `C:${BS}Users${BS}y`, `C:${BS}`]) expect(rootBarred(root, barrier), root).toBe(true);
    expect(rootBarred(`D:${BS}Users${BS}x${BS}proj`, barrier)).toBe(false);
    // A home on the network: its real path is never asked, and its `resolve` stays in the barrier.
    const network = fakeDisk();
    const home = `${BS}${BS}198.51.100.7${BS}share${BS}x`;
    const held = homeBarrier([home], memo(), network.deps);
    expect(network.realpath).toEqual([]);
    expect(held).toEqual([home]);
  });

  it('T-06 (i) a mapped drive whose root is a share gives null after one question', () => {
    const disk = fakeDisk({ real: { [`Z:${BS}`]: `${BS}${BS}host${BS}share${BS}` } });
    expect(diskSpelling(`Z:${BS}proj`, memo(), disk.deps, 'win32')).toBeNull();
    expect(disk.realpath).toEqual([`Z:${BS}`]);
  });
});
