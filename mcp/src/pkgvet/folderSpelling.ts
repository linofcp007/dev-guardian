/**
 * One folder, written two ways (install-vet-path-forms). On Windows a folder has a long spelling and a short 8.3 one
 * (`PROJEC~1`), and the case of either may differ; a path compared as text then calls one folder two. This module says,
 * from a closed grammar, when two spellings are the one folder: component by component from a local drive root that is
 * itself, each component a directory reached through no link, written as the name the disk has (in other case) or as
 * its 8.3 name. Anything else is `null`, and the caller answers as before: a hook fails open.
 *
 * Windows only (`platform`): elsewhere there are no short names and every answer is `null`, asking nothing.
 * The Windows path functions are used on every platform, so the grammar is the same wherever it is tested.
 * No network I/O: a path that {@link isNetworkPath} knows is never asked of the disk. The disk is asked through
 * `deps` (the real ones by {@link systemDisk}), each folder at most once per hook call (`memo`).
 */
import { lstatSync, realpathSync } from 'node:fs';
import { win32 } from 'node:path';
import { isNetworkPath } from '../hooks/configFile.js';

/** The part of `fs.Stats` the grammar reads. */
type DiskStat = { isDirectory(): boolean; isSymbolicLink(): boolean };

/** What the disk is asked: `lstat` (follows no link) and the real path. Tests give counting ones. */
export interface DiskDeps {
  lstat: (path: string) => DiskStat;
  realpath: (path: string) => string;
}

/** The answers of one hook call: a folder is asked of the disk once, whatever the number of commands that name it. */
export type SpellingMemo = Map<string, string | null>;

/** The most components below the drive root a path may have; the 64th is accepted, the 65th is `null`. */
const MAX_COMPONENTS = 64;

/** The real dependencies: `lstatSync` and `realpathSync.native` (the one direct call of the new code). */
export const systemDisk: DiskDeps = {
  lstat: (path) => lstatSync(path),
  realpath: (path) => realpathSync.native(path),
};

const DRIVE_ROOT = /^[A-Za-z]:\\$/;
const SHORT_NAME =
  /^(?=[^.]{1,8}(?:\.|$))[A-Za-z0-9$%'@~!(){}^#&_`-]{1,6}~[1-9][0-9]{0,5}(?:\.[A-Za-z0-9$%'@~!(){}^#&_`-]{1,3})?$/;

/** Whether `name` is spelled as an 8.3 short name: up to eight characters before the dot, `~` and digits, an extension of one to three. */
export function isShortName(name: string): boolean {
  return SHORT_NAME.test(name);
}

const same = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/** The real path of `path` through `memo` (a failure is `null`, remembered). The caller has ruled out a network path. */
function realOf(path: string, memo: SpellingMemo, deps: DiskDeps): string | null {
  const key = `real\0${path}`;
  const known = memo.get(key);
  if (known !== undefined) return known;
  let answer: string | null;
  try {
    answer = deps.realpath(path);
  } catch {
    answer = null; // fail-open: the caller answers as before
  }
  memo.set(key, answer);
  return answer;
}

/**
 * The real path of the folder that the component `typed` names inside the folder whose real path is `realParent`
 * (`path` is that folder joined with `typed`) — when `path` is no network path, `lstat` says a directory and no link
 * (a symbolic link, a junction), the real path is `realParent` plus one name, and `typed` is that name in other case or
 * an 8.3 short name. Otherwise `null`: a trailing dot or space, a stream suffix, a component that is not there, a failure.
 */
export function diskStep(realParent: string, path: string, typed: string, memo: SpellingMemo, deps: DiskDeps): string | null {
  if (isNetworkPath(path) || typed === '' || /[. ]$|[:<>"|?*]/.test(typed)) return null;
  const key = `step\0${realParent}\0${typed}`;
  const known = memo.get(key);
  if (known !== undefined) return known;
  let answer: string | null = null;
  try {
    const kind = deps.lstat(path);
    if (kind.isDirectory() && !kind.isSymbolicLink()) {
      const real = deps.realpath(path);
      const name = win32.basename(real);
      if (same(win32.dirname(real), realParent) && name !== '' && (same(typed, name) || isShortName(typed))) answer = real;
    }
  } catch {
    answer = null; // fail-open: a folder the disk cannot describe is not the same folder
  }
  memo.set(key, answer);
  return answer;
}

/**
 * The real path of a whole absolute path, component by component with {@link diskStep} from the drive root — which is
 * checked by its text first (`X:\`, which leaves out `\\?\C:\…`, `\\.\C:\…` and every UNC path, asking nothing) and
 * then by its real path being itself (which leaves out a `subst` drive for another folder). At most
 * {@link MAX_COMPONENTS} components below the root. `null` for the rest, and for any platform but Windows.
 */
export function diskSpelling(path: string, memo: SpellingMemo, deps: DiskDeps = systemDisk, platform: NodeJS.Platform = process.platform): string | null {
  if (platform !== 'win32' || isNetworkPath(path)) return null;
  const whole = win32.resolve(path);
  const root = win32.parse(whole).root;
  if (!DRIVE_ROOT.test(root) || isNetworkPath(whole)) return null;
  const key = `spell\0${whole}`;
  const known = memo.get(key);
  if (known !== undefined) return known;
  const parts = whole.slice(root.length).split('\\').filter((part) => part !== '');
  let answer: string | null = null;
  if (parts.length <= MAX_COMPONENTS) {
    const rootReal = realOf(root, memo, deps);
    if (rootReal !== null && same(rootReal, root)) {
      answer = rootReal;
      for (const typed of parts) {
        const next = diskStep(answer, win32.join(answer, typed), typed, memo, deps);
        if (next === null) {
          answer = null;
          break;
        }
        answer = next;
      }
    }
  }
  memo.set(key, answer);
  return answer;
}

/**
 * The folders no real root of a climb may be, nor contain: each home directory (`homeDir` and the system's) as
 * resolved and by its real path — the wider equivalence, links included, since this is an exclusion. The real path
 * is never asked for a network path; a failure gives nothing beyond the `resolve`.
 */
export function homeBarrier(homes: ReadonlyArray<string | undefined>, memo: SpellingMemo, deps: DiskDeps = systemDisk): string[] {
  const out: string[] = [];
  for (const home of homes) {
    if (home === undefined || home === '') continue;
    const here = win32.resolve(home);
    out.push(here);
    if (isNetworkPath(here)) continue;
    const real = realOf(here, memo, deps);
    if (real !== null) out.push(real);
  }
  return out;
}

/** Whether a real `root` is a barred folder or holds one (a home directory, or a folder above it). */
export function rootBarred(root: string, barrier: readonly string[]): boolean {
  return barrier.some((home) => {
    const rel = win32.relative(root, home);
    return rel === '' || (rel !== '..' && !rel.startsWith('..\\') && !win32.isAbsolute(rel));
  });
}
