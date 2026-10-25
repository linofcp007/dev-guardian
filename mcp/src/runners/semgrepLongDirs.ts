/**
 * Semgrep and Windows' path limits — measured on Semgrep 1.176.1 with
 * Windows' default `LongPathsEnabled=0`, 2026-10-25, and again on 1.182.0
 * (the version the CI templates pin), 2026-10-24: the same. Its engine,
 * `semgrep-core.exe`, has a manifest without `longPathAware`, so turning
 * `LongPathsEnabled` on does not lift either limit for it (Windows needs
 * both); its Python CLI is long-path aware.
 *
 *   - A FILE at a path of 260 characters or more cannot be opened by path —
 *     but the same file handed as an extended-length path (`\\?\C:\…`, an
 *     explicit target) is read: a 305-character file was. A drive letter
 *     (`subst`) also works; a directory junction did not on 1.176.1 (Semgrep
 *     resolved it back to the long path) and did on 1.182.0.
 *   - One DIRECTORY at a path of 256 characters or more anywhere in the tree
 *     (256–259, and 261 up; one of exactly 260 was listed on 1.176.1, not on
 *     1.182.0) makes the walk fail
 *     the whole listing — `Failed to obtain target files from semgrep-core`,
 *     nothing scanned, the root's files included. A WordPress install copied
 *     off a server is the usual shape (WooCommerce 11.2.1's
 *     `packages/email-editor/…/Blocks/icons/*` under a deep folder). In a git
 *     repository Semgrep lists through git and is not affected (git itself
 *     cannot add such a directory without `core.longpaths`).
 *   - `--exclude=<the directory, project-relative>` keeps the walk out of it
 *     and the rest is listed, every `.semgrepignore` still honoured — explicit
 *     targets bypass `.semgrepignore` (measured: one under an ignored
 *     directory was scanned). With the absolute target the callers pass, the
 *     pattern has no leading `/`: an anchored one matched nothing.
 *
 * So, on Windows (`runners/semgrepRun.ts#runSemgrep`): a walk that failed that
 * way is run again with each directory at {@link WINDOWS_DIR_MAX} or more
 * excluded; then every source file the walk did not read because its path is
 * too long — those in the excluded directories too — is read in a second run,
 * as extended-length explicit targets filtered by the run's own `--exclude`s
 * and the project's `.semgrepignore` files, and the findings are merged into
 * the run's report under the paths the walk would have given. The explicit
 * targets of a scope or a review get the same form
 * (`runners/fileBatchScan.ts#semgrepOnFiles`). A file still not read is named
 * by the long-path gap (`frameworks/projectLanguages.ts#longPathsOf`).
 */

import { win32 } from 'node:path';
import { languageOfFile } from '../frameworks/languages.js';
import { compileIgnore, type IgnoreMatcher } from '../platform/guardianIgnore.js';
import { listProjectDirOrNull, readProjectTextOrUndefined, realpathInProject } from '../platform/projectFs.js';
import { SCANNED_WALK_EXCLUDE } from './projectFiles.js';

/**
 * Windows' `MAX_PATH`: a path of this many characters or more cannot be
 * opened by a program that is not long-path aware, which is the default
 * (`LongPathsEnabled=0`). Review 8, finding 2: a file at a 301-character path
 * holding `exec('ls ' + req.query.dir)` was missing from Semgrep's
 * `paths.scanned`, with no error, and the gate read coverage full, exit 0.
 */
export const WINDOWS_MAX_PATH = 260;

/**
 * The longest path Windows allows a directory — `MAX_PATH` less the 12
 * characters of an 8.3 file name. Semgrep's walk broke from 256 up; a
 * directory this long is excluded, and its files read on their own, with that
 * margin.
 */
export const WINDOWS_DIR_MAX = 248;

/** How many directories one search lists at most: a tree bigger than this is not searched past it. */
const MAX_DIRS = 100_000;

/** What Semgrep says when its walk could not list the targets. */
const LISTING_FAILED = /Failed to obtain target files from semgrep-core/;

/** The real path Windows' limits are measured on: a short (8.3) name in the given one would hide its length. */
export function windowsBase(root: string): string {
  return realpathInProject(root, '.') ?? win32.resolve(root);
}

/** Whether `rel` (project-relative, `/`-separated) under `base` is too long for Semgrep to open, or to list its directory. */
export function tooLongForWindows(base: string, rel: string): boolean {
  const parts = rel.split('/');
  if (win32.join(base, ...parts).length >= WINDOWS_MAX_PATH) return true;
  return parts.length > 1 && win32.join(base, ...parts.slice(0, -1)).length >= WINDOWS_DIR_MAX;
}

/** `\\?\C:\…` (`\\?\UNC\host\…` for a share): the form Windows opens at any length, whatever the program's manifest. */
export function extendedLengthPath(abs: string): string {
  return abs.startsWith('\\\\') ? `\\\\?\\UNC\\${abs.slice(2)}` : `\\\\?\\${abs}`;
}

/**
 * A path as a report key, the extended-length prefix taken off (a share's
 * back to `\\host\…`), `\`-separated, lower case — what a scanner wrote for
 * an extended-length target and the path it stands for compare equal.
 */
export function windowsPathKey(p: string): string {
  return p
    .replace(/^\\\\\?\\UNC\\/i, '\\\\')
    .replace(/^\\\\\?\\/, '')
    .split('/')
    .join('\\')
    .toLowerCase();
}

/** Whether a Semgrep run's output — its JSON report, stdout or stderr — says it could not list its targets. */
export function failedToListTargets(...outputs: ReadonlyArray<string | null | undefined>): boolean {
  return outputs.some((o) => o !== null && o !== undefined && LISTING_FAILED.test(o));
}

interface LongPathWalk {
  /** The top-most directories at {@link WINDOWS_DIR_MAX} or more. */
  dirs: string[];
  /** The source files (a known language) too long for Windows, those in `dirs` included. */
  files: string[];
  /** Each `.semgrepignore` met, by the directory that holds it (`''`: the root). */
  semgrepignores: Array<{ dir: string; matcher: IgnoreMatcher }>;
}

/**
 * One walk of `root` for what Windows' limits hide from Semgrep: project-relative,
 * `/`-separated, sorted; nothing elsewhere than Windows. The directories the
 * scanners' own listing leaves out (`.git`, `node_modules`, `vendor`, …) are
 * left out; links are never followed (`listProjectDirOrNull`).
 */
export function longPathWalk(root: string, platform: NodeJS.Platform = process.platform): LongPathWalk {
  const out: LongPathWalk = { dirs: [], files: [], semgrepignores: [] };
  if (platform !== 'win32') return out;
  const base = windowsBase(root);
  const stack: Array<{ rel: string; long: boolean }> = [{ rel: '', long: false }];
  let listed = 0;
  while (stack.length > 0 && listed < MAX_DIRS) {
    const { rel, long } = stack.pop() ?? { rel: '', long: false };
    const entries = listProjectDirOrNull(root, rel === '' ? '.' : rel);
    listed++;
    if (entries === null) continue;
    for (const e of entries) {
      const child = rel === '' ? e.name : `${rel}/${e.name}`;
      if (e.kind === 'directory') {
        if (SCANNED_WALK_EXCLUDE.has(e.name)) continue;
        const isLong = !long && win32.join(base, ...child.split('/')).length >= WINDOWS_DIR_MAX;
        if (isLong) out.dirs.push(child);
        stack.push({ rel: child, long: long || isLong });
      } else if (e.kind === 'file') {
        if (e.name === '.semgrepignore') {
          const text = readProjectTextOrUndefined(root, child);
          if (text !== undefined) out.semgrepignores.push({ dir: rel, matcher: compileIgnore(text) });
        } else if (languageOfFile(child) !== null && tooLongForWindows(base, child)) {
          out.files.push(child);
        }
      }
    }
  }
  out.dirs.sort();
  out.files.sort();
  return out;
}

/** {@link longPathWalk}'s directories alone. */
export function longDirsUnder(root: string, platform: NodeJS.Platform = process.platform): string[] {
  return longPathWalk(root, platform).dirs;
}

/** Whether a `.semgrepignore` of the walk leaves `rel` out (each read relative to its own directory). */
export function semgrepIgnores(walk: Pick<LongPathWalk, 'semgrepignores'>, rel: string): boolean {
  return walk.semgrepignores.some(({ dir, matcher }) => {
    if (dir === '') return matcher.ignores(rel);
    return rel.startsWith(`${dir}/`) && matcher.ignores(rel.slice(dir.length + 1));
  });
}

/** `--exclude=<rel>`, its glob characters escaped (gitignore's rules: a backslash before each). */
export function semgrepExcludeForDir(rel: string): string {
  return `--exclude=${rel.replace(/[\\*?[\]!#]/g, (c) => `\\${c}`)}`;
}

/**
 * A Semgrep JSON report with each path `rewrite` maps replaced — the results',
 * the errors' (and their spans'), `paths.scanned` and `paths.skipped`. A path
 * `rewrite` returns null for is kept.
 */
export function rewriteReportPaths(raw: unknown, rewrite: (path: string) => string | null): unknown {
  if (raw === null || typeof raw !== 'object') return raw;
  const map = (p: unknown): unknown => (typeof p === 'string' ? (rewrite(p) ?? p) : p);
  const withPath = (o: unknown, key: string): unknown =>
    o !== null && typeof o === 'object' ? { ...(o as Record<string, unknown>), [key]: map((o as Record<string, unknown>)[key]) } : o;
  const report = { ...(raw as Record<string, unknown>) };
  if (Array.isArray(report['results'])) report['results'] = report['results'].map((r: unknown) => withPath(r, 'path'));
  if (Array.isArray(report['errors'])) {
    report['errors'] = report['errors'].map((e: unknown) => {
      if (e === null || typeof e !== 'object') return e;
      const err = { ...(e as Record<string, unknown>) };
      if ('path' in err) err['path'] = map(err['path']);
      if (Array.isArray(err['spans'])) err['spans'] = err['spans'].map((s: unknown) => withPath(s, 'file'));
      return err;
    });
  }
  const paths = report['paths'];
  if (paths !== null && typeof paths === 'object') {
    const p = { ...(paths as Record<string, unknown>) };
    if (Array.isArray(p['scanned'])) p['scanned'] = p['scanned'].map(map);
    if (Array.isArray(p['skipped'])) p['skipped'] = p['skipped'].map((s: unknown) => withPath(s, 'path'));
    report['paths'] = p;
  }
  return report;
}
