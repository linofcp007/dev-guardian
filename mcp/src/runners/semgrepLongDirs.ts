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
 *     directory was scanned). The walk fails only outside git, and there
 *     Semgrep anchors a pattern holding a slash at the scan target, the
 *     absolute one the callers pass included (`platform/guardianIgnore.ts`;
 *     inside a work tree it anchors at the git root). Measured on 1.182.0,
 *     2026-10-25 (review 3.6.1, finding 8, which corrected "an anchored one
 *     matched nothing" here): `--exclude=<dir>` and `--exclude=/<dir>` alike
 *     kept the walk out of a 248-character directory, one file listed and
 *     exit 0, against exit 2 without. The spelling without the `/` is kept: a
 *     top-level directory's name alone matches at any depth too, but any
 *     directory of that name below it is longer still, so long itself.
 *
 * So, on Windows (`runners/semgrepRun.ts#runSemgrep`): a walk that failed that
 * way is run again with each directory at {@link WINDOWS_DIR_MAX} or more
 * excluded; then every file Semgrep reads ({@link semgrepReadsFile}) that the
 * walk left unread because its path is too long — those in the excluded
 * directories too — is read in a second run,
 * as extended-length explicit targets filtered by the run's own `--exclude`s
 * and the project's `.semgrepignore` files, and the findings are merged into
 * the run's report under the paths the walk would have given. The explicit
 * targets of a scope or a review get the same form
 * (`runners/fileBatchScan.ts#semgrepOnFiles`). A file still not read is named
 * by the long-path gap (`frameworks/projectLanguages.ts#longPathsOf`).
 *
 * Finding those files costs a listing of the tree, after every Semgrep run on
 * Windows — 3.6.0 walked it synchronously (up to 100 000 directories, every
 * path component checked for links) and read and compiled every nested
 * `.semgrepignore` it met (review 3.6.1, finding 2). Inside a git work tree
 * Semgrep lists through git, so git's own listing answers, with
 * `core.longpaths=true` — measured, git 2.51: without it git leaves out an
 * untracked directory past MAX_PATH with only a warning, exit 0. A walk, not
 * blocking the event loop, is needed only outside one, or when Semgrep's own
 * walk failed (the directories are wanted then). A `.semgrepignore` is read
 * only when a candidate lies below it, within one read budget.
 */

import { readdir, stat } from 'node:fs/promises';
import { join, win32 } from 'node:path';
import { languageOfFile } from '../frameworks/languages.js';
import { compileIgnore, type IgnoreMatcher } from '../platform/guardianIgnore.js';
import { ReadBudget, realpathInProject } from '../platform/projectFs.js';
import { git, splitNul } from './git.js';
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

/**
 * Markup, configuration and shell Semgrep reads besides the source languages:
 * what its registry rules and dev-guardian's own packs (Android's and iOS's
 * manifests, templates) are written for.
 */
const SEMGREP_TEXT_TARGET = /\.(?:ya?ml|json|tf|tfvars|hcl|sh|bash|zsh|ksh|html?|xhtml|vue|svelte|xml|plist|twig|razor|cshtml|hbs|ejs|erb|jsp|sol)$/i;
const DOCKERFILE = /(?:^|\/)(?:dockerfile|containerfile)(?:\.[^/]*)?$|\.dockerfile$/i;

/**
 * Whether Semgrep reads `rel` when it can open it: a source language
 * (`languageOfFile`, or a `.h`), or one of {@link SEMGREP_TEXT_TARGET} or a
 * Dockerfile. What a file at a long path is judged by — review 3.6.1, finding
 * 3: the source languages alone were, so a Kubernetes manifest, a Dockerfile
 * or an AndroidManifest.xml Semgrep never opened was neither read on its own
 * nor named, and coverage read full.
 */
export function semgrepReadsFile(rel: string): boolean {
  return languageOfFile(rel) !== null || /\.h$/i.test(rel) || SEMGREP_TEXT_TARGET.test(rel) || DOCKERFILE.test(rel);
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

const IGNORE_NAME = '.semgrepignore';
/** What all the `.semgrepignore` files one search reads may hold, and each: an ignore file is applied up to 64 KiB. */
const IGNORE_BUDGET_BYTES = 1024 * 1024;
const IGNORE_BUDGET_FILES = 64;
const IGNORE_FILE_MAX_BYTES = 64 * 1024;

/**
 * The `.semgrepignore` files of a tree, each applying to its own directory's
 * subtree — read and compiled only when a path below one is asked about, all
 * of them within one {@link ReadBudget}: 3.6.0 read every one it met, 8 MiB
 * each, and kept them all compiled — dozens of copies of one 8 MiB blob of
 * `a` lines, a few KB on the wire, were millions of RegExps.
 */
class NestedSemgrepIgnores {
  private readonly matchers = new Map<string, IgnoreMatcher | null>();
  private readonly budget = new ReadBudget(IGNORE_BUDGET_BYTES, IGNORE_BUDGET_FILES);

  constructor(
    private readonly root: string,
    /** The directories holding one (`''`: the root), project-relative, `/`-separated. */
    readonly dirs: readonly string[],
  ) {}

  /**
   * Whether one of them leaves `rel` out: true, false — or null when one that
   * applies was not read (the budget, a refusal) or not applied (too large, or
   * too costly to test), so that nobody can say.
   */
  ignores(rel: string): boolean | null {
    let unknown = false;
    for (const dir of this.dirs) {
      if (dir !== '' && !rel.startsWith(`${dir}/`)) continue;
      const matcher = this.matcher(dir);
      if (matcher === null) {
        unknown = true;
        continue;
      }
      const before = matcher.overBudget;
      if (matcher.ignores(dir === '' ? rel : rel.slice(dir.length + 1))) return true;
      if (matcher.overBudget !== before) unknown = true;
    }
    return unknown ? null : false;
  }

  private matcher(dir: string): IgnoreMatcher | null {
    const known = this.matchers.get(dir);
    if (known !== undefined) return known;
    const read = this.budget.readText(this.root, dir === '' ? IGNORE_NAME : `${dir}/${IGNORE_NAME}`, IGNORE_FILE_MAX_BYTES);
    const compiled = read.status === 'ok' ? compileIgnore(read.text) : null;
    const matcher = compiled === null || compiled.refused !== undefined ? null : compiled;
    this.matchers.set(dir, matcher);
    return matcher;
  }
}

interface LongPathWalk {
  /** The top-most directories at {@link WINDOWS_DIR_MAX} or more — searched for only when asked (`dirs`). */
  dirs: string[];
  /** The files Semgrep reads ({@link semgrepReadsFile}) too long for Windows, those in `dirs` included. */
  files: string[];
  /** The tree's `.semgrepignore` files. */
  semgrepignores: NestedSemgrepIgnores;
}

/** `git ls-files` as Semgrep lists a work tree, with git's own long-path support; null outside one, or when git cannot answer. */
async function gitListing(root: string): Promise<string[] | null> {
  const r = await git(root, ['-c', 'core.longpaths=true', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], 30_000);
  return r.exitCode === 0 ? splitNul(r.stdout).map((p) => p.split('\\').join('/')) : null;
}

/**
 * What Windows' limits hide from Semgrep under `root`: project-relative,
 * `/`-separated, sorted; nothing elsewhere than Windows, or for a target that
 * is not a directory. The directories the scanners' own listing leaves out
 * (`.git`, `node_modules`, `vendor`, …) are left out. Inside a git work tree
 * the files are git's listing — unless `dirs` is asked for (Semgrep's own
 * walk failed): then, as outside one, a walk, which never descends a link (a
 * junction is one) and stops at {@link MAX_DIRS} directories.
 */
export async function longPathWalk(
  root: string,
  platform: NodeJS.Platform = process.platform,
  opts: { dirs?: boolean } = {},
): Promise<LongPathWalk> {
  const none = (): LongPathWalk => ({ dirs: [], files: [], semgrepignores: new NestedSemgrepIgnores(root, []) });
  if (platform !== 'win32') return none();
  const isDir = await stat(root).then(
    (s) => s.isDirectory(),
    () => false,
  );
  if (!isDir) return none();
  const base = windowsBase(root);
  const listed = opts.dirs === true ? null : await gitListing(root);
  if (listed !== null) {
    const kept = listed.filter((rel) => !rel.split('/').some((segment) => SCANNED_WALK_EXCLUDE.has(segment)));
    const ignoreDirs = kept
      .filter((rel) => rel === IGNORE_NAME || rel.endsWith(`/${IGNORE_NAME}`))
      .map((rel) => (rel === IGNORE_NAME ? '' : rel.slice(0, -(IGNORE_NAME.length + 1))));
    return {
      dirs: [],
      files: kept.filter((rel) => semgrepReadsFile(rel) && tooLongForWindows(base, rel)).sort(),
      semgrepignores: new NestedSemgrepIgnores(root, ignoreDirs),
    };
  }
  const out = { dirs: [] as string[], files: [] as string[], ignoreDirs: [] as string[] };
  const stack: Array<{ rel: string; long: boolean }> = [{ rel: '', long: false }];
  let listedDirs = 0;
  while (stack.length > 0 && listedDirs < MAX_DIRS) {
    const { rel, long } = stack.pop() ?? { rel: '', long: false };
    listedDirs++;
    let entries;
    try {
      entries = await readdir(rel === '' ? root : join(root, ...rel.split('/')), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const child = rel === '' ? e.name : `${rel}/${e.name}`;
      // Typed from the directory itself: a link (a junction included) is neither.
      if (e.isDirectory()) {
        if (SCANNED_WALK_EXCLUDE.has(e.name)) continue;
        const isLong = !long && win32.join(base, ...child.split('/')).length >= WINDOWS_DIR_MAX;
        if (isLong) out.dirs.push(child);
        stack.push({ rel: child, long: long || isLong });
      } else if (e.isFile()) {
        if (e.name === IGNORE_NAME) out.ignoreDirs.push(rel);
        else if (semgrepReadsFile(child) && tooLongForWindows(base, child)) out.files.push(child);
      }
    }
  }
  return { dirs: out.dirs.sort(), files: out.files.sort(), semgrepignores: new NestedSemgrepIgnores(root, out.ignoreDirs) };
}

/** {@link longPathWalk}'s directories alone. */
export async function longDirsUnder(root: string, platform: NodeJS.Platform = process.platform): Promise<string[]> {
  return (await longPathWalk(root, platform, { dirs: true })).dirs;
}

/** Whether a `.semgrepignore` of the walk leaves `rel` out (each read relative to its own directory); null: one could not be read. */
export function semgrepIgnores(walk: Pick<LongPathWalk, 'semgrepignores'>, rel: string): boolean | null {
  return walk.semgrepignores.ignores(rel);
}

/** `--exclude=<rel>`, its glob characters escaped (gitignore's rules: a backslash before each). */
export function semgrepExcludeForDir(rel: string): string {
  return `--exclude=${rel.replace(/[\\*?[\]!#]/g, (c) => `\\${c}`)}`;
}

/**
 * A Semgrep JSON report with each path `rewrite` maps replaced — the results',
 * the errors' (and their spans'), `paths.scanned`, `paths.skipped` and the
 * taint timeouts' (`time.fixpoint_timeouts[].location`). A path `rewrite`
 * returns null for is kept.
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
  const time = report['time'];
  if (time !== null && typeof time === 'object' && Array.isArray((time as Record<string, unknown>)['fixpoint_timeouts'])) {
    const t = { ...(time as Record<string, unknown>) };
    t['fixpoint_timeouts'] = (t['fixpoint_timeouts'] as unknown[]).map((entry) =>
      entry !== null && typeof entry === 'object'
        ? { ...(entry as Record<string, unknown>), location: withPath((entry as Record<string, unknown>)['location'], 'path') }
        : entry,
    );
    report['time'] = t;
  }
  return report;
}
