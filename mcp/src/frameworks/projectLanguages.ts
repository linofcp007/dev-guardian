/**
 * The source languages of one project — what OWASP coverage
 * (`frameworks/coverage.ts`) is judged against, since a scanner's rules
 * only see the languages they were written for.
 *
 * ---- The union, always ------------------------------------------------
 *
 * The languages are the UNION of the detect_stack snapshot and the
 * languages of the project's files. The snapshot alone is not evidence of
 * absence: it is read from manifests (a Groovy `build.gradle` says java over
 * Kotlin sources), it goes stale (a `native/Cargo.toml` added after it), it
 * may describe another branch, and it cannot see C#, Swift or C at all. A
 * language the files show and the snapshot does not is named in `source`.
 *
 * ---- Which files: exactly the ones the scanners read ------------------
 *
 * A directory exclusion never hides a language (review round 3: a
 * directory-name list matched `com/example/...`, the Android Studio and
 * Spring Initializr default package, and dropped the whole app). Excluded
 * is only what the scanners exclude:
 *   - git's own listing inside a work tree (tracked plus untracked files
 *     `.gitignore` does not exclude — what Semgrep reads), minus the
 *     skip-worktree entries of a sparse checkout, which are not on disk;
 *     else a walk;
 *   - the project's `.semgrepignore`, or, when there is none, Semgrep's
 *     built-in default list — MEASURED on Semgrep 1.176.1 by scanning a tree
 *     of 40 candidate paths: it skips `build/ vendor/ dist/ node_modules/
 *     test/ tests/ testsuite/` at any depth, `*_test.go`, `*.min.js`,
 *     `.venv/ .env/ .tox/ .npm/ .yarn/ _opam/ _build/ _cargo/` and VCS
 *     folders, and reads everything else (`.github/`, other hidden folders,
 *     `examples/`, `docs/`, `spec/`, `fixtures/`, `third_party/`, `Pods/`,
 *     `generated/`, `target/`); a project `.semgrepignore` REPLACES the
 *     defaults;
 *   - the project's `.guardianignore`;
 *   - files `languages.ts#languageOfFile` does not count (a `*.gradle.kts`
 *     build script, a `.d.ts`, minified or generated protobuf code). A `.h`
 *     counts as C — Semgrep reads it as C — unless the project has a C++
 *     source or header (`.cc .cpp .cxx .hpp .hh .hxx`).
 *
 * ---- Peripheral languages ---------------------------------------------
 *
 * A language seen ONLY under a conventional non-product directory at the
 * top of the project ({@link PERIPHERAL_TOP_DIRS}: `examples/`, `docs/`,
 * `spec/`, `third_party/`, …) is still a language of the project — the
 * scanners read it — but it is named in `source` ("rust only under
 * examples/"), and no rule-based claim for it is more than partial. Only the
 * TOP-level directory is compared: `src/main/java/com/example/…` or
 * `…/repository/spec/…` is the product's code.
 *
 * ---- Languages only in skipped paths ----------------------------------
 *
 * A language whose files ALL sit where the scanners do not look
 * (`pkg/build/`, `dist/`, `test/`, a `.guardianignore` entry) is not a
 * language of the project — nothing read it — but it is never silently
 * gone: a Go `build` package or a `dist/` crate can be product code no
 * scanner saw. It is named in `source` ("rust only under pkg/build/
 * (skipped by Semgrep) — not counted"), at most {@link MAX_NAMED_PATHS}
 * paths and then "+N more", and changes no status. A walk looks into
 * skipped directories for this within its own budget
 * ({@link MAX_PEEK_DIRS}); dependency and tool caches (`node_modules/`,
 * `.venv/`, …) are never looked into.
 *
 * ---- Incomplete and unknown -------------------------------------------
 *
 * `incomplete` is set, with the reason, when the listing may have missed a
 * language: the walk stopped at {@link MAX_DIRS} directories, or a
 * directory could not be read. Coverage then claims nothing
 * language-specific as `tested`. Unknown is `languages: null`, never `[]`.
 *
 * ---- Recorded at scan time, listed without blocking -------------------
 *
 * The scan factory records the resolved languages on the row of every scan
 * an OWASP detector reads (`meta.project_languages`), and `review_pr`
 * records those of the head it reviewed (none, when it never checked the
 * head out). Reports judge a scan against what it recorded
 * ({@link languagesOfRunsAsync}); a row written before that falls back to
 * today's tree, and the source says so. The MCP server's readers use the
 * async listing: on a large tree `git ls-files --others` takes seconds.
 */

import { spawnSync } from 'node:child_process';
import { readdirSync, type Dirent } from 'node:fs';
import { lstat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { compileIgnore, GUARDIAN_IGNORE_FILE, type IgnoreMatcher } from '../platform/guardianIgnore.js';
import { readProjectTextOrUndefined } from '../platform/projectFs.js';
import { git, splitNul } from '../runners/git.js';
import { OWASP_SCAN_TYPES } from './coverage.js';
import { canonicalLanguage, languageOfFile, SOURCE_LANGUAGES, type SourceLanguage } from './languages.js';

export interface ProjectLanguages {
  /** Sorted, de-duplicated. Null: they could not be determined. */
  languages: string[] | null;
  /** Where they came from, in words — printed beside every coverage table. */
  source: string;
  /** Why the list may have missed a language. Absent: the listing was complete. */
  incomplete?: string;
  /**
   * Languages seen only under conventional non-product top-level
   * directories, with those directories (`{ rust: ['examples/'] }`). Every
   * rule-based claim for them is at most partial. Absent: none.
   */
  peripheral?: Record<string, string[]>;
  /**
   * Languages found ONLY in paths the scanners skip, with those paths
   * (bounded, then "+N more"). Not project languages: a note in `source`,
   * never a status. Absent: none.
   */
  skipped?: Record<string, string[]>;
}

/** What `storage.stack` offers, and all this needs of it. */
export interface StackSnapshotSource {
  getLatestForProject(projectPath: string): { captured_at: string; snapshot: unknown } | null;
}

export interface FileLanguages {
  languages: SourceLanguage[] | null;
  /** How the files were listed. */
  listing: 'git' | 'walk';
  incomplete?: string;
  peripheral?: Record<string, string[]>;
  skipped?: Record<string, string[]>;
}

export interface WalkOptions {
  /** Directories the walk visits at most. Default {@link MAX_DIRS}. */
  maxDirs?: number;
  /** Read git's listing inside a work tree. Default true. */
  useGit?: boolean;
  /** Test seam: how a directory is read (sync walk). */
  readDir?: (abs: string) => Dirent[];
  /** Test seam: how a directory is read (async walk). */
  readDirAsync?: (abs: string) => Promise<Dirent[]>;
  /**
   * Where `.guardianignore` is read, when not in the walked tree: the CI gate's
   * `--rules-ref` copy (`ci/refConfig.ts`). `.semgrepignore` stays the tree's —
   * Semgrep reads the tree's.
   */
  guardianIgnoreFrom?: string;
}

/** Directories the walk visits at most — the ceiling detect_stack's manifest walk uses. */
const MAX_DIRS = 20_000;
/** Skipped directories the walk looks into, at most, to name the languages only they hold. */
const MAX_PEEK_DIRS = 2_000;
/** Paths named per skipped-only language before "+N more". */
const MAX_NAMED_PATHS = 3;

/** Dependency and tool caches: skipped, and never looked into for a note. */
const CACHE_DIRS: ReadonlySet<string> = new Set([
  '.git', '.svn', '.hg', '_darcs', 'CVS', 'node_modules', '.venv', '.env', '.tox', '.npm', '.yarn', '_opam', '_build', '_cargo',
]);

/** Semgrep 1.176.1's built-in `.semgrepignore`, used when the project has none (measured — see the module comment). */
const SEMGREP_DEFAULT_IGNORE = [
  '.git',
  '.svn',
  '.hg',
  '_darcs',
  'CVS',
  'build/',
  'vendor/',
  'dist/',
  '*.min.js',
  '.env/',
  '.tox/',
  'node_modules/',
  '.npm/',
  '.yarn/',
  '.venv/',
  '_opam/',
  '_build/',
  '_cargo/',
  'test/',
  'tests/',
  'testsuite/',
  '*_test.go',
].join('\n');

/**
 * Conventional non-product directories, compared with the project's TOP
 * level only (case-insensitive). A language found only under these is
 * peripheral — counted, named, never fully tested.
 */
export const PERIPHERAL_TOP_DIRS: ReadonlySet<string> = new Set([
  '__mocks__',
  '__tests__',
  'bower_components',
  'carthage',
  'demo',
  'demos',
  'doc',
  'docs',
  'example',
  'examples',
  'fixtures',
  'pods',
  'sample',
  'samples',
  'spec',
  'testdata',
  'third-party',
  'third_party',
  'thirdparty',
]);

/** C++ sources and headers: with any of these, a `.h` is C++'s, not C's. */
const CPP_EXTENSIONS = /\.(cc|cpp|cxx|hpp|hh|hxx)$/i;

/** The project's own ignore files, as text (null: absent or unreadable). */
interface IgnoreTexts {
  semgrep: string | null;
  guardian: string | null;
}

/** The largest ignore file read; a real one is a few KB. */
const MAX_IGNORE_FILE_BYTES = 1024 * 1024;

/**
 * An ignore file at the project root — the repository's: bounded, regular
 * files only, never through a link out of the project
 * (`platform/projectFs.ts`). Small enough to read synchronously on the async
 * path too.
 */
function readTextSync(root: string, name: string): string | null {
  return readProjectTextOrUndefined(root, name, MAX_IGNORE_FILE_BYTES) ?? null;
}

async function readTextAsync(root: string, name: string): Promise<string | null> {
  return readTextSync(root, name);
}

function ignoreTextsSync(root: string, guardianFrom: string = root): IgnoreTexts {
  return { semgrep: readTextSync(root, '.semgrepignore'), guardian: readTextSync(guardianFrom, GUARDIAN_IGNORE_FILE) };
}

async function ignoreTextsAsync(root: string, guardianFrom: string = root): Promise<IgnoreTexts> {
  const [semgrep, guardian] = await Promise.all([
    readTextAsync(root, '.semgrepignore'),
    readTextAsync(guardianFrom, GUARDIAN_IGNORE_FILE),
  ]);
  return { semgrep, guardian };
}

/** Which layer leaves a path out: Semgrep's ignores, `.guardianignore`, or VCS internals. */
type ExclusionLayer = 'semgrep' | 'guardian' | 'vcs';

interface Exclusions {
  /** The layer that leaves out this exact path (not its parents), or null. */
  layer(rel: string, isDir?: boolean): ExclusionLayer | null;
  /** Whether the path is left out, by itself or by a directory above it. */
  excluded(rel: string, isDir?: boolean): boolean;
}

/** What the scanners leave out (see the module comment). */
function scannerExclusions(texts: IgnoreTexts): Exclusions {
  const semgrep: IgnoreMatcher = compileIgnore(texts.semgrep ?? SEMGREP_DEFAULT_IGNORE);
  const guardian = texts.guardian === null ? null : compileIgnore(texts.guardian);
  const layer = (rel: string, isDir = false): ExclusionLayer | null => {
    if (rel.split('/').includes('.git')) return 'vcs';
    if (semgrep.ignores(rel, isDir)) return 'semgrep';
    return guardian !== null && guardian.ignores(rel, isDir) ? 'guardian' : null;
  };
  return { layer, excluded: (rel, isDir = false) => layer(rel, isDir) !== null };
}

const LAYER_TEXT: Record<Exclude<ExclusionLayer, 'vcs'>, string> = {
  semgrep: 'skipped by Semgrep',
  guardian: 'excluded by .guardianignore',
};

/** Bound a list of named paths: the first {@link MAX_NAMED_PATHS}, then "+N more" (counting any earlier "+N more"). */
function boundPaths(entries: Iterable<string>): string[] {
  let extra = 0;
  const named = new Set<string>();
  for (const e of entries) {
    const more = /^\+(\d+) more$/.exec(e);
    if (more !== null && more[1] !== undefined) extra += Number.parseInt(more[1], 10);
    else named.add(e);
  }
  const sorted = [...named].sort();
  const shown = sorted.slice(0, MAX_NAMED_PATHS);
  const hidden = sorted.length - shown.length + extra;
  return hidden > 0 ? [...shown, `+${hidden} more`] : shown;
}

function languagesOfList(
  files: readonly string[],
  exclusions: Exclusions,
): Pick<FileLanguages, 'languages' | 'peripheral' | 'skipped'> & { languages: SourceLanguage[] } {
  // The top-most left-out directory of a path, memoised per directory.
  const dirMemo = new Map<string, { at: string; layer: ExclusionLayer } | null>();
  const leftOutDir = (segments: readonly string[]): { at: string; layer: ExclusionLayer } | null => {
    for (let i = 1; i < segments.length; i++) {
      const prefix = segments.slice(0, i).join('/');
      let hit = dirMemo.get(prefix);
      if (hit === undefined) {
        const layer = exclusions.layer(prefix, true);
        hit = layer === null ? null : { at: `${prefix}/`, layer };
        dirMemo.set(prefix, hit);
      }
      if (hit !== null) return hit;
    }
    return null;
  };
  const skippedAt = new Map<string, Set<string>>();
  const noteSkipped = (lang: string, where: { at: string; layer: ExclusionLayer }): void => {
    if (where.layer === 'vcs') return;
    const set = skippedAt.get(lang) ?? new Set<string>();
    set.add(`${where.at} (${LAYER_TEXT[where.layer]})`);
    skippedAt.set(lang, set);
  };
  const product = new Set<string>();
  const peripheralDirs = new Map<string, Set<string>>();
  let hasCpp = false;
  const note = (lang: string, rel: string): void => {
    const top = rel.includes('/') ? rel.slice(0, rel.indexOf('/')) : '';
    if (top !== '' && PERIPHERAL_TOP_DIRS.has(top.toLowerCase())) {
      const dirs = peripheralDirs.get(lang) ?? new Set<string>();
      dirs.add(`${top}/`);
      peripheralDirs.set(lang, dirs);
    } else {
      product.add(lang);
    }
  };
  const headers: string[] = [];
  for (const rel of files) {
    const segments = rel.split('/');
    const byDir = leftOutDir(segments);
    const fileLayer = byDir === null ? exclusions.layer(rel) : null;
    const where = byDir ?? (fileLayer === null ? null : { at: rel, layer: fileLayer });
    if (where !== null) {
      const lang = languageOfFile(rel);
      if (lang !== null) noteSkipped(lang, where);
      continue;
    }
    if (/\.h$/i.test(rel)) {
      headers.push(rel);
      continue;
    }
    if (CPP_EXTENSIONS.test(rel)) hasCpp = true;
    const lang = languageOfFile(rel);
    if (lang !== null) note(lang, rel);
  }
  // Semgrep reads a `.h` as C: headers are C unless the project has C++.
  if (!hasCpp) for (const h of headers) note('c', h);
  const all = new Set<string>([...product, ...peripheralDirs.keys()]);
  const languages = SOURCE_LANGUAGES.filter((l) => all.has(l));
  const peripheral: Record<string, string[]> = {};
  for (const lang of languages) {
    const dirs = peripheralDirs.get(lang);
    if (!product.has(lang) && dirs !== undefined) peripheral[lang] = [...dirs].sort();
  }
  const skipped: Record<string, string[]> = {};
  for (const lang of SOURCE_LANGUAGES) {
    const at = skippedAt.get(lang);
    if (at !== undefined && !all.has(lang)) skipped[lang] = boundPaths(at);
  }
  return {
    languages,
    ...(Object.keys(peripheral).length > 0 ? { peripheral } : {}),
    ...(Object.keys(skipped).length > 0 ? { skipped } : {}),
  };
}

/** `git ls-files -t`: every listed path, minus the skip-worktree ('S') entries of a sparse checkout. */
const GIT_LIST_ARGS = ['ls-files', '-z', '-t', '--cached', '--others', '--exclude-standard'];

function parseGitList(stdout: string): string[] {
  const out: string[] = [];
  for (const entry of splitNul(stdout)) {
    // `<tag> <path>`: H cached, S skip-worktree, ? other, …
    const tag = entry.slice(0, 1);
    const path = entry.slice(2);
    if (tag !== 'S' && path !== '') out.push(path);
  }
  return out;
}

function gitListSync(root: string): string[] | null {
  try {
    const r = spawnSync('git', ['-C', root, ...GIT_LIST_ARGS], {
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 512 * 1024 * 1024,
      windowsHide: true,
    });
    return r.status === 0 && typeof r.stdout === 'string' ? parseGitList(r.stdout) : null;
  } catch {
    return null;
  }
}

async function gitListAsync(root: string): Promise<string[] | null> {
  const r = await git(root, GIT_LIST_ARGS, 30_000);
  return r.exitCode === 0 ? parseGitList(r.stdout) : null;
}

interface Walked {
  /** Every file seen: the ones the scanners read, and the ones found in skipped directories. */
  files: string[];
  incomplete?: string;
}

function walkReasons(stopped: boolean, maxDirs: number, unreadable: readonly string[]): string | undefined {
  const reasons: string[] = [];
  if (stopped) reasons.push(`the file walk stopped after ${maxDirs} directories`);
  if (unreadable.length > 0) {
    const shown = unreadable.slice(0, 3).join(', ');
    reasons.push(`could not read ${shown}${unreadable.length > 3 ? ` and ${unreadable.length - 3} more` : ''}`);
  }
  return reasons.length > 0 ? reasons.join('; ') : undefined;
}

/**
 * The walk, as a plan: it yields each directory to read (relative, `''` for
 * the root) and is handed back its entries, or null when it could not be
 * read. A synchronous and an asynchronous driver run the same plan, so the
 * CLI dashboard (synchronous) and the MCP readers (which must not block)
 * walk identically.
 *
 * Directories the scanners read count toward `maxDirs`; reaching it makes
 * the walk incomplete. Directories they skip are looked into only to name
 * the languages found there, within their own `maxPeek` budget — never a
 * cache (`CACHE_DIRS`), never a reason for incompleteness.
 */
function* walkPlan(
  exclusions: Exclusions,
  maxDirs: number,
  maxPeek: number,
): Generator<string, Walked | null, Dirent[] | null> {
  const rootEntries = yield '';
  if (rootEntries === null) return null;
  const files: string[] = [];
  const unreadable: string[] = [];
  const read: Array<{ rel: string; entries: Dirent[] | null }> = [{ rel: '', entries: rootEntries }];
  const peek: string[] = [];
  let visited = 0;
  let stopped = false;
  const take = (rel: string, entries: readonly Dirent[], skipped: boolean): void => {
    for (const entry of entries) {
      const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) {
        if (CACHE_DIRS.has(entry.name)) continue;
        if (skipped || exclusions.excluded(child, true)) peek.push(child);
        else read.push({ rel: child, entries: null });
      } else if (entry.isFile()) {
        files.push(child);
      }
    }
  };
  while (read.length > 0) {
    const next = read.pop();
    if (next === undefined) break;
    if (visited >= maxDirs) {
      stopped = true;
      break;
    }
    visited += 1;
    const entries = next.entries ?? (yield next.rel);
    if (entries === null) {
      unreadable.push(next.rel);
      continue;
    }
    take(next.rel, entries, false);
  }
  // Looked into only for the note: its own budget, and no verdict on the walk.
  let peeked = 0;
  while (peek.length > 0 && peeked < maxPeek && !stopped) {
    const rel = peek.pop();
    if (rel === undefined) break;
    peeked += 1;
    const entries = yield rel;
    if (entries !== null) take(rel, entries, true);
  }
  const incomplete = walkReasons(stopped, maxDirs, unreadable);
  return incomplete !== undefined ? { files, incomplete } : { files };
}

function walkSync(root: string, exclusions: Exclusions, opts: WalkOptions): Walked | null {
  const read = opts.readDir ?? ((abs: string) => readdirSync(abs, { withFileTypes: true }));
  const plan = walkPlan(exclusions, opts.maxDirs ?? MAX_DIRS, MAX_PEEK_DIRS);
  let step = plan.next(null);
  while (step.done !== true) {
    let entries: Dirent[] | null;
    try {
      entries = read(join(root, step.value));
    } catch {
      entries = null;
    }
    step = plan.next(entries);
  }
  return step.value;
}

async function walkAsync(root: string, exclusions: Exclusions, opts: WalkOptions): Promise<Walked | null> {
  const read = opts.readDirAsync ?? ((abs: string) => readdir(abs, { withFileTypes: true }));
  const plan = walkPlan(exclusions, opts.maxDirs ?? MAX_DIRS, MAX_PEEK_DIRS);
  let step = plan.next(null);
  while (step.done !== true) {
    let entries: Dirent[] | null;
    try {
      entries = await read(join(root, step.value));
    } catch {
      entries = null;
    }
    step = plan.next(entries);
  }
  return step.value;
}

function fromFiles(listing: 'git' | 'walk', files: string[] | null, exclusions: Exclusions, incomplete?: string): FileLanguages {
  if (files === null) return { languages: null, listing };
  const out: FileLanguages = { ...languagesOfList(files, exclusions), listing };
  if (incomplete !== undefined) out.incomplete = incomplete;
  return out;
}

/** The source languages among the files the scanners would read — synchronous (the CLI dashboard). */
export function languagesFromFiles(root: string, opts: WalkOptions = {}): FileLanguages {
  const exclusions = scannerExclusions(ignoreTextsSync(root, opts.guardianIgnoreFrom));
  const listed = opts.useGit === false ? null : gitListSync(root);
  if (listed !== null) return fromFiles('git', listed, exclusions);
  const walked = walkSync(root, exclusions, opts);
  return fromFiles('walk', walked?.files ?? null, exclusions, walked?.incomplete);
}

/** {@link languagesFromFiles} without blocking the event loop — scan time and the MCP readers. */
export async function languagesFromFilesAsync(root: string, opts: WalkOptions = {}): Promise<FileLanguages> {
  const exclusions = scannerExclusions(await ignoreTextsAsync(root, opts.guardianIgnoreFrom));
  const listed = opts.useGit === false ? null : await gitListAsync(root);
  if (listed !== null) return fromFiles('git', listed, exclusions);
  const walked = await walkAsync(root, exclusions, opts);
  return fromFiles('walk', walked?.files ?? null, exclusions, walked?.incomplete);
}

// ---------------------------------------------------------------- files too large for Semgrep

/** Semgrep's `--max-target-bytes` default (1.176.1: "Defaults to 1000000 bytes"): a larger target is ignored. */
export const SEMGREP_MAX_TARGET_BYTES = 1_000_000;

export interface OversizedFile {
  /** Project-relative, `/`-separated. */
  path: string;
  bytes: number;
}

export interface OversizedFiles {
  files: OversizedFile[];
  /** Why the listing may have missed some. Absent: it did not. */
  incomplete?: string;
}

/** Whether `rel` is a file the scanners read with a source language — see the module comment. */
function isScannedSource(rel: string, exclusions: Exclusions): boolean {
  if (languageOfFile(rel) === null && !/\.h$/i.test(rel)) return false;
  const segments = rel.split('/');
  for (let i = 1; i < segments.length; i++) {
    if (exclusions.layer(segments.slice(0, i).join('/'), true) !== null) return false;
  }
  return exclusions.layer(rel) === null;
}

async function sizesOver(root: string, rels: readonly string[], limit: number): Promise<OversizedFile[]> {
  const out: OversizedFile[] = [];
  const BATCH = 64;
  for (let i = 0; i < rels.length; i += BATCH) {
    const batch = rels.slice(i, i + BATCH);
    const sizes = await Promise.all(
      batch.map(async (rel) => {
        try {
          const st = await lstat(join(root, ...rel.split('/')));
          return st.isFile() ? st.size : -1;
        } catch {
          return -1;
        }
      }),
    );
    sizes.forEach((bytes, j) => {
      const rel = batch[j];
      if (rel !== undefined && bytes > limit) out.push({ path: rel, bytes });
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * The files Semgrep would read here — the scanners' own listing and
 * exclusions (the module comment), with a source language — that are over
 * `limit` bytes, which Semgrep ignores without a word (review M1: its
 * `paths.skipped` says so only under `--verbose`, and a 1.16 MB file of
 * the project's only Python read as "no covered language"). `only`, when
 * given, restricts the answer to those paths (a scoped scan's files).
 */
export async function oversizedSourceFilesAsync(
  root: string,
  opts: { limit?: number; only?: readonly string[]; guardianIgnoreFrom?: string } = {},
): Promise<OversizedFiles> {
  const limit = opts.limit ?? SEMGREP_MAX_TARGET_BYTES;
  const exclusions = scannerExclusions(await ignoreTextsAsync(root, opts.guardianIgnoreFrom));
  if (opts.only !== undefined) {
    const rels = opts.only.map((p) => p.split('\\').join('/')).filter((rel) => isScannedSource(rel, exclusions));
    return { files: await sizesOver(root, rels, limit) };
  }
  const listed = await gitListAsync(root);
  const walked = listed === null ? await walkAsync(root, exclusions, {}) : null;
  const files = listed ?? walked?.files ?? [];
  const out: OversizedFiles = { files: await sizesOver(root, files.filter((rel) => isScannedSource(rel, exclusions)), limit) };
  if (walked?.incomplete !== undefined) out.incomplete = walked.incomplete;
  return out;
}

/** `src/big.py (1.2 MB)`, the first few, then "and N more". */
export function describeOversized(files: readonly OversizedFile[], limit = SEMGREP_MAX_TARGET_BYTES): string {
  const mb = (n: number): string => `${(n / 1_000_000).toFixed(1)} MB`;
  const shown = files.slice(0, 5).map((f) => `${f.path} (${mb(f.bytes)})`);
  const more = files.length > shown.length ? ` and ${files.length - shown.length} more` : '';
  const n = files.length;
  return (
    `${n} file${n === 1 ? '' : 's'} over Semgrep's ${mb(limit).replace('.0 ', ' ')} target limit ` +
    `${n === 1 ? 'was' : 'were'} not scanned: ${shown.join(', ')}${more}`
  );
}

function snapshotLanguages(snapshot: unknown): SourceLanguage[] | null {
  if (snapshot === null || typeof snapshot !== 'object') return null;
  const raw = (snapshot as { languages?: unknown }).languages;
  if (!Array.isArray(raw) || !raw.every((l) => typeof l === 'string')) return null;
  return [...new Set((raw as string[]).map(canonicalLanguage).filter((l): l is SourceLanguage => l !== null))];
}

function readSnapshot(stack: StackSnapshotSource, projectPath: string): { at: string; languages: SourceLanguage[] } | null {
  try {
    const persisted = stack.getLatestForProject(projectPath);
    if (persisted === null) return null;
    const languages = snapshotLanguages(persisted.snapshot);
    return languages === null ? null : { at: persisted.captured_at, languages };
  } catch {
    return null;
  }
}

function peripheralText(peripheral: Record<string, string[]> | undefined): string {
  if (peripheral === undefined) return '';
  return Object.entries(peripheral)
    .map(([lang, dirs]) => `; ${lang} only under ${dirs.join(', ')}`)
    .join('');
}

function skippedText(skipped: Record<string, string[]> | undefined): string {
  if (skipped === undefined) return '';
  return Object.entries(skipped)
    .map(([lang, paths]) => `; ${lang} only under ${paths.join(', ')} — not counted`)
    .join('');
}

/** The skipped-only notes for languages NOT among `languages` (a counted language needs none). */
function skippedFor(
  skipped: Record<string, string[]> | undefined,
  languages: readonly string[],
): Record<string, string[]> | undefined {
  if (skipped === undefined) return undefined;
  const kept = Object.entries(skipped).filter(([lang]) => !languages.includes(lang));
  return kept.length > 0 ? Object.fromEntries(kept) : undefined;
}

/** The union of the snapshot and the files, described. */
function combine(snapshot: { at: string; languages: SourceLanguage[] } | null, files: FileLanguages): ProjectLanguages {
  const how = files.listing === 'git' ? "file extensions (git's listing)" : 'file extensions (a walk of the directory)';
  if (files.languages === null) {
    if (snapshot === null) return { languages: null, source: 'could not be determined (the project directory could not be read)' };
    return {
      languages: [...snapshot.languages].sort(),
      source: `detect_stack snapshot of ${snapshot.at}; the project files could not be listed`,
      incomplete: 'the project files could not be listed',
    };
  }
  let out: ProjectLanguages;
  if (snapshot === null) {
    out = { languages: [...files.languages].sort(), source: `${how}; no detect_stack snapshot` };
  } else {
    const extra = files.languages.filter((l) => !snapshot.languages.includes(l));
    const languages = [...new Set([...snapshot.languages, ...files.languages])].sort();
    out = {
      languages,
      source:
        `detect_stack snapshot of ${snapshot.at} + ${how}` +
        (extra.length > 0 ? `; ${extra.join(', ')} found in the files but not in the snapshot` : ''),
    };
  }
  if (files.peripheral !== undefined) {
    out.peripheral = files.peripheral;
    out.source += peripheralText(files.peripheral);
  }
  // A snapshot language is counted, so a skipped-only note for it would be noise.
  const skipped = skippedFor(files.skipped, out.languages ?? []);
  if (skipped !== undefined) {
    out.skipped = skipped;
    out.source += skippedText(skipped);
  }
  if (files.incomplete !== undefined) out.incomplete = files.incomplete;
  return out;
}

export interface ResolveOptions {
  /** The tree to list, when it is not the project directory (a review's head checkout). */
  walkRoot?: string;
  walk?: WalkOptions;
}

/** The project's languages now: the snapshot and the files, always both — synchronous (the CLI dashboard). */
export function resolveProjectLanguages(
  stack: StackSnapshotSource,
  projectPath: string,
  opts: ResolveOptions = {},
): ProjectLanguages {
  return combine(readSnapshot(stack, projectPath), languagesFromFiles(opts.walkRoot ?? projectPath, opts.walk));
}

/** {@link resolveProjectLanguages} without blocking the event loop — scan time and the MCP readers. */
export async function resolveProjectLanguagesAsync(
  stack: StackSnapshotSource,
  projectPath: string,
  opts: ResolveOptions = {},
): Promise<ProjectLanguages> {
  return combine(readSnapshot(stack, projectPath), await languagesFromFilesAsync(opts.walkRoot ?? projectPath, opts.walk));
}

/** The meta key a scan records its languages under. */
export const PROJECT_LANGUAGES_META_KEY = 'project_languages';

function readPeripheral(raw: unknown): Record<string, string[]> | undefined {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const out: Record<string, string[]> = {};
  for (const [lang, dirs] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(dirs) && dirs.every((d) => typeof d === 'string')) out[lang] = [...(dirs as string[])];
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** A scan row's recorded languages, or null when it has none (older rows) or they are malformed. */
export function recordedLanguages(meta: Record<string, unknown> | undefined): ProjectLanguages | null {
  const raw = meta?.[PROJECT_LANGUAGES_META_KEY];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { languages, source, incomplete, peripheral, skipped } = raw as Record<string, unknown>;
  if (typeof source !== 'string') return null;
  if (languages !== null && !(Array.isArray(languages) && languages.every((l) => typeof l === 'string'))) return null;
  const out: ProjectLanguages = { languages: languages === null ? null : [...(languages as string[])].sort(), source };
  if (typeof incomplete === 'string') out.incomplete = incomplete;
  const p = readPeripheral(peripheral);
  if (p !== undefined) out.peripheral = p;
  const s = readPeripheral(skipped);
  if (s !== undefined) out.skipped = s;
  return out;
}

type Run = { scan_type: string; meta?: Record<string, unknown> };

/** The relevant runs, and whether any of them predates recorded languages. */
function considered(runs: readonly Run[]): { runs: Run[]; needsFallback: boolean } {
  const kept = runs.filter((r) => OWASP_SCAN_TYPES.has(r.scan_type));
  return { runs: kept, needsFallback: kept.length === 0 || kept.some((r) => recordedLanguages(r.meta) === null) };
}

function unionOfRuns(runs: readonly Run[], fallback: ProjectLanguages | null): ProjectLanguages {
  if (runs.length === 0) return fallback ?? { languages: null, source: 'no scan in play' };
  const recorded = runs.map((r) => recordedLanguages(r.meta));
  const known = recorded.filter((r): r is ProjectLanguages => r !== null);
  const older = recorded.length - known.length;
  const parts = older > 0 && fallback !== null ? [...known, fallback] : known;

  const languages = new Set<string>();
  let anyKnown = false;
  const incomplete: string[] = [];
  // Peripheral only if EVERY part that has the language saw it only there.
  const peripheral = new Map<string, Set<string>>();
  const product = new Set<string>();
  for (const p of parts) {
    if (p.languages === null) incomplete.push(`the languages of a scan could not be determined (${p.source})`);
    else {
      anyKnown = true;
      for (const l of p.languages) {
        languages.add(l);
        const dirs = p.peripheral?.[l];
        if (dirs === undefined) product.add(l);
        else {
          const set = peripheral.get(l) ?? new Set<string>();
          for (const d of dirs) set.add(d);
          peripheral.set(l, set);
        }
      }
    }
    if (p.incomplete !== undefined) incomplete.push(p.incomplete);
  }
  const sources = [...new Set(known.map((k) => k.source))];
  let source =
    known.length > 0
      ? `recorded when the scan${known.length > 1 ? 's' : ''} ran: ${sources.join('; ')}`
      : 'no scan recorded its languages';
  if (older > 0) {
    source +=
      `; ${older} older scan${older > 1 ? 's predate' : ' predates'} that record and ${older > 1 ? 'are' : 'is'} ` +
      `judged against today's tree (${fallback?.source ?? 'unknown'})`;
  }
  const out: ProjectLanguages = { languages: anyKnown ? [...languages].sort() : null, source };
  if (incomplete.length > 0) out.incomplete = [...new Set(incomplete)].join('; ');
  const onlyPeripheral: Record<string, string[]> = {};
  for (const [l, dirs] of peripheral) if (!product.has(l)) onlyPeripheral[l] = [...dirs].sort();
  if (Object.keys(onlyPeripheral).length > 0) out.peripheral = onlyPeripheral;
  // Skipped-only notes: every scan's, for languages no scan counted, re-bounded.
  const skippedPaths = new Map<string, string[]>();
  for (const p of parts) {
    for (const [l, paths] of Object.entries(p.skipped ?? {})) skippedPaths.set(l, [...(skippedPaths.get(l) ?? []), ...paths]);
  }
  const notes: Record<string, string[]> = {};
  for (const [l, paths] of [...skippedPaths].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (!languages.has(l)) notes[l] = boundPaths(paths);
  }
  if (Object.keys(notes).length > 0) out.skipped = notes;
  return out;
}

/**
 * The languages a set of coverage runs is judged against: the union of what
 * each scan recorded when it ran. Only the scan types an OWASP detector
 * reads count (`coverage.ts#OWASP_SCAN_TYPES`). Such a scan that predates
 * the record is judged against today's tree (`fallback`, asked only then),
 * and the source says so; with no such scan at all, today's tree answers
 * alone. Synchronous — the CLI dashboard.
 */
export function languagesOfRuns(runs: readonly Run[], fallback: () => ProjectLanguages): ProjectLanguages {
  const c = considered(runs);
  if (c.runs.length === 0) return fallback();
  return unionOfRuns(c.runs, c.needsFallback ? fallback() : null);
}

/** {@link languagesOfRuns} with an async fallback — the MCP readers, which must not block. */
export async function languagesOfRunsAsync(
  runs: readonly Run[],
  fallback: () => Promise<ProjectLanguages>,
): Promise<ProjectLanguages> {
  const c = considered(runs);
  if (c.runs.length === 0) return fallback();
  return unionOfRuns(c.runs, c.needsFallback ? await fallback() : null);
}
