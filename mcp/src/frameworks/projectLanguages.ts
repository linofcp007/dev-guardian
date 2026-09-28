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
 * ---- Which files ------------------------------------------------------
 *
 * The files the scanners would read, not every file on disk:
 *   - git's own listing inside a work tree (tracked plus untracked files
 *     `.gitignore` does not exclude — what Semgrep reads), else a walk;
 *   - minus dependency, build and hidden directories (`PROJECT_WALK_EXCLUDE`);
 *   - minus what Semgrep ignores: the project's `.semgrepignore`, or
 *     Semgrep's built-in default list when there is none (read from
 *     semgrep-core 1.176.1: VCS folders, `build/ vendor/ dist/ node_modules/
 *     .venv/ _build/ …`, `test/ tests/ testsuite/`, `*_test.go`,
 *     `*.min.js`);
 *   - minus the project's `.guardianignore`;
 *   - minus trees that are not the product's code — tests, fixtures,
 *     examples, samples, docs, vendored and third-party code, generated
 *     code ({@link NOT_PRODUCT_DIRS}) — so `third_party/zlib/*.c` or an
 *     `examples/*.rb` does not make every category partial for C or Ruby;
 *   - and files `languages.ts#languageOfFile` does not count (a `.h`, a
 *     `build.gradle.kts`, a `.d.ts`, generated code).
 *
 * ---- Incomplete and unknown -------------------------------------------
 *
 * `incomplete` is set, with the reason, when the listing may have missed a
 * language: the walk stopped at {@link MAX_DIRS} directories, or a
 * directory could not be read. Coverage then claims nothing
 * language-specific as `tested` (at most `partial`, saying why). Unknown is
 * `languages: null`, never `[]`: a project directory that cannot be read at
 * all has languages nobody measured.
 *
 * ---- Recorded at scan time --------------------------------------------
 *
 * The scan factory records the resolved languages on the row of every scan
 * an OWASP detector reads (`meta.project_languages`), and `review_pr`
 * records those of the head it reviewed. Reports judge a scan against what
 * it recorded ({@link languagesOfRuns}); a row written before that falls
 * back to today's tree, and the source says so.
 */

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, type Dirent } from 'node:fs';
import { join } from 'node:path';
import { compileIgnore, GUARDIAN_IGNORE_FILE, type IgnoreMatcher } from '../platform/guardianIgnore.js';
import { git, splitNul } from '../runners/git.js';
import { PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { OWASP_SCAN_TYPES } from './coverage.js';
import { canonicalLanguage, languageOfFile, SOURCE_LANGUAGES, type SourceLanguage } from './languages.js';

export interface ProjectLanguages {
  /** Sorted, de-duplicated. Null: they could not be determined. */
  languages: string[] | null;
  /** Where they came from, in words — printed beside every coverage table. */
  source: string;
  /** Why the list may have missed a language. Absent: the listing was complete. */
  incomplete?: string;
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
}

export interface WalkOptions {
  /** Directories the walk visits at most. Default {@link MAX_DIRS}. */
  maxDirs?: number;
  /** Read git's listing inside a work tree. Default true. */
  useGit?: boolean;
  /** Test seam: how a directory is read. */
  readDir?: (abs: string) => Dirent[];
}

/** Directories the walk visits at most — the ceiling detect_stack's manifest walk uses. */
const MAX_DIRS = 20_000;

/** Semgrep 1.176.1's built-in `.semgrepignore`, used when the project has none. */
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

/** Directory names (any depth, case-insensitive) that hold no product code. */
export const NOT_PRODUCT_DIRS: ReadonlySet<string> = new Set([
  '__generated__',
  '__mocks__',
  '__tests__',
  'bower_components',
  'carthage',
  'doc',
  'docs',
  'example',
  'examples',
  'fixtures',
  'generated',
  'node_modules',
  'pods',
  'sample',
  'samples',
  'spec',
  'test',
  'testdata',
  'tests',
  'testsuite',
  'third-party',
  'third_party',
  'thirdparty',
  'vendor',
]);

function readText(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/** Every exclusion layer above, as one test on a project-relative POSIX path. */
function exclusions(root: string): (rel: string) => boolean {
  const semgrep: IgnoreMatcher = compileIgnore(readText(join(root, '.semgrepignore')) ?? SEMGREP_DEFAULT_IGNORE);
  const guardianText = readText(join(root, GUARDIAN_IGNORE_FILE));
  const guardian = guardianText === null ? null : compileIgnore(guardianText);
  return (rel) => {
    const segments = rel.split('/');
    const dirs = segments.slice(0, -1);
    if (dirs.some((d) => d.startsWith('.') || PROJECT_WALK_EXCLUDE.has(d) || NOT_PRODUCT_DIRS.has(d.toLowerCase()))) return true;
    if (semgrep.ignores(rel)) return true;
    return guardian !== null && guardian.ignores(rel);
  };
}

function languagesOfList(root: string, files: readonly string[]): SourceLanguage[] {
  const excluded = exclusions(root);
  const found = new Set<SourceLanguage>();
  for (const rel of files) {
    const lang = languageOfFile(rel);
    if (lang !== null && !found.has(lang) && !excluded(rel)) found.add(lang);
  }
  return SOURCE_LANGUAGES.filter((l) => found.has(l));
}

const GIT_LIST_ARGS = ['ls-files', '-z', '--cached', '--others', '--exclude-standard'];

function gitListSync(root: string): string[] | null {
  try {
    const r = spawnSync('git', ['-C', root, ...GIT_LIST_ARGS], {
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 512 * 1024 * 1024,
      windowsHide: true,
    });
    return r.status === 0 && typeof r.stdout === 'string' ? splitNul(r.stdout) : null;
  } catch {
    return null;
  }
}

async function gitListAsync(root: string): Promise<string[] | null> {
  const r = await git(root, GIT_LIST_ARGS, 30_000);
  return r.exitCode === 0 ? splitNul(r.stdout) : null;
}

/**
 * A bounded walk of `root`: every file path (POSIX, relative), and whether
 * the walk saw everything. Null when `root` itself cannot be read.
 */
function walk(root: string, opts: WalkOptions): { files: string[]; incomplete?: string } | null {
  const readDir = opts.readDir ?? ((abs: string) => readdirSync(abs, { withFileTypes: true }));
  const maxDirs = opts.maxDirs ?? MAX_DIRS;
  let top: Dirent[];
  try {
    top = readDir(root);
  } catch {
    return null;
  }
  const files: string[] = [];
  const unreadable: string[] = [];
  const stack: Array<{ rel: string; entries: Dirent[] | null }> = [{ rel: '', entries: top }];
  let visited = 0;
  let stopped = false;
  while (stack.length > 0) {
    const next = stack.pop();
    if (next === undefined) break;
    if (visited >= maxDirs) {
      stopped = true;
      break;
    }
    visited += 1;
    let entries = next.entries;
    if (entries === null) {
      try {
        entries = readDir(join(root, next.rel));
      } catch {
        unreadable.push(next.rel);
        continue;
      }
    }
    for (const entry of entries) {
      const rel = next.rel === '' ? entry.name : `${next.rel}/${entry.name}`;
      if (entry.isDirectory()) {
        const name = entry.name;
        if (!PROJECT_WALK_EXCLUDE.has(name) && !name.startsWith('.') && !NOT_PRODUCT_DIRS.has(name.toLowerCase())) {
          stack.push({ rel, entries: null });
        }
      } else if (entry.isFile()) {
        files.push(rel);
      }
    }
  }
  const reasons: string[] = [];
  if (stopped) reasons.push(`the file walk stopped after ${maxDirs} directories`);
  if (unreadable.length > 0) {
    const shown = unreadable.slice(0, 3).join(', ');
    reasons.push(`could not read ${shown}${unreadable.length > 3 ? ` and ${unreadable.length - 3} more` : ''}`);
  }
  return reasons.length > 0 ? { files, incomplete: reasons.join('; ') } : { files };
}

function fromListing(root: string, listed: string[] | null, opts: WalkOptions): FileLanguages {
  if (listed !== null) return { languages: languagesOfList(root, listed), listing: 'git' };
  const walked = walk(root, opts);
  if (walked === null) return { languages: null, listing: 'walk' };
  const out: FileLanguages = { languages: languagesOfList(root, walked.files), listing: 'walk' };
  if (walked.incomplete !== undefined) out.incomplete = walked.incomplete;
  return out;
}

/** The source languages among the files the scanners would read (see the module comment). */
export function languagesFromFiles(root: string, opts: WalkOptions = {}): FileLanguages {
  return fromListing(root, opts.useGit === false ? null : gitListSync(root), opts);
}

/** {@link languagesFromFiles}, without blocking on git — for scan time. */
export async function languagesFromFilesAsync(root: string, opts: WalkOptions = {}): Promise<FileLanguages> {
  return fromListing(root, opts.useGit === false ? null : await gitListAsync(root), opts);
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
  if (files.incomplete !== undefined) out.incomplete = files.incomplete;
  return out;
}

export interface ResolveOptions {
  /** The tree to list, when it is not the project directory (a review's head checkout). */
  walkRoot?: string;
  walk?: WalkOptions;
}

/** The project's languages now: the snapshot and the files, always both. */
export function resolveProjectLanguages(
  stack: StackSnapshotSource,
  projectPath: string,
  opts: ResolveOptions = {},
): ProjectLanguages {
  return combine(readSnapshot(stack, projectPath), languagesFromFiles(opts.walkRoot ?? projectPath, opts.walk));
}

/** {@link resolveProjectLanguages} without blocking on git — for scan time. */
export async function resolveProjectLanguagesAsync(
  stack: StackSnapshotSource,
  projectPath: string,
  opts: ResolveOptions = {},
): Promise<ProjectLanguages> {
  return combine(readSnapshot(stack, projectPath), await languagesFromFilesAsync(opts.walkRoot ?? projectPath, opts.walk));
}

/** The meta key a scan records its languages under. */
export const PROJECT_LANGUAGES_META_KEY = 'project_languages';

/** A scan row's recorded languages, or null when it has none (older rows) or they are malformed. */
export function recordedLanguages(meta: Record<string, unknown> | undefined): ProjectLanguages | null {
  const raw = meta?.[PROJECT_LANGUAGES_META_KEY];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { languages, source, incomplete } = raw as Record<string, unknown>;
  if (typeof source !== 'string') return null;
  if (languages !== null && !(Array.isArray(languages) && languages.every((l) => typeof l === 'string'))) return null;
  const out: ProjectLanguages = { languages: languages === null ? null : [...(languages as string[])].sort(), source };
  if (typeof incomplete === 'string') out.incomplete = incomplete;
  return out;
}

/**
 * The languages a set of coverage runs is judged against: the union of what
 * each scan recorded when it ran. Only the scan types an OWASP detector
 * reads count (`coverage.ts#OWASP_SCAN_TYPES`). Such a scan that predates
 * the record is judged against today's tree (`fallback`), and the source
 * says so; with no such scan at all, today's tree answers alone.
 */
export function languagesOfRuns(
  runs: ReadonlyArray<{ scan_type: string; meta?: Record<string, unknown> }>,
  fallback: () => ProjectLanguages,
): ProjectLanguages {
  const considered = runs.filter((r) => OWASP_SCAN_TYPES.has(r.scan_type));
  if (considered.length === 0) return fallback();
  const recorded = considered.map((r) => recordedLanguages(r.meta));
  const known = recorded.filter((r): r is ProjectLanguages => r !== null);
  const older = recorded.length - known.length;
  const parts = older > 0 ? [...known, fallback()] : known;

  const languages = new Set<string>();
  let anyKnown = false;
  const incomplete: string[] = [];
  for (const p of parts) {
    if (p.languages === null) incomplete.push(`the languages of a scan could not be determined (${p.source})`);
    else {
      anyKnown = true;
      for (const l of p.languages) languages.add(l);
    }
    if (p.incomplete !== undefined) incomplete.push(p.incomplete);
  }
  const sources = [...new Set(known.map((k) => k.source))];
  let source =
    known.length > 0
      ? `recorded when the scan${known.length > 1 ? 's' : ''} ran: ${sources.join('; ')}`
      : 'no scan recorded its languages';
  if (older > 0) {
    const fb = parts[parts.length - 1];
    source +=
      `; ${older} older scan${older > 1 ? 's predate' : ' predates'} that record and ${older > 1 ? 'are' : 'is'} ` +
      `judged against today's tree (${fb?.source ?? 'unknown'})`;
  }
  const out: ProjectLanguages = { languages: anyKnown ? [...languages].sort() : null, source };
  if (incomplete.length > 0) out.incomplete = [...new Set(incomplete)].join('; ');
  return out;
}
