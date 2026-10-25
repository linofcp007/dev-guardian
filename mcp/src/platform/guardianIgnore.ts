/**
 * `.guardianignore` — paths a project declares are not its own code to scan.
 *
 * Self-scanning dev-guardian reported its own deliberately vulnerable test
 * fixtures (`mcp/test/fixtures/**`) as critical and high findings: every rule
 * pack ships a `hits/` tree whose whole purpose is to be flagged. A project
 * says so once, in `.guardianignore` at its root, in gitignore syntax, and
 * every scanner honours it.
 *
 * ---- Two layers, and which one is the guarantee ---------------------------
 *
 *   1. **The result filter** (`ignores`) — every finding of every scan tool
 *      built on the scan factory passes through it before anything is
 *      stored. This is the guarantee: it implements the syntax exactly (it is
 *      tested against `git check-ignore` itself), and it covers scanners that
 *      have no exclusion flag at all (gitleaks, jscpd, ruff, …).
 *   2. **Native flags** — Semgrep `--exclude`, Trivy `--skip-dirs` /
 *      `--skip-files`, Bandit `-x` — so the scanner never reads an excluded
 *      tree in the first place. They are derived from the project's file list
 *      (`excludedDirs` / `excludedFiles`: the top-most excluded paths, exact),
 *      never by translating patterns, because each scanner reads a pattern
 *      differently. Measured on Semgrep 1.176.1: `--exclude` is read as
 *      gitignore (`docs` at any depth, `/docs` anchored) — and anchored at
 *      the GIT ROOT, not at the scan target: with the project at `repo/sub`,
 *      `--exclude=/fixtures` excluded nothing and `--exclude=/sub/lib` (meant
 *      for `<project>/sub/lib`) excluded the kept `<project>/lib` instead. So
 *      the anchor is the project's `git rev-parse --show-prefix` (the target
 *      itself outside git), and no Semgrep flag at all when that cannot be
 *      known. Trivy anchors `--skip-dirs` / `--skip-files` at its target (a
 *      single segment too). Bandit's `-x` is a SUBSTRING test on the path as
 *      it walks it (plus `fnmatch`), so only an absolute native path works — a
 *      relative `data/fx` excluded nothing on Windows. A path holding glob
 *      syntax (`pages/[id].test.js`) is a pattern to all three — `--exclude`
 *      of that name excluded `pages/i.py` and kept itself — so it is never
 *      passed. A native flag that could exclude MORE than the file says under
 *      some reading is not passed either: the filter still applies, so a
 *      withheld flag costs only speed, never a silent gap.
 *
 * Exclusion is never silent: the factory reports how many files the ignore
 * file excludes and how many findings it dropped on every scan of a project
 * that has one.
 *
 * Only the file at the project root is read; `.guardianignore` files in
 * subdirectories are not (gitignore's per-directory files are not supported).
 */

import { createHash } from 'node:crypto';
import { dirname, join, resolve, sep } from 'node:path';
import { git, isGitUnanswered, splitNul } from '../runners/git.js';
import { listProjectFiles, SCANNED_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { isGuardianOutput } from './guardianOutput.js';
import { describeReadRefusal, presentInProject, projectEntryKind, readProjectText, readProjectTextOrUndefined } from './projectFs.js';

/** The largest `.guardianignore` read; a real one is a few KB. */
const MAX_GUARDIAN_IGNORE_BYTES = 1024 * 1024;

export const GUARDIAN_IGNORE_FILE = '.guardianignore';

/** Bandit's own default `-x` list — replaced, not extended, by passing `-x`. */
const BANDIT_DEFAULT_EXCLUDES = ['.svn', 'CVS', '.bzr', '.hg', '.git', '__pycache__', '.tox', '.eggs', '*.egg'];

/** Glob syntax to Semgrep's gitignore reader and Trivy's doublestar (tested on POSIX paths). */
const GLOB_SYNTAX = /[*?[\]{}\\]/;
/** Glob syntax to Bandit's `fnmatch` (tested on native absolute paths, backslashes and all). */
const FNMATCH_SYNTAX = /[*?[\]]/;

/** Most native exclusion entries passed to one scanner; the rest are filtered from results only. */
const MAX_NATIVE_ENTRIES = 200;
/** Most characters of native exclusion arguments (the command line is shared with targets). */
const MAX_NATIVE_CHARS = 8_000;

/**
 * The most text of one ignore file compiled — a real one is a few KB — and
 * the most patterns. Past either the file is not applied at all
 * ({@link IgnoreMatcher.refused}): every path is tested against every
 * pattern, and an 8 MiB blob of `a` lines was four million of them.
 */
const MAX_IGNORE_TEXT_CHARS = 64 * 1024;
const MAX_IGNORE_PATTERNS = 2000;
/** The longest pattern compiled (a path is at most 4 096 characters on Linux, 260 on Windows). */
const MAX_IGNORE_PATTERN_CHARS = 4096;

/**
 * The steps one {@link IgnoreMatcher.ignores} may take: {@link MATCH_STEPS_BASE}
 * plus {@link MATCH_STEPS_PER_TEST} per pattern and path segment. A real
 * pattern takes one to a few steps a segment; matching costs at most pattern
 * length x path length steps, and 64 KiB of patterns crafted to backtrack
 * inside a 250-character name took 47 ms a path (measured) — minutes on the
 * server's only thread for a repository of such files. A path that would
 * take more is answered "kept" — the direction that never hides a file —
 * and counted ({@link IgnoreMatcher.overBudget}). The answer depends on the
 * path and the patterns alone, never on what was asked before.
 */
const MATCH_STEPS_BASE = 4096;
const MATCH_STEPS_PER_TEST = 32;

/** Thrown inside a test that spent its budget; caught by `ignores`, never further. */
class MatchBudgetSpent {}
const BUDGET_SPENT = new MatchBudgetSpent();

interface Budget {
  left: number;
}

interface Rule {
  negated: boolean;
  dirOnly: boolean;
  /** Null: a pattern git aborts on (an unterminated `[`, a trailing `\`) — it matches nothing. */
  segments: Segment[] | null;
  /** A pattern without a slash (`*.log`): it is matched against the last segment alone. */
  basename?: Exclude<Segment, typeof GLOBSTAR>;
}

export interface IgnoreMatcher {
  /** Number of patterns (comments and blank lines excluded). */
  readonly patterns: number;
  /**
   * Why the text was not applied — too large to compile — or absent when it
   * was. A refused text excludes nothing: the direction that never hides a
   * file, and the caller names it where it can (`loadProjectExclusions`).
   */
  readonly refused?: string;
  /** How many paths were answered "kept" because testing them passed the step budget (see MATCH_STEPS_BASE). */
  readonly overBudget: number;
  /**
   * Is `relPath` (relative to the project, either separator) excluded — by
   * its own pattern, or because a directory above it is? `isDir` says the
   * path itself is a directory (only matters for `dir/` patterns).
   */
  ignores(relPath: string, isDir?: boolean): boolean;
}

/** Parse gitignore-syntax text into a matcher. */
export function compileIgnore(text: string): IgnoreMatcher {
  const refuse = (why: string): IgnoreMatcher => ({ patterns: 0, refused: why, overBudget: 0, ignores: () => false });
  // Measured before splitting: the split of an 8 MiB blob is the cost.
  if (text.length > MAX_IGNORE_TEXT_CHARS) {
    return refuse(`it holds ${String(text.length)} characters, more than the ${String(MAX_IGNORE_TEXT_CHARS)} an ignore file is applied up to`);
  }
  const rules: Rule[] = [];
  for (const [i, rawLine] of text.split(/\r?\n/).entries()) {
    if (rawLine.length > MAX_IGNORE_PATTERN_CHARS) {
      return refuse(`line ${String(i + 1)} holds ${String(rawLine.length)} characters, more than the ${String(MAX_IGNORE_PATTERN_CHARS)} a pattern may`);
    }
    const rule = parseLine(rawLine);
    if (rule !== null) rules.push(rule);
    if (rules.length > MAX_IGNORE_PATTERNS) {
      return refuse(`it holds more than the ${String(MAX_IGNORE_PATTERNS)} patterns an ignore file is applied up to`);
    }
  }

  /** The last rule matching this exact path decides; no rule means kept. */
  const decide = (segments: readonly string[], isDir: boolean, budget: Budget): boolean => {
    let ignored = false;
    const last = segments.at(-1) ?? '';
    for (const rule of rules) {
      if (rule.dirOnly && !isDir) continue;
      const hit =
        rule.basename !== undefined
          ? matchSegment(rule.basename, last, budget)
          : rule.segments !== null && matchSegments(rule.segments, segments, budget);
      if (hit) ignored = !rule.negated;
    }
    return ignored;
  };

  let overBudget = 0;
  return {
    patterns: rules.length,
    get overBudget() {
      return overBudget;
    },
    ignores(relPath: string, isDir = false): boolean {
      const path = normalise(relPath);
      if (path === null || path === '') return false;
      const segments = path.split('/');
      const budget: Budget = { left: MATCH_STEPS_BASE + MATCH_STEPS_PER_TEST * rules.length * segments.length };
      try {
        // A file inside an excluded directory cannot be re-included (git).
        for (let i = 1; i < segments.length; i++) {
          if (decide(segments.slice(0, i), true, budget)) return true;
        }
        return decide(segments, isDir, budget);
      } catch (e) {
        if (e !== BUDGET_SPENT) throw e;
        overBudget += 1;
        return false;
      }
    },
  };
}

/**
 * A project-relative path in POSIX form without a leading `./`, or null when
 * it is not relative to the project at all (absolute, or climbing out).
 */
function normalise(relPath: string): string | null {
  let p = relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
  if (p.startsWith('/') || /^[A-Za-z]:\//.test(p)) return null;
  p = p.replace(/\/{2,}/g, '/');
  if (p === '..' || p.startsWith('../')) return null;
  return p;
}

function parseLine(rawLine: string): Rule | null {
  // Trailing spaces are ignored unless escaped with a backslash.
  let line = rawLine.replace(/(?<!\\)[ \t]+$/, '');
  if (line.length === 0 || line.startsWith('#')) return null;
  let negated = false;
  if (line.startsWith('!')) {
    negated = true;
    line = line.slice(1);
  } else if (line.startsWith('\\!') || line.startsWith('\\#')) {
    line = line.slice(1);
  }
  let dirOnly = false;
  if (line.endsWith('/') && !line.endsWith('\\/')) {
    dirOnly = true;
    line = line.replace(/\/+$/, '');
  }
  if (line.length === 0) return null;
  // A slash at the start or in the middle anchors the pattern at the root;
  // otherwise it matches at any depth.
  const anchored = line.includes('/');
  if (line.startsWith('/')) line = line.slice(1);
  if (line.length === 0) return null;
  const body = compileSegments(line);
  if (body === null) return { negated, dirOnly, segments: null };
  if (anchored) return { negated, dirOnly, segments: body };
  // No slash: `**/` before it — which for one segment is "the last one".
  const only = body.length === 1 ? body[0] : undefined;
  return only !== undefined && only !== GLOBSTAR
    ? { negated, dirOnly, segments: [GLOBSTAR, only], basename: only }
    : { negated, dirOnly, segments: [GLOBSTAR, ...body] };
}

// ---- Matching, never by backtracking -------------------------------------
//
// A pattern is compiled to its path segments, not to a RegExp. 3.6.0 made
// each one a RegExp — `**/` became `(?:.*/)?`, `*` became `[^/]*` — and a
// RegExp of several such pieces backtracks without end on a path that almost
// matches (review 3.6.1, finding 1: `**/` nineteen times then `zz` took 7 s
// to test one path twelve directories deep, twelve `a*` then `b` 7-300 s
// against a 30-character name). The patterns are the scanned repository's,
// and the server has one thread. Here a segment is matched by the classic
// last-star algorithm — on a mismatch it resumes after the LAST `*` only —
// and the path's segments the same way, `**` playing the star: at most
// pattern length x path length steps, whatever the pattern, and never more
// than a path's budget (MATCH_STEPS_BASE).
//
// What a pattern means is git's (`wildmatch.c` with WM_PATHNAME, tested
// against `git check-ignore`): `?`, `*` and a class never match `/`; a
// `**` run between slashes (or the pattern's ends) matches whole
// directories — `**/` none or more, `/**` at the end everything inside,
// `**\/` one or more; a class takes git's `[:digit:]` names, `\` escapes and
// ranges, and an unterminated `[` or a trailing `\` matches nothing.
// Characters are UTF-16 code units, as 3.6.0's RegExps read them.

/** One character of a segment: a literal, or `?` / a class as a test. */
type CharToken = string | ((c: string) => boolean);
/** A run of `*` inside one segment: any characters, none or more. */
const STAR = 0;
type SegmentToken = CharToken | typeof STAR;
/** A whole-segment `**`: any segments, none or more. */
const GLOBSTAR = 1;
/** One path segment's pattern — a literal (compared whole), its tokens, or a `**`. */
type Segment = string | SegmentToken[] | typeof GLOBSTAR;

const anyChar = (): boolean => true;

/** git's `[:name:]` classes (its own ctype, ASCII only). */
const POSIX_CLASSES: Readonly<Record<string, (code: number) => boolean>> = {
  alnum: (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122),
  alpha: (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122),
  blank: (c) => c === 32 || c === 9,
  cntrl: (c) => c < 32 || c === 127,
  digit: (c) => c >= 48 && c <= 57,
  graph: (c) => c > 32 && c < 127,
  lower: (c) => c >= 97 && c <= 122,
  print: (c) => c >= 32 && c < 127,
  punct: (c) => c > 32 && c < 127 && !((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)),
  space: (c) => c === 32 || (c >= 9 && c <= 13),
  upper: (c) => c >= 65 && c <= 90,
  xdigit: (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102),
};

/**
 * The `[…]` opened at `start` (wildmatch.c's loop): where it ends and its
 * test, or null when git aborts on it — unterminated, or an unknown `[:name:]`.
 * A `]` first is a member; `a-z` is a range whose low end is also a member on
 * its own (so `[z-a]` matches `z`); `\x` is `x`.
 */
function parseClass(p: string, start: number): { end: number; test: (c: string) => boolean } | null {
  let j = start + 1;
  const negated = p.charAt(j) === '!' || p.charAt(j) === '^';
  if (negated) j += 1;
  const members = new Set<string>();
  const ranges: Array<[number, number]> = [];
  const named: Array<(code: number) => boolean> = [];
  let prev: string | null = null;
  for (let first = true; ; first = false) {
    if (j >= p.length) return null;
    const c = p.charAt(j);
    if (c === ']' && !first) break;
    if (c === '\\') {
      if (j + 1 >= p.length) return null;
      prev = p.charAt(j + 1);
      members.add(prev);
      j += 2;
    } else if (c === '-' && prev !== null && j + 1 < p.length && p.charAt(j + 1) !== ']') {
      let hi = j + 1;
      if (p.charAt(hi) === '\\') hi += 1;
      if (hi >= p.length) return null;
      ranges.push([prev.charCodeAt(0), p.charCodeAt(hi)]);
      prev = null;
      j = hi + 1;
    } else if (c === '[' && p.charAt(j + 1) === ':') {
      const close = p.indexOf(']', j + 2);
      if (close === -1) return null;
      if (close - 1 < j + 2 || p.charAt(close - 1) !== ':') {
        // No `:]` before the `]`: the `[` is a member, and the rest is read on.
        prev = '[';
        members.add(prev);
        j += 1;
        continue;
      }
      const test = POSIX_CLASSES[p.slice(j + 2, close - 1)];
      if (test === undefined) return null;
      named.push(test);
      prev = null;
      j = close + 1;
    } else {
      prev = c;
      members.add(c);
      j += 1;
    }
  }
  const test = (ch: string): boolean => {
    const code = ch.charCodeAt(0);
    const member = members.has(ch) || ranges.some(([lo, hi]) => code >= lo && code <= hi) || named.some((t) => t(code));
    return member !== negated && ch !== '/';
  };
  return { end: j + 1, test };
}

/** A pattern (leading `/` and trailing `/` already taken off) as its segments; null when git aborts on it. */
function compileSegments(p: string): Segment[] | null {
  const segments: Segment[] = [];
  let tokens: SegmentToken[] = [];
  /** False after a trailing `**`, which takes the place of the last segment. */
  let open = true;
  const close = (): void => {
    segments.push(tokens.every((t) => typeof t === 'string') ? tokens.join('') : tokens);
    tokens = [];
  };
  let i = 0;
  while (i < p.length) {
    const c = p.charAt(i);
    if (c === '*') {
      let j = i;
      while (p.charAt(j) === '*') j += 1;
      // A run of two or more between slashes (or the ends) is git's `**`.
      // Then the open segment is empty: `i` is 0 or follows a `/`, and every
      // `/` closes a segment.
      if (j - i >= 2 && (i === 0 || p.charAt(i - 1) === '/')) {
        if (p.charAt(j) === '/') {
          segments.push(GLOBSTAR);
          i = j + 1;
          continue;
        }
        if (j === p.length || (p.charAt(j) === '\\' && p.charAt(j + 1) === '/')) {
          // `**` at the end, or `**\/`: one segment or more.
          segments.push([STAR], GLOBSTAR);
          open = j < p.length;
          i = j === p.length ? j : j + 2;
          continue;
        }
      }
      if (tokens.at(-1) !== STAR) tokens.push(STAR);
      i = j;
    } else if (c === '?') {
      tokens.push(anyChar);
      i += 1;
    } else if (c === '[') {
      const cls = parseClass(p, i);
      if (cls === null) return null;
      tokens.push(cls.test);
      i = cls.end;
    } else if (c === '/') {
      close();
      i += 1;
    } else if (c === '\\') {
      if (i + 1 >= p.length) return null;
      const next = p.charAt(i + 1);
      if (next === '/') close();
      else tokens.push(next);
      i += 2;
    } else {
      tokens.push(c);
      i += 1;
    }
  }
  if (open) close();
  return segments;
}

/** Spend one step of `budget`. */
function step(budget: Budget): void {
  budget.left -= 1;
  if (budget.left < 0) throw BUDGET_SPENT;
}

/** One segment of a path against one segment's pattern (no `/` in either). */
function matchSegment(pattern: string | readonly SegmentToken[], text: string, budget: Budget): boolean {
  step(budget);
  if (typeof pattern === 'string') return pattern === text;
  let t = 0;
  let s = 0;
  let star = -1;
  let resume = 0;
  while (s < text.length) {
    step(budget);
    const tok = pattern[t];
    if (tok === STAR) {
      star = t;
      resume = s;
      t += 1;
    } else if (tok !== undefined && (typeof tok === 'string' ? tok === text.charAt(s) : tok(text.charAt(s)))) {
      t += 1;
      s += 1;
    } else if (star >= 0) {
      // Let the last `*` take one more character, and match on from there.
      t = star + 1;
      resume += 1;
      s = resume;
    } else {
      return false;
    }
  }
  while (pattern[t] === STAR) t += 1;
  return t === pattern.length;
}

/** A path's segments against a pattern's: the same algorithm, a `**` playing the `*`. */
function matchSegments(pattern: readonly Segment[], path: readonly string[], budget: Budget): boolean {
  let p = 0;
  let s = 0;
  let star = -1;
  let resume = 0;
  while (s < path.length) {
    step(budget);
    const seg = pattern[p];
    const part = path[s];
    if (part === undefined) break;
    if (seg === GLOBSTAR) {
      star = p;
      resume = s;
      p += 1;
    } else if (seg !== undefined && matchSegment(seg, part, budget)) {
      p += 1;
      s += 1;
    } else if (star >= 0) {
      p = star + 1;
      resume += 1;
      s = resume;
    } else {
      return false;
    }
  }
  while (pattern[p] === GLOBSTAR) p += 1;
  return p === pattern.length;
}

// ---- A project's exclusions -------------------------------------------

export interface ProjectExclusions {
  /** Absolute path of the ignore file. */
  file: string;
  /** sha256 of its content — part of every scan's cache key. */
  hash: string;
  patterns: number;
  ignores(relPath: string, isDir?: boolean): boolean;
  /** Top-most excluded directories (POSIX, project-relative, sorted). */
  excludedDirs: string[];
  /** Excluded files outside every excluded directory (sorted). */
  excludedFiles: string[];
  /** Every regular file the ignore file excludes (the walk's count). */
  excludedFileCount: number;
  /** Every regular file it keeps — what native flags are checked against. */
  keptFiles: string[];
  /**
   * What Semgrep anchors a leading-`/` `--exclude` at, relative to the
   * project: the project's path inside its git repository (`sub/`, or `''`
   * at the top level; the scan target itself outside git). Null when it
   * cannot be known — then no Semgrep exclude is passed at all.
   */
  semgrepAnchor: string | null;
}

interface ExclusionsLoadError {
  file: string;
  error: string;
}

/**
 * The project's `.guardianignore`, compiled and applied to the project's
 * files. Null when there is no such file; an error object when it exists and
 * cannot be read — the caller must say so, never proceed as if nothing were
 * excluded without a word.
 *
 * The files are git's own listing in a work tree (tracked, plus untracked
 * files `.gitignore` does not exclude — what Semgrep and the tree hash read,
 * and never a crawl of a gitignored `data/` of a million files), else a walk
 * of the directory. Either way `SCANNED_WALK_EXCLUDE` (`node_modules`,
 * `.git`, build output, …) and the root `.guardian/`'s generated output are
 * left out: no scan of the project's own files reads those (a `.guardian`
 * folder below the root is read — review 10, finding 1).
 *
 * `configRoot` is where the file itself is read — the project, unless the CI
 * gate took it from `--rules-ref` (`ci/refConfig.ts`): the ref's copy is then
 * applied to the project's files, and the project's own is never read.
 */
export async function loadProjectExclusions(
  projectPath: string,
  configRoot: string = projectPath,
): Promise<ProjectExclusions | ExclusionsLoadError | null> {
  const file = join(configRoot, GUARDIAN_IGNORE_FILE);
  // The repository's file (or the CI gate's --rules-ref copy): bounded,
  // regular files only, never through a link out of its root
  // (`platform/projectFs.ts`). One that is there and refused is an error the
  // caller reports, never "nothing excluded".
  const read = readProjectText(configRoot, GUARDIAN_IGNORE_FILE, MAX_GUARDIAN_IGNORE_BYTES);
  if (read.status === 'absent') return null;
  if (read.status === 'refused') return { file, error: `not read: ${describeReadRefusal(read.reason)}` };
  const text = read.text;
  const matcher = compileIgnore(text);
  if (matcher.refused !== undefined) return { file, error: `not applied: ${matcher.refused}` };
  const listed = await gitListFiles(projectPath);
  let semgrepAnchor: string | null;
  if (listed !== null) {
    const prefix = await git(projectPath, ['rev-parse', '--show-prefix']);
    semgrepAnchor = prefix.exitCode === 0 ? prefix.stdout.trim() : null;
  } else {
    // git could not list the project: outside any work tree Semgrep anchors
    // at the target; inside one (git failing for another reason) the anchor
    // is unknown.
    semgrepAnchor = insideGitWorkTree(projectPath) ? null : '';
  }
  const classified = classify(listed ?? walkScannedFiles(projectPath), matcher);
  // Some file was kept only because testing it took too long: the file's
  // exclusions are not what it says, so none of them is applied, and the
  // caller says so.
  if (matcher.overBudget > 0) {
    return {
      file,
      error:
        `not applied: testing ${String(matcher.overBudget)} path(s) against its ${String(matcher.patterns)} patterns ` +
        'took more steps than a path is allowed',
    };
  }
  return {
    file,
    hash: createHash('sha256').update(text).digest('hex'),
    patterns: matcher.patterns,
    ignores: (relPath, isDir) => matcher.ignores(relPath, isDir),
    ...classified,
    semgrepAnchor,
  };
}

/**
 * The project's files a scan reads, before `.guardianignore`: git's own
 * listing in a work tree, else a walk — `SCANNED_WALK_EXCLUDE` and the root
 * `.guardian/`'s generated output left out either way (the listing
 * {@link loadProjectExclusions} classifies). Project-relative, `/`-separated.
 */
export async function listScannedFiles(projectPath: string): Promise<string[]> {
  return (await gitListFiles(projectPath)) ?? walkScannedFiles(projectPath);
}

function walkScannedFiles(projectPath: string): string[] {
  return listProjectFiles(projectPath, SCANNED_WALK_EXCLUDE).filter((f) => !isGuardianOutput(f));
}

/** A name no file has, to ask whether EVERYTHING inside a directory is excluded (`libs/core/**`). */
const PROBE_CHILD = '.guardian-probe-7f3a';

/**
 * The submodules (project-relative directories) the project's
 * `.guardianignore` leaves in (round 4, item 6). One it excludes — by name
 * (`libs/core`), by a directory above it (`libs/`), or all of its contents
 * (`libs/core/**`) — is not the project's to scan, so its unscanned
 * contents are no gap; one it excludes only part of (`libs/core/*.js`) still
 * is. A `.guardianignore` that cannot be read excludes nothing here: the gap
 * stays named. `configRoot` is where it is read — the CI gate's `--rules-ref`
 * copy (`ci/refConfig.ts`) instead of the project, like `loadProjectExclusions`.
 */
export function submodulesNotIgnored(
  projectPath: string,
  submodules: readonly string[],
  configRoot: string = projectPath,
): string[] {
  if (submodules.length === 0) return [];
  const text = readProjectTextOrUndefined(configRoot, GUARDIAN_IGNORE_FILE, MAX_GUARDIAN_IGNORE_BYTES);
  if (text === undefined) return [...submodules];
  const matcher = compileIgnore(text);
  // git's "could not answer" is no path: no pattern (`*`) may drop it.
  return submodules.filter(
    (sub) => isGitUnanswered(sub) || (!matcher.ignores(sub, true) && !matcher.ignores(`${sub}/${PROBE_CHILD}`, false)),
  );
}

/**
 * Is a finding's `file_path` a path IN the project — the file itself, or a
 * directory it would sit in (a secret in a file a later commit deleted)? A
 * container image target (`alpine:3.18 (alpine 3.18.4)`) or Trivy's `Node.js`
 * pseudo-target can match a pattern (`alpine*`, `*.js`) and is no project
 * file: the result filter leaves those alone. A deleted top-level file has no
 * directory left to place it by and is kept too — the direction that never
 * hides a finding.
 */
export function isProjectPath(projectPath: string, relPath: string): boolean {
  return projectPathTest(projectPath)(relPath);
}

/**
 * {@link isProjectPath} for many paths of one project, asking the disk about
 * each DIRECTORY once: a scan's result filter used to `existsSync` every
 * finding (20 000 findings: 2-4 s on Windows). A path below the top level is
 * in the project exactly when one of its directories exists — the file itself
 * cannot exist without its directory — so only a top-level path (or one with
 * a `.`/`..` segment, where the lexical parent is not the real one) is looked
 * up by its own name. Answers are memoised for the returned function's
 * lifetime: make one per scan.
 */
export function projectPathTest(projectPath: string): (relPath: string) => boolean {
  const exists = new Map<string, boolean>();
  const onDisk = (segments: readonly string[]): boolean => {
    const key = segments.join('/');
    let v = exists.get(key);
    if (v === undefined) {
      v = presentInProject(projectPath, join(...segments));
      exists.set(key, v);
    }
    return v;
  };
  return (relPath) => {
    const p = relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
    if (p === '' || p.startsWith('/') || /^[A-Za-z]:/.test(p) || p === '..' || p.startsWith('../')) return false;
    const segments = p.split('/');
    if (segments.length === 1 || segments.some((s) => s === '.' || s === '..')) {
      if (onDisk(segments)) return true;
    }
    for (let i = segments.length - 1; i >= 1; i--) {
      if (onDisk(segments.slice(0, i))) return true;
    }
    return false;
  };
}

/** A `.git` (directory or worktree file) in the project or one of its ancestors. */
function insideGitWorkTree(projectPath: string): boolean {
  for (let dir = resolve(projectPath); ; dir = dirname(dir)) {
    // lstat only: a `.git` link is never followed to find out.
    if (projectEntryKind(join(dir, '.git')) !== 'absent') return true;
    if (dirname(dir) === dir) return false;
  }
}

/** `git ls-files` of the work tree at `root`, relative to it; null outside git. */
async function gitListFiles(root: string): Promise<string[] | null> {
  const r = await git(root, [
    'ls-files',
    '-z',
    '--cached',
    '--others',
    '--exclude-standard',
    ...[...SCANNED_WALK_EXCLUDE].map((d) => `--exclude=${d}/`),
  ]);
  if (r.exitCode !== 0) return null;
  const files = new Set<string>();
  for (const entry of splitNul(r.stdout)) {
    // Tracked files under an excluded directory name are listed by git; no
    // walk of the project would see them.
    if (entry.split('/').some((segment) => SCANNED_WALK_EXCLUDE.has(segment)) || isGuardianOutput(entry)) continue;
    files.add(entry);
  }
  return [...files];
}

/**
 * Each file is excluded by its top-most excluded directory, or by its own
 * pattern, or kept. Directory verdicts are memoised: a tree of thousands of
 * files under one excluded directory costs one match per directory.
 */
function classify(
  files: readonly string[],
  matcher: IgnoreMatcher,
): Pick<ProjectExclusions, 'excludedDirs' | 'excludedFiles' | 'excludedFileCount' | 'keptFiles'> {
  const dirVerdict = new Map<string, boolean>();
  const dirIgnored = (dir: string): boolean => {
    let v = dirVerdict.get(dir);
    if (v === undefined) {
      v = matcher.ignores(dir, true);
      dirVerdict.set(dir, v);
    }
    return v;
  };
  const excludedDirs = new Set<string>();
  const excludedFiles: string[] = [];
  const keptFiles: string[] = [];
  let excludedFileCount = 0;
  for (const f of files) {
    const segments = f.split('/');
    let top: string | null = null;
    for (let i = 1; i < segments.length; i++) {
      const dir = segments.slice(0, i).join('/');
      if (dirIgnored(dir)) {
        top = dir;
        break;
      }
    }
    if (top !== null) {
      excludedDirs.add(top);
      excludedFileCount += 1;
    } else if (matcher.ignores(f, false)) {
      excludedFiles.push(f);
      excludedFileCount += 1;
    } else {
      keptFiles.push(f);
    }
  }
  return {
    excludedDirs: [...excludedDirs].sort(),
    excludedFiles: excludedFiles.sort(),
    excludedFileCount,
    keptFiles: keptFiles.sort(),
  };
}

// ---- Native flags -----------------------------------------------------

interface NativeEntry {
  rel: string;
  dir: boolean;
}

function nativeEntries(ex: ProjectExclusions): NativeEntry[] {
  return [
    ...ex.excludedDirs.map((rel) => ({ rel, dir: true })),
    ...ex.excludedFiles.map((rel) => ({ rel, dir: false })),
  ];
}

/**
 * Would an UNANCHORED reading of `entry` (a scanner treating `a/b` as "a/b at
 * any depth") also exclude a file the ignore file keeps?
 */
function widensOntoKept(entry: NativeEntry, kept: readonly string[]): boolean {
  const needle = `/${entry.rel}`;
  return kept.some((k) => {
    const hay = `/${k}`;
    return entry.dir ? hay.includes(`${needle}/`) : hay.endsWith(needle);
  });
}

/** Keep entries until the count or character budget is spent. */
function withinBudget<T>(items: readonly T[], cost: (item: T) => number): T[] {
  const out: T[] = [];
  let used = 0;
  for (const item of items) {
    if (out.length >= MAX_NATIVE_ENTRIES) break;
    const c = cost(item);
    if (used + c > MAX_NATIVE_CHARS) break;
    out.push(item);
    used += c;
  }
  return out;
}

/**
 * `--exclude=/<anchor><path>` per top-most excluded path. The leading slash
 * anchors it at the GIT ROOT, where Semgrep 1.176.1 anchors it (measured —
 * see the module comment), hence `semgrepAnchor`; unknown anchor, no flags.
 * An entry holding glob syntax, or one an unanchored reading would widen onto
 * a kept file, is left to the result filter.
 */
export function semgrepExcludeArgs(ex: ProjectExclusions | null): string[] {
  if (ex === null || ex.semgrepAnchor === null) return [];
  const anchor = ex.semgrepAnchor;
  const patterns = nativeEntries(ex)
    .filter((e) => !widensOntoKept(e, ex.keptFiles))
    .map((e) => `/${anchor}${e.rel}`)
    // Glob syntax, or a trailing space gitignore would trim: not this path.
    .filter((p) => !GLOB_SYNTAX.test(p) && !/\s$/.test(p));
  return withinBudget(
    patterns.map((p) => `--exclude=${p}`),
    (a) => a.length + 3,
  );
}

/**
 * `--skip-dirs <dir>` / `--skip-files <file>`, project-relative: Trivy
 * matches them against the path relative to the scan target, anchored
 * (measured — `data/fx` skips `data/fx`, not `x/data/fx`; `data` skips only
 * the top-level one). They are doublestar patterns: a path with glob syntax
 * is left to the result filter.
 */
export function trivySkipArgs(ex: ProjectExclusions | null): string[] {
  if (ex === null) return [];
  const args: string[] = [];
  const plain = nativeEntries(ex).filter((e) => !GLOB_SYNTAX.test(e.rel));
  for (const e of withinBudget(plain, (entry) => entry.rel.length + 16)) {
    args.push(e.dir ? '--skip-dirs' : '--skip-files', e.rel);
  }
  return args;
}

/**
 * `-x <list>`: Bandit's defaults plus the absolute path of every top-most
 * excluded path (a directory with a trailing separator, so `data/fx` does not
 * also match `data/fx2`). Bandit tests each as a substring of the path it
 * walks, so an entry that is a prefix of a kept file's path, or holds a comma
 * (the list separator), is left to the result filter. Empty when nothing is
 * excluded — Bandit's own defaults then stay in force.
 */
export function banditExcludeArgs(ex: ProjectExclusions | null, projectPath: string): string[] {
  if (ex === null) return [];
  const keptAbs = ex.keptFiles.map((k) => join(projectPath, ...k.split('/')));
  const entries = nativeEntries(ex)
    .filter((e) => !e.rel.includes(','))
    .map((e) => {
      const abs = join(projectPath, ...e.rel.split('/'));
      return e.dir ? `${abs}${sep}` : abs;
    })
    .filter((abs) => !FNMATCH_SYNTAX.test(abs) && !keptAbs.some((k) => k.includes(abs)));
  const chosen = withinBudget(entries, (a) => a.length + 1);
  if (chosen.length === 0) return [];
  return ['-x', [...BANDIT_DEFAULT_EXCLUDES, ...chosen].join(',')];
}
