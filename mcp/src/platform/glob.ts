/**
 * A small, dependency-free glob: `*`, `?`, `**` and `{a,b}` over POSIX-style
 * relative paths — the subset workspace manifests (`pnpm-workspace.yaml`
 * `packages:`, `package.json` `workspaces`) and `register_custom_rules`
 * paths actually use.
 *
 * Not `fs.globSync` / `path.matchesGlob`: both are still experimental on the
 * Node 22 line this server supports, and print an `ExperimentalWarning` the
 * first time they run.
 *
 * Not a regular expression either: a pattern can be the scanned
 * repository's (a workspace manifest), and as a backtracking expression each
 * wildcard multiplied the cost of a path it does not match — eight `**`
 * segments then `z` took 3.9 s on a path 30 segments deep, `*a*a*a*a*b` 1 s
 * on a 100-character name (measured). {@link globMatcher} reads the path
 * once, keeping every place in the pattern it could have reached: a test
 * costs at most the path's length times the pattern's.
 */

import { listProjectDir, projectPathKind } from './projectFs.js';
import { join, relative, sep } from 'node:path';

/** True when `pattern` contains a glob metacharacter. */
export function hasGlobMagic(pattern: string): boolean {
  return /[*?{[]/.test(pattern);
}

/**
 * One step of a glob: one of some literal strings; `?`, one character but
 * `/`; `*`, a run of them; `**` with its `/`, any number of whole segments,
 * each with its `/`; or a run of any characters but a line break (`**` at
 * the end, a workspace pattern's `**` anywhere).
 */
export type GlobStep =
  | { kind: 'literal'; options: readonly string[] }
  | { kind: 'char' }
  | { kind: 'star' }
  | { kind: 'segments' }
  | { kind: 'any' };

/** A compiled glob: whether it matches the whole of `path`. */
export interface GlobMatcher {
  test(path: string): boolean;
}

/** A place in a compiled glob: where each character leads from it, and where it leads with none. */
interface GlobState {
  reads: Array<{ accepts: (c: string) => boolean; to: GlobState }>;
  free: GlobState[];
}

const isSlash = (c: string): boolean => c === '/';
const notSlash = (c: string): boolean => c !== '/';
/** A regular expression's `.`, which `any` was: a character but a line terminator. */
const notLineBreak = (c: string): boolean => c !== '\n' && c !== '\r' && c !== ' ' && c !== ' ';

/** `states` and every state they lead to with no character. */
function closure(states: readonly GlobState[]): Set<GlobState> {
  const out = new Set<GlobState>();
  const pending = [...states];
  for (let s = pending.pop(); s !== undefined; s = pending.pop()) {
    if (out.has(s)) continue;
    out.add(s);
    pending.push(...s.free);
  }
  return out;
}

/** The steps as a matcher of whole paths, read one UTF-16 code unit at a time. */
export function globMatcher(steps: readonly GlobStep[]): GlobMatcher {
  const state = (): GlobState => ({ reads: [], free: [] });
  const start = state();
  let entry = start;
  for (const step of steps) {
    const exit = state();
    if (step.kind === 'literal') {
      for (const option of step.options) {
        let at = entry;
        for (let i = 0; i < option.length; i++) {
          const ch = option.charAt(i);
          const next = state();
          at.reads.push({ accepts: (c) => c === ch, to: next });
          at = next;
        }
        at.free.push(exit);
      }
    } else if (step.kind === 'char') {
      entry.reads.push({ accepts: notSlash, to: exit });
    } else if (step.kind === 'segments') {
      const inSegment = state();
      entry.reads.push({ accepts: isSlash, to: entry }, { accepts: notSlash, to: inSegment });
      inSegment.reads.push({ accepts: notSlash, to: inSegment }, { accepts: isSlash, to: entry });
      entry.free.push(exit);
    } else {
      entry.reads.push({ accepts: step.kind === 'star' ? notSlash : notLineBreak, to: entry });
      entry.free.push(exit);
    }
    entry = exit;
  }
  const accept = entry;
  return {
    test(path: string): boolean {
      let current = closure([start]);
      for (let i = 0; i < path.length && current.size > 0; i++) {
        const c = path.charAt(i);
        const next: GlobState[] = [];
        for (const s of current) for (const r of s.reads) if (r.accepts(c)) next.push(r.to);
        current = closure(next);
      }
      return current.has(accept);
    },
  };
}

/** `text` without its trailing `/`s, in one pass: `/\/+$/` read every run of them to its end again. */
export function withoutTrailingSlashes(text: string): string {
  let end = text.length;
  while (end > 0 && text.charAt(end - 1) === '/') end -= 1;
  return text.slice(0, end);
}

/**
 * The pattern as an anchored matcher over a POSIX relative path. `**` matches
 * any number of whole segments (including none), `*` and `?` stay inside one
 * segment, `{a,b}` is alternation. A leading `./` and a trailing `/` are
 * ignored.
 */
export function compileGlob(pattern: string): GlobMatcher {
  const p = withoutTrailingSlashes(pattern.replace(/\\/g, '/').replace(/^(\.\/)+/, ''));
  const steps: GlobStep[] = [];
  for (let i = 0; i < p.length; i++) {
    const c = p.charAt(i);
    if (c === '*') {
      if (p.charAt(i + 1) === '*') {
        const atSegmentStart = i === 0 || p.charAt(i - 1) === '/';
        const atSegmentEnd = i + 2 === p.length || p.charAt(i + 2) === '/';
        if (atSegmentStart && atSegmentEnd) {
          if (i + 2 === p.length) {
            steps.push({ kind: 'any' });
            i += 1;
          } else {
            // `**/` — zero or more whole segments.
            steps.push({ kind: 'segments' });
            i += 2;
          }
          continue;
        }
        steps.push({ kind: 'star' });
        i += 1;
        continue;
      }
      steps.push({ kind: 'star' });
    } else if (c === '?') {
      steps.push({ kind: 'char' });
    } else if (c === '{') {
      const close = p.indexOf('}', i);
      if (close === -1) {
        steps.push({ kind: 'literal', options: ['{'] });
        continue;
      }
      steps.push({ kind: 'literal', options: p.slice(i + 1, close).split(',') });
      i = close;
    } else {
      steps.push({ kind: 'literal', options: [c] });
    }
  }
  return globMatcher(steps);
}

/**
 * Does `relPath` match the pattern list? Later `!negations` remove what an
 * earlier pattern included — pnpm's and npm's own reading of the list.
 */
export function matchesAny(relPath: string, patterns: readonly string[]): boolean {
  const path = withoutTrailingSlashes(relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, ''));
  let matched = false;
  for (const raw of patterns) {
    const negated = raw.startsWith('!');
    const pattern = negated ? raw.slice(1) : raw;
    if (pattern.length === 0) continue;
    if (compileGlob(pattern).test(path)) matched = !negated;
  }
  return matched;
}

/** Directories never descended into while expanding a pattern. */
const SKIP_DIRS = new Set(['.git', 'node_modules']);

/** Upper bound on entries visited by one expansion — a runaway `**` stops here. */
const MAX_VISITED = 50_000;

/**
 * Every existing file or directory under `root` whose POSIX relative path
 * matches `pattern` (relative to `root`), sorted. `root` is the project, so
 * the walk is `platform/projectFs.ts`'s: a directory link is never descended
 * (no loop, nothing outside `root` listed), and a link matches only when it
 * resolves inside `root`. `.git` and `node_modules` are never entered.
 */
export function expandGlob(root: string, pattern: string): string[] {
  const glob = compileGlob(pattern);
  const out: string[] = [];
  let visited = 0;
  const walk = (dir: string): void => {
    for (const { name, kind } of listProjectDir(root, dir)) {
      if (visited++ > MAX_VISITED) return;
      const abs = join(dir, name);
      const rel = relative(root, abs).split(sep).join('/');
      if (kind === 'link' && projectPathKind(root, abs) === 'outside') continue;
      if (glob.test(rel)) out.push(abs);
      if (kind === 'directory' && !SKIP_DIRS.has(name)) walk(abs);
    }
  };
  walk(root);
  return out.sort();
}
