/**
 * A small, dependency-free glob: `*`, `?`, `**` and `{a,b}` over POSIX-style
 * relative paths — the subset workspace manifests (`pnpm-workspace.yaml`
 * `packages:`, `package.json` `workspaces`) and `register_custom_rules`
 * paths actually use.
 *
 * Not `fs.globSync` / `path.matchesGlob`: both are still experimental on the
 * Node 22 line this server supports, and print an `ExperimentalWarning` the
 * first time they run.
 */

import { listProjectDir, projectPathKind } from './projectFs.js';
import { join, relative, sep } from 'node:path';

/** True when `pattern` contains a glob metacharacter. */
export function hasGlobMagic(pattern: string): boolean {
  return /[*?{[]/.test(pattern);
}

/**
 * The pattern as an anchored RegExp over a POSIX relative path. `**` matches
 * any number of whole segments (including none), `*` and `?` stay inside one
 * segment, `{a,b}` is alternation. A leading `./` and a trailing `/` are
 * ignored.
 */
export function globToRegExp(pattern: string): RegExp {
  const p = pattern.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p.charAt(i);
    if (c === '*') {
      if (p.charAt(i + 1) === '*') {
        const atSegmentStart = i === 0 || p.charAt(i - 1) === '/';
        const atSegmentEnd = i + 2 === p.length || p.charAt(i + 2) === '/';
        if (atSegmentStart && atSegmentEnd) {
          if (i + 2 === p.length) {
            re += '.*';
            i += 1;
          } else {
            // `**/` — zero or more whole segments.
            re += '(?:[^/]*/)*';
            i += 2;
          }
          continue;
        }
        re += '[^/]*';
        i += 1;
        continue;
      }
      re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const close = p.indexOf('}', i);
      if (close === -1) {
        re += '\\{';
        continue;
      }
      const alternatives = p.slice(i + 1, close).split(',').map(escapeRegExp);
      re += `(?:${alternatives.join('|')})`;
      i = close;
    } else {
      re += escapeRegExp(c);
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * Does `relPath` match the pattern list? Later `!negations` remove what an
 * earlier pattern included — pnpm's and npm's own reading of the list.
 */
export function matchesAny(relPath: string, patterns: readonly string[]): boolean {
  const path = relPath.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
  let matched = false;
  for (const raw of patterns) {
    const negated = raw.startsWith('!');
    const pattern = negated ? raw.slice(1) : raw;
    if (pattern.length === 0) continue;
    if (globToRegExp(pattern).test(path)) matched = !negated;
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
  const re = globToRegExp(pattern);
  const out: string[] = [];
  let visited = 0;
  const walk = (dir: string): void => {
    for (const { name, kind } of listProjectDir(root, dir)) {
      if (visited++ > MAX_VISITED) return;
      const abs = join(dir, name);
      const rel = relative(root, abs).split(sep).join('/');
      if (kind === 'link' && projectPathKind(root, abs) === 'outside') continue;
      if (re.test(rel)) out.push(abs);
      if (kind === 'directory' && !SKIP_DIRS.has(name)) walk(abs);
    }
  };
  walk(root);
  return out.sort();
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
