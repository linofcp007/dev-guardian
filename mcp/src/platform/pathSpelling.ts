/**
 * Whether a stored project path is another SPELLING of a directory — the
 * same directory entries, written differently — and never a path that
 * reaches it through a link.
 *
 * Spellings of one directory: a lower-case drive letter (2.0.0 stored
 * `resolve(input)`: `c:\Users\…`), letter case on a case-insensitive file
 * system, an 8.3 short name, separators, `.` and `..`. None of those can come
 * to mean another directory. A link can: `~/work/current` repointed from
 * project A to project B, or `/proc/self/cwd`, which is whatever directory
 * the reading process runs in — a path anyone can write into a database that
 * then "matches" every project it is opened in. So a path with a symbolic
 * link or junction in any component is never a spelling of anything.
 */

import { lstatSync, statSync } from 'node:fs';
import { isAbsolute, join, parse, resolve, sep } from 'node:path';
import { canonicalPath } from './projectPath.js';

/**
 * The canonical spelling of `path` when it names an existing directory,
 * differs from it, and reaches it through no link; null otherwise.
 */
export function spellingOnlyCanonical(path: string): string | null {
  if (!isAbsolute(path)) return null;
  try {
    if (!statSync(path).isDirectory()) return null;
  } catch {
    return null;
  }
  const canonical = canonicalPath(path);
  if (canonical === path) return null;
  // Every component, from the root down, must be a real directory entry.
  const resolved = resolve(path);
  const root = parse(resolved).root;
  let current = root;
  for (const part of resolved.slice(root.length).split(sep).filter((s) => s !== '')) {
    current = join(current, part);
    try {
      if (lstatSync(current).isSymbolicLink()) return null;
    } catch {
      return null;
    }
  }
  return canonical;
}

/** Whether `stored` is `canonicalProject` itself, or a spelling of it ({@link spellingOnlyCanonical}). */
export function isSpellingOf(stored: string, canonicalProject: string): boolean {
  return stored === canonicalProject || spellingOnlyCanonical(stored) === canonicalProject;
}
