/**
 * Semgrep's own directory walk and Windows' path limits — measured on Semgrep
 * 1.176.1 with Windows' default `LongPathsEnabled=0`, 2026-10-25:
 *
 *   - One directory at a path of 256 characters or more ANYWHERE in the tree
 *     (256–259, and 261 up; one of exactly 260 was listed) makes semgrep-core
 *     fail the whole listing — `Failed to obtain target files from
 *     semgrep-core`, nothing scanned, the files at the root included. A WordPress
 *     install copied off a server is the usual shape (WooCommerce 11.2.1's
 *     `packages/email-editor/src/Integrations/Core/Renderer/Blocks/icons/*`
 *     under a deep folder). In a git repository Semgrep lists through git and is
 *     not affected (git itself cannot add such a directory without
 *     `core.longpaths`).
 *   - `--exclude=<the directory, project-relative>` keeps the walk out of it and
 *     the rest of the tree is listed, every `.semgrepignore` still honoured —
 *     which explicit file targets would not be (measured: an explicit target
 *     under an ignored directory was scanned). With the absolute target the
 *     callers pass, the pattern has no leading `/`: an anchored one matched
 *     nothing. One with a `/` inside is anchored to the target by gitignore's
 *     rules; a one-segment name matches at any depth, but only directories at
 *     least as long, which are excluded anyway.
 *
 * So a run that failed that way, on Windows, is run again with each directory
 * at {@link WINDOWS_DIR_MAX} characters or more excluded (the top-most of a
 * chain), measured on the real path — whose files the long-path gap names
 * (`frameworks/projectLanguages.ts#longPathsOf`), never left out unsaid.
 */

import { join, win32 } from 'node:path';
import { listProjectDirOrNull, realpathInProject } from '../platform/projectFs.js';

/**
 * The longest path Windows allows a directory — `MAX_PATH` less the 12
 * characters of an 8.3 file name. Semgrep's walk broke from 256 up; a
 * directory this long is excluded, and its files named, with that margin.
 */
export const WINDOWS_DIR_MAX = 248;

/** How many directories one search lists at most: a tree bigger than this is not searched past it. */
const MAX_DIRS = 100_000;

/** What Semgrep says when its walk could not list the targets. */
const LISTING_FAILED = /Failed to obtain target files from semgrep-core/;

/** Whether a Semgrep run's output — its JSON report, stdout or stderr — says it could not list its targets. */
export function failedToListTargets(...outputs: ReadonlyArray<string | null | undefined>): boolean {
  return outputs.some((o) => o !== null && o !== undefined && LISTING_FAILED.test(o));
}

/**
 * The project's top-most directories whose real path is {@link WINDOWS_DIR_MAX}
 * characters or longer, project-relative and `/`-separated, sorted; none
 * elsewhere than Windows. Links are never followed (`listProjectDirOrNull`), and
 * `.git` is not read.
 */
export function longDirsUnder(root: string, platform: NodeJS.Platform = process.platform): string[] {
  if (platform !== 'win32') return [];
  // The real path: a short (8.3) name in the given one would hide its length.
  const base = realpathInProject(root, '.') ?? win32.resolve(root);
  const out: string[] = [];
  const stack: string[] = [''];
  let listed = 0;
  while (stack.length > 0 && listed < MAX_DIRS) {
    const rel = stack.pop() ?? '';
    const entries = listProjectDirOrNull(root, rel === '' ? '.' : join(...rel.split('/')));
    listed++;
    if (entries === null) continue;
    for (const e of entries) {
      if (e.kind !== 'directory' || (rel === '' && e.name === '.git')) continue;
      const child = rel === '' ? e.name : `${rel}/${e.name}`;
      if (win32.join(base, ...child.split('/')).length >= WINDOWS_DIR_MAX) out.push(child);
      else stack.push(child);
    }
  }
  return out.sort();
}

/** `--exclude=<rel>`, its glob characters escaped (gitignore's rules: a backslash before each). */
export function semgrepExcludeForDir(rel: string): string {
  return `--exclude=${rel.replace(/[\\*?[\]!#]/g, (c) => `\\${c}`)}`;
}
