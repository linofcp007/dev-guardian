/**
 * The git a test runs with — for the tests whose honest expectation depends
 * on it.
 *
 * The secrets history pass reads every commit's change with the working
 * tree's `.gitattributes` set aside (`src/runners/historyView.ts`): through
 * `GIT_ATTR_SOURCE` from git 2.40, and on an older git by starting git from
 * an empty directory. Until that second half existed, the tree's attributes
 * applied on an older git and the pass said so in a sentence of its own —
 * which the tests of that time asserted where it was true: Debian 12 ships
 * git 2.39.5, the image this suite runs on in containers and the base of a
 * great deal of real CI. What still depends on the git is a merge's own
 * change (`--diff-merges=remerge`, 2.36).
 */

import { spawnSync } from 'node:child_process';

/** `[major, minor]` of the `git` on PATH. Throws when it cannot be read: a test never picks a branch by guessing. */
export function gitVersion(): [number, number] {
  const r = spawnSync('git', ['--version'], { encoding: 'utf8', timeout: 30_000 });
  const m = /git version (\d+)\.(\d+)/.exec(String(r.stdout ?? ''));
  if (r.status !== 0 || m === null) throw new Error(`could not read the git version: ${String(r.stdout ?? '').trim() || String(r.stderr ?? '').trim() || 'no output'}`);
  return [Number(m[1]), Number(m[2])];
}

/** Whether the `git` on PATH is at least `major.minor`. */
export function gitAtLeast(major: number, minor: number): boolean {
  const [a, b] = gitVersion();
  return a > major || (a === major && b >= minor);
}

/**
 * What the history pass says when it could NOT set the tree's `.gitattributes` aside — only on a git older than 2.40
 * whose git directory could not be resolved. On a run that read the history as committed it must not be there.
 */
export const TREE_ATTRIBUTES_LIMIT = /the working tree's \.gitattributes applied to every commit's change .*GIT_ATTR_SOURCE needs git 2\.40/;
