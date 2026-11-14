/**
 * The git a test runs with — for the tests whose honest expectation depends
 * on it.
 *
 * The secrets history pass reads every commit's change with the working
 * tree's `.gitattributes` set aside, through `GIT_ATTR_SOURCE`, which git has
 * from 2.40 (`src/runners/historyView.ts`). On an older git the tree's
 * attributes apply, a file it marks `binary` is in no hunk, and the pass says
 * so in a sentence of its own. Debian 12 ships git 2.39.5 — the image this
 * suite runs on in containers, and the base of a great deal of real CI — so
 * a test that expected the key found on every git was a test that had only
 * ever run on a newer one.
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

/** The first git with `GIT_ATTR_SOURCE`: the history pass sets the tree's `.gitattributes` aside from here on. */
export const GIT_SETS_TREE_ATTRIBUTES_ASIDE = gitAtLeast(2, 40);

/** What the history pass says of itself on an older git — the limit it names, never a silent gap. */
export const TREE_ATTRIBUTES_LIMIT = /the working tree's \.gitattributes applied to every commit's change .*GIT_ATTR_SOURCE needs git 2\.40/;
