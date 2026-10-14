/**
 * Which of a list of project files are not, in the scanned tree, what they
 * were at a commit — for the CI gate's `semgrep.accept_timeouts` under
 * `--baseline-ref` / `--rules-ref` (review 11, finding 1).
 *
 * An accepted per-file timeout covers a file as a reviewer saw it. With the
 * acceptance keyed by path alone, a pull request appended
 * `exec('cat ' + req.query.file)` to an accepted `src/big.js`, the rule that
 * would have caught it timed out like every other on that file, and the gate
 * passed (exit 0, the gap under `accepted_gaps`). Under a ref, a timeout on a
 * file that changed since it is not accepted.
 *
 * Changed means: absent at the commit (`git ls-tree`), or listed by
 * `git diff --name-only <commit>` — the working tree against the commit,
 * committed and uncommitted changes alike, with git's own line-ending
 * conversion (a CRLF checkout of an unchanged file is unchanged). Pathspecs
 * are literal (`pages/[id].js` is a file). An untracked file at a path the
 * commit has is listed by the diff (deleted from the index's view).
 *
 * Never throws: when git cannot answer, `error` says why and the caller
 * accepts no timeout — "could not compare" is never "unchanged".
 */

import { git, splitNul } from '../runners/git.js';

/** Paths per git call: well inside Windows' 32 767-character command line. */
const BATCH = 100;

export async function filesChangedSince(
  projectPath: string,
  commit: string,
  paths: readonly string[],
): Promise<{ changed: Set<string> } | { error: string }> {
  const changed = new Set<string>();
  const wanted = [...new Set(paths)];
  for (let i = 0; i < wanted.length; i += BATCH) {
    const batch = wanted.slice(i, i + BATCH);
    // `--relative` paths, from the project (which may be a repository's
    // subdirectory): ls-tree's are relative to the working directory too.
    const listed = await git(projectPath, ['--literal-pathspecs', 'ls-tree', '-r', '-z', '--name-only', commit, '--', ...batch]);
    if (listed.exitCode !== 0) return { error: firstLine(listed.stderr) || `git ls-tree exited ${listed.exitCode}` };
    const atCommit = new Set(splitNul(listed.stdout));
    for (const path of batch) if (!atCommit.has(path)) changed.add(path);
    const diff = await git(projectPath, ['--literal-pathspecs', 'diff', '--name-only', '--relative', '--no-renames', '-z', commit, '--', ...batch]);
    if (diff.exitCode !== 0) return { error: firstLine(diff.stderr) || `git diff exited ${diff.exitCode}` };
    for (const path of splitNul(diff.stdout)) changed.add(path);
  }
  return { changed };
}

function firstLine(text: string): string {
  return text.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? '';
}
