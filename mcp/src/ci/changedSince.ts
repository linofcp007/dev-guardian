/**
 * Which of a list of project files are not, in the scanned tree, what they
 * were at a commit — for the CI gate's `semgrep.accept_timeouts` (review 11
 * finding 1, review 12 finding 10).
 *
 * An accepted per-file timeout covers a file as a reviewer saw it. With the
 * acceptance keyed by path alone, a pull request appended
 * `exec('cat ' + req.query.file)` to an accepted `src/big.js`, the rule that
 * would have caught it timed out like every other on that file, and the gate
 * passed (exit 0, the gap under `accepted_gaps`). So a timeout is accepted
 * only on a file unchanged since the commit that stands for the review:
 *
 *   - under `--baseline-ref` / `--rules-ref`, that ref;
 *   - without one — a local run, dev-spec-driven's own gate command — the
 *     last commit that changed `.guardian/scan.yml` ({@link scanSettingsCommit}):
 *     committing the acceptance is what reviews it.
 *
 * Changed means: absent at the commit (`git ls-tree`), not a regular file in
 * the tree (a link, a directory, gone), or a different CONTENT — the tree's
 * file hashed as git would store it (`git hash-object`, its line-ending
 * attributes applied, so a CRLF checkout of an unchanged file is unchanged)
 * against the blob at the commit. Content, not `git diff`: diff trusts the
 * index's `assume-unchanged` and `skip-worktree` flags, and a file with
 * either set passed as unchanged with an injection appended (review 12,
 * finding 10). Paths are literal (`pages/[id].js` is a file).
 *
 * Never throws: when git cannot answer, `error` says why and the caller
 * accepts no timeout — "could not compare" is never "unchanged".
 *
 * {@link filesChangedFrom} lists the files a pull request changed, for the
 * gate's full-content secrets pass.
 */

import { join } from 'node:path';
import { projectEntryKind, projectPathKind } from '../platform/projectFs.js';
import { git, repoState, splitNul } from '../runners/git.js';

/** Paths per git call: well inside Windows' 32 767-character command line. */
const BATCH = 100;

/** Where the project's scan settings live (`platform/scanSettings.ts`), for the commit that last changed them. */
const SCAN_SETTINGS_PATH = '.guardian/scan.yml';

export async function filesChangedSince(
  projectPath: string,
  commit: string,
  paths: readonly string[],
): Promise<{ changed: Set<string> } | { error: string }> {
  const changed = new Set<string>();
  const wanted = [...new Set(paths)];
  for (let i = 0; i < wanted.length; i += BATCH) {
    const batch = wanted.slice(i, i + BATCH);
    // Paths relative to the project (which may be a repository's
    // subdirectory): ls-tree's are relative to the working directory too.
    const listed = await git(projectPath, ['--literal-pathspecs', 'ls-tree', '-r', '-z', commit, '--', ...batch]);
    if (listed.exitCode !== 0) return { error: firstLine(listed.stderr) || `git ls-tree exited ${listed.exitCode}` };
    const atCommit = new Map<string, string>();
    for (const entry of splitNul(listed.stdout)) {
      const m = /^\d+ blob ([0-9a-f]{40,64})\t([\s\S]+)$/.exec(entry);
      if (m?.[1] !== undefined && m[2] !== undefined) atCommit.set(m[2], m[1]);
    }
    const toHash: string[] = [];
    for (const path of batch) {
      // Hashed only as a regular file of the project: a link, a FIFO or a
      // directory is changed, never read (a FIFO would hold git's read).
      const regular = projectPathKind(projectPath, path) === 'file' && projectEntryKind(join(projectPath, path)) === 'file';
      if (!atCommit.has(path) || !regular) changed.add(path);
      else toHash.push(path);
    }
    if (toHash.length === 0) continue;
    const hashed = await git(projectPath, ['hash-object', '--', ...toHash]);
    if (hashed.exitCode !== 0) return { error: firstLine(hashed.stderr) || `git hash-object exited ${hashed.exitCode}` };
    const shas = hashed.stdout.split(/\r?\n/).filter((l) => l.trim() !== '');
    if (shas.length !== toHash.length) return { error: 'git hash-object did not hash every file' };
    toHash.forEach((path, n) => {
      if (shas[n]?.trim() !== atCommit.get(path)) changed.add(path);
    });
  }
  return { changed };
}

/**
 * Every regular file of the project that is not, at HEAD or in the working
 * tree, what it was at `commit` — added, modified, renamed or retyped since —
 * as paths relative to the project: the CI gate's full-content secrets pass
 * reads them whole (`ci/runScans.ts`, review 12 finding 11). HEAD is compared
 * tree to tree too, so an index flag (`skip-worktree`) hides no committed
 * change. A link, a directory or a file gone from disk is left out: there is
 * no file to read. `error` when git cannot answer.
 */
export async function filesChangedFrom(
  projectPath: string,
  commit: string,
): Promise<{ files: string[] } | { error: string }> {
  const listed = new Set<string>();
  for (const sides of [[commit, 'HEAD'], [commit]]) {
    const r = await git(projectPath, ['diff', '-z', '--name-only', '--relative', '--no-renames', '--diff-filter=ACMRT', ...sides, '--']);
    if (r.exitCode !== 0) return { error: firstLine(r.stderr) || `git diff exited ${r.exitCode}` };
    for (const path of splitNul(r.stdout)) listed.add(path);
  }
  const files = [...listed]
    .filter((path) => projectPathKind(projectPath, path) === 'file' && projectEntryKind(join(projectPath, path)) === 'file')
    .sort();
  return { files };
}

/**
 * The commit that last changed `.guardian/scan.yml` — what a gate run without
 * a ref compares an accepted file with (see the module comment). `none`: not a
 * git repository, so there is nothing to compare with and an acceptance
 * stands as written. `error`: a repository in which no commit holds the file,
 * or git could not answer — no acceptance applies.
 */
export async function scanSettingsCommit(
  projectPath: string,
): Promise<{ commit: string } | { none: true } | { error: string }> {
  const state = await repoState(projectPath);
  if (state.kind === 'not_git') return { none: true };
  const uncommitted = `no commit holds ${SCAN_SETTINGS_PATH} yet: an acceptance is reviewed by committing it`;
  if (state.kind === 'no_commits') return { error: uncommitted };
  if (state.kind === 'error') return { error: state.message };
  const log = await git(projectPath, ['--literal-pathspecs', 'log', '-1', '--format=%H', '--', SCAN_SETTINGS_PATH]);
  if (log.exitCode !== 0) return { error: firstLine(log.stderr) || `git log exited ${log.exitCode}` };
  const commit = log.stdout.trim();
  return /^[0-9a-f]{40,64}$/.test(commit) ? { commit } : { error: uncommitted };
}

function firstLine(text: string): string {
  return text.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? '';
}
