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
 * the tree (a link, a directory, gone), a file git stores as something other
 * than its bytes up to line endings ({@link gitBlobsOf}: an `ident`, `filter`
 * or `working-tree-encoding` attribute), or a different CONTENT — the tree's
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
import { git, repoState, splitNul, type GitRunner } from '../runners/git.js';

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
    // A file the commit does not have is changed, never hashed; a link, a FIFO
    // or a directory is changed, never read ({@link gitBlobsOf}).
    const hashed = await gitBlobsOf(projectPath, batch.filter((path) => atCommit.has(path)));
    if ('error' in hashed) return hashed;
    for (const path of batch) {
      const blob = hashed.blobs.get(path);
      if (blob === undefined || blob === null || blob !== atCommit.get(path)) changed.add(path);
    }
  }
  return { changed };
}

/**
 * The object id git would store each of `paths` under — the project's file
 * hashed as git stores it (`git hash-object`: its line-ending attributes
 * applied, so a CRLF checkout of a file reads as the LF one; the index's
 * `assume-unchanged` / `skip-worktree` flags never consulted) — or null for a
 * path that is not a regular file of the project: a link, a FIFO or a
 * directory is never read (a FIFO would hold git's read), and a file gone
 * has no content. Paths relative to the project, which may be a repository's
 * subdirectory. `error` when git cannot hash — never read as a content.
 *
 * Null too for a file git stores as something other than its bytes up to
 * line endings ({@link CONTENT_ATTRIBUTES}, one `git check-attr -z` per
 * batch, before the hash): with `ident`, git's clean step turns any
 * `$Id:<anything>$` into `$Id$`, so a change that put new code between the
 * markers of a recorded file, plus one `.gitattributes` line, hashed to the
 * recorded blob and its finding read "not new" (3.18.0 review 1, DGBASE-1); a
 * `filter` or a `working-tree-encoding` stores what the scanner did not read
 * either. The line-ending conversion (`text`, `eol`, `core.autocrlf`) is
 * kept: it only drops the CR of a CRLF, a Windows checkout's parity with a
 * Linux one rests on it, and a repository that normalises line endings
 * (`* text=auto`) sets it on every file.
 *
 * The gate's one "unchanged as git stores it": {@link filesChangedSince}
 * compares it with a commit's blob (`semgrep.accept_timeouts`), and the
 * baseline's taint-incomplete records (`ci/taintIncomplete.ts`, 3.18.0) with
 * the blob `baseline update` recorded.
 */
export async function gitBlobsOf(
  projectPath: string,
  paths: readonly string[],
  run: GitRunner = git,
): Promise<{ blobs: Map<string, string | null> } | { error: string }> {
  const blobs = new Map<string, string | null>();
  const wanted = [...new Set(paths)];
  for (let i = 0; i < wanted.length; i += BATCH) {
    const regular: string[] = [];
    for (const path of wanted.slice(i, i + BATCH)) {
      const isRegular = projectPathKind(projectPath, path) === 'file' && projectEntryKind(join(projectPath, path)) === 'file';
      if (isRegular) regular.push(path);
      else blobs.set(path, null);
    }
    if (regular.length === 0) continue;
    const asRead = await storedAsRead(projectPath, regular, run);
    if ('error' in asRead) return asRead;
    const toHash = regular.filter((path) => asRead.paths.has(path));
    for (const path of regular) if (!asRead.paths.has(path)) blobs.set(path, null);
    if (toHash.length === 0) continue;
    const hashed = await run(projectPath, ['hash-object', '--', ...toHash]);
    if (hashed.exitCode !== 0) return { error: firstLine(hashed.stderr) || `git hash-object exited ${hashed.exitCode}` };
    const shas = hashed.stdout.split(/\r?\n/).filter((l) => l.trim() !== '');
    if (shas.length !== toHash.length) return { error: 'git hash-object did not hash every file' };
    toHash.forEach((path, n) => blobs.set(path, shas[n]?.trim() ?? null));
  }
  return { blobs };
}

/**
 * The gitattributes that make git store a file as something other than its
 * bytes up to line endings — every conversion on git's way in but the
 * line-ending one: `ident` collapses `$Id:<anything>$` to `$Id$`, `filter`
 * runs a clean driver (Git LFS stores a pointer), `working-tree-encoding`
 * re-encodes. Each is off only when git says `unspecified` or `unset`; any
 * value, `set` included, is on.
 */
const CONTENT_ATTRIBUTES: readonly string[] = ['ident', 'filter', 'working-tree-encoding'];

/**
 * Which of `paths` git stores as their bytes up to line endings — none of
 * {@link CONTENT_ATTRIBUTES} on — from one `git check-attr -z`, which reads
 * the attribute sources `hash-object` reads (the tree's `.gitattributes`,
 * `.git/info/attributes`, `core.attributesFile`). A path git gave no full
 * answer for is not one of them: never "as read" on an answer not given.
 */
async function storedAsRead(
  projectPath: string,
  paths: readonly string[],
  run: GitRunner,
): Promise<{ paths: Set<string> } | { error: string }> {
  const r = await run(projectPath, ['check-attr', '-z', ...CONTENT_ATTRIBUTES, '--', ...paths]);
  if (r.exitCode !== 0) return { error: firstLine(r.stderr) || `git check-attr exited ${r.exitCode}` };
  // `<path> NUL <attribute> NUL <value> NUL`, each path as it was given.
  const fields = r.stdout.split('\0');
  const off = new Map<string, number>();
  const on = new Set<string>();
  for (let i = 0; i + 2 < fields.length; i += 3) {
    const path = fields[i] ?? '';
    const attribute = fields[i + 1] ?? '';
    const value = fields[i + 2] ?? '';
    if (!CONTENT_ATTRIBUTES.includes(attribute)) continue;
    if (value === 'unspecified' || value === 'unset') off.set(path, (off.get(path) ?? 0) + 1);
    else on.add(path);
  }
  return { paths: new Set(paths.filter((path) => !on.has(path) && off.get(path) === CONTENT_ATTRIBUTES.length)) };
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
