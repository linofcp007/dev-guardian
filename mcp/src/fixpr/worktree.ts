/**
 * `createWorktree` — the isolation `create_fix_pr` runs every fix inside
 * (design doc the design of record
 * §3).
 *
 * Two properties this module exists to hold:
 *
 *   1. The user's working tree is never touched. The worktree branches from
 *      committed HEAD, in a fresh directory, on a fresh branch — uncommitted
 *      work in the caller's own checkout is irrelevant and stays exactly as
 *      it was, because nothing here ever reads it.
 *   2. The worktree is removed on every path, including every failure path.
 *      This is the `mcp/src/ci/appRunner.ts` lesson applied to git instead
 *      of a child process: teardown belongs in the CALLER's `finally`
 *      (`worktree.remove()`, not anything automatic here), and correctness
 *      is judged by observing the world afterwards (`git worktree list`,
 *      `existsSync`) — never by trusting a return value the implementation
 *      itself controls.
 *
 * This is the first code in the repository that WRITES through git — every
 * other git invocation here is a read (`status --porcelain`, `rev-parse`,
 * `diff --name-only`, `ls-files`, `symbolic-ref`). Every call in this module
 * goes through `runProcess`: no shell, argv arrays end to end, and it never
 * throws — outcomes are inspected, not caught.
 */

import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';

export interface Worktree {
  /** Absolute path to the worktree directory. */
  path: string;
  /** The branch created inside it. */
  branch: string;
  /** Idempotent. Removes the worktree and prunes. Safe to call twice. */
  remove(): Promise<{ removed: boolean; warning: string | null }>;
}

/**
 * Exported only so the integration test can assert no directory bearing this
 * prefix survives a create+remove cycle, or a failed create — the same
 * reason `testCommand.ts` exports `TEST_MANIFESTS` rather than letting the
 * test duplicate a literal that could silently drift from the real one.
 */
export const WORKTREE_DIR_PREFIX = 'guardian-fixpr-wt-';

export async function createWorktree(opts: {
  /** Expected already resolved/absolute, as every other tool in this repo
   *  hands `resolveProjectPath()`'s output around rather than a raw input. */
  projectPath: string;
  branch: string;
  timeoutMs?: number;
}): Promise<{ ok: true; worktree: Worktree } | { ok: false; reason: string }> {
  let dir: string;
  try {
    // A fresh, empty, guaranteed-unique directory for `git worktree add` to
    // target — created ourselves, rather than letting git invent a path, so
    // it is unconditionally ours to clean up on the failure branch below.
    // Empirically confirmed (both failure modes this module returns `ok:
    // false` for — target not a git repo, branch already exists): git
    // leaves this directory exactly as it found it, still empty, never
    // touches it before failing.
    dir = mkdtempSync(join(tmpdir(), WORKTREE_DIR_PREFIX));
  } catch (e) {
    return { ok: false, reason: `could not create a temp directory: ${errorMessage(e)}` };
  }

  const add = await runProcess({
    command: 'git',
    args: ['-C', opts.projectPath, 'worktree', 'add', '-b', opts.branch, dir, 'HEAD'],
    cwd: opts.projectPath,
    timeoutMs: opts.timeoutMs,
  });

  if (add.outcome !== 'completed') {
    // Ours to remove — see the comment on `dir` above. Best-effort: a
    // failure here rides along with the (already-failing) result rather
    // than escalating into a second, different failure.
    safeRmDir(dir);
    // Defence in depth beyond the two failure modes this module tests
    // directly (target not a git repo; branch already exists) — both
    // confirmed empirically to leave NO `.git/worktrees/` admin state
    // behind, so this is normally a no-op. A THIRD kind of failure this
    // module cannot rehearse on demand — `runProcess`'s own timeout or
    // signal killing `git worktree add` after it has started writing that
    // admin state but before it reports success — could leave a stale
    // entry pointing at a directory `safeRmDir` just deleted out from under
    // it. Pruning unconditionally here costs nothing on the common path
    // (prune against nothing to prune is a fast no-op) and closes that gap.
    await runProcess({
      command: 'git',
      args: ['-C', opts.projectPath, 'worktree', 'prune'],
      cwd: opts.projectPath,
      timeoutMs: opts.timeoutMs,
    });
    return { ok: false, reason: describeFailure(add, 'git worktree add') };
  }

  // The path this module hands back — and later removes by — is sourced
  // from git itself, NOT reused verbatim from `dir` above, because the two
  // are not reliably the same string. Confirmed on this Windows host: `dir`
  // came back as a short (8.3) path segment
  // (`C:\Users\ADMINI~1\AppData\Local\Temp\...`), while `git worktree list`
  // reports the SAME directory as `C:/Users/Administrator/AppData/Local/
  // Temp/...` — long form, forward slashes. `git worktree list --porcelain`
  // would not contain `dir`'s own string, and neither would a `git worktree
  // remove <dir>` argument reliably be treated as identical text by a
  // caller comparing strings. Asking git for the path it actually
  // registered sidesteps reproducing ITS normalisation rules by
  // construction, on every platform at once — including whatever a
  // different platform's equivalent (e.g. a macOS `/tmp` -> `/private/tmp`
  // symlink) would otherwise additionally require guessing at.
  const canonicalPath =
    (await resolveRegisteredPath(opts.projectPath, opts.branch, opts.timeoutMs)) ?? dir;

  return {
    ok: true,
    worktree: makeWorktree(opts.projectPath, canonicalPath, opts.branch, opts.timeoutMs),
  };
}

function makeWorktree(
  projectPath: string,
  path: string,
  branch: string,
  timeoutMs: number | undefined,
): Worktree {
  // A shared IN-FLIGHT PROMISE, not a boolean flag set before the first
  // `await` — `appRunner.ts`'s `makeStop` documents exactly why the boolean
  // shape is wrong: a second call that OVERLAPS the first sees the flag
  // already set and resolves immediately, while the real teardown is still
  // running underneath it. `remove()` is only contractually promised to be
  // safe called twice SEQUENTIALLY, but this project has already paid once
  // to learn the cheap fix, so it is applied here too rather than waiting
  // for a second incident to justify it.
  let removePromise: Promise<{ removed: boolean; warning: string | null }> | null = null;
  return {
    path,
    branch,
    remove: () => {
      removePromise ??= removeWorktree(projectPath, path, timeoutMs);
      return removePromise;
    },
  };
}

async function removeWorktree(
  projectPath: string,
  path: string,
  timeoutMs: number | undefined,
): Promise<{ removed: boolean; warning: string | null }> {
  const removeResult = await runProcess({
    command: 'git',
    args: ['-C', projectPath, 'worktree', 'remove', '--force', path],
    cwd: projectPath,
    timeoutMs,
  });

  // Prune unconditionally, whether `remove` above just succeeded, failed
  // because there was nothing left to remove (a second, idempotent call —
  // git itself refuses to operate on a path it no longer has registered),
  // or failed for some other reason. `prune` clears stale
  // `.git/worktrees/<name>` admin state regardless, and is a no-op when
  // there is nothing to prune.
  await runProcess({
    command: 'git',
    args: ['-C', projectPath, 'worktree', 'prune'],
    cwd: projectPath,
    timeoutMs,
  });

  // Observing the world, not `remove`'s own exit code: idempotency (a
  // second call, where the `remove` above necessarily fails because there
  // is nothing left to remove) and the half-applied-fix case (a dirty
  // worktree, which `--force` clears in one pass — verified directly:
  // modified tracked files AND untracked files are both gone after a single
  // `--force` call) both hinge on whether the directory is ACTUALLY gone
  // afterwards, not on whether this particular call's own commands reported
  // success.
  if (!existsSync(path)) {
    return { removed: true, warning: null };
  }
  const detail =
    removeResult.outcome !== 'completed'
      ? `: ${describeFailure(removeResult, 'git worktree remove')}`
      : '';
  return {
    removed: false,
    warning: `'${path}' still exists after 'git worktree remove --force' and 'git worktree prune'${detail}`,
  };
}

interface WorktreeListEntry {
  path: string;
  branch: string | null;
}

/** The path git itself registered for `branch`, or null if it could not be
 *  determined (the `list` call itself failed, or — defensively, should
 *  never happen right after a successful `add` — no entry matched). */
async function resolveRegisteredPath(
  projectPath: string,
  branch: string,
  timeoutMs: number | undefined,
): Promise<string | null> {
  const list = await runProcess({
    command: 'git',
    args: ['-C', projectPath, 'worktree', 'list', '--porcelain'],
    cwd: projectPath,
    timeoutMs,
  });
  if (list.outcome !== 'completed') return null;
  for (const entry of parseWorktreeList(list.stdout)) {
    if (entry.branch === branch) return entry.path;
  }
  return null;
}

/**
 * `git worktree list --porcelain`: one block per worktree, blank-line
 * separated, each line a `key value` pair (`worktree <path>`,
 * `branch refs/heads/<name>`, plus others this module does not need).
 * Parsed structurally, line by line — never via a RegExp built from
 * `branch`'s own text, which is not literal-safe (branch names routinely
 * carry `.`, `/`, `+`, all regex metacharacters).
 */
function parseWorktreeList(porcelain: string): WorktreeListEntry[] {
  const entries: WorktreeListEntry[] = [];
  let path: string | null = null;
  let branch: string | null = null;
  const flush = (): void => {
    if (path !== null) entries.push({ path, branch });
    path = null;
    branch = null;
  };
  for (const line of porcelain.split('\n')) {
    if (line === '') {
      flush();
      continue;
    }
    if (line.startsWith('worktree ')) {
      path = line.slice('worktree '.length);
    } else if (line.startsWith('branch ')) {
      const ref = line.slice('branch '.length);
      branch = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
    }
  }
  flush();
  return entries;
}

/**
 * `git worktree add` writes progress ahead of a real failure on the SAME
 * stream: a branch-collision failure's stderr is two lines, "Preparing
 * worktree (new branch '<name>')" THEN "fatal: a branch named '<name>'
 * already exists" — confirmed directly. Taking the first non-empty line
 * unconditionally (this function's first version) returned the progress
 * line, not the reason, on exactly that path. `git`'s own convention marks
 * the actual failure with a `fatal:`/`error:` prefix, so that line is
 * preferred when one exists; only when none does (a single-line message,
 * like the "not a git repository" failure, or a completely different
 * command) does this fall back to the first non-empty line.
 */
function describeFailure(result: ProcessRunResult, label: string): string {
  return (
    preferredErrorLine(result.stderr) ??
    firstNonEmptyLine(result.stderr) ??
    firstNonEmptyLine(result.stdout) ??
    `${label}: ${result.outcome}${result.exitCode !== null ? ` (exit ${result.exitCode})` : ''}`
  );
}

function preferredErrorLine(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('fatal:') || trimmed.startsWith('error:')) return trimmed;
  }
  return null;
}

function firstNonEmptyLine(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

function safeRmDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort — nothing more to do if this fails too */
  }
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
