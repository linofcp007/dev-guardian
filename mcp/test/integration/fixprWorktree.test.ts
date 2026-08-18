/**
 * Integration tests for `createWorktree` (design doc
 * `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md` §3) against a
 * REAL throwaway git repository in the system temp directory — a mock proves
 * nothing about `git worktree`'s actual behaviour.
 *
 * The first seven tests are the brief's own, verbatim. The final `describe`
 * block adds coverage the brief asked for but did not spell out as a test:
 * concurrent (not just sequential) double-removal, and a check that no
 * `guardian-fixpr-wt-*` directory survives a create+remove cycle — this repo
 * has already shipped one test suite that quietly grew hundreds of temp
 * directories nobody noticed (see commit 821b7cd), so this file audits its
 * own footprint rather than assuming its calls to `remove()` were enough.
 */

import { describe, expect, it, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWorktree, WORKTREE_DIR_PREFIX } from '../../src/fixpr/worktree.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../helpers/tempDir.js';

/**
 * ---- The flake, its actual cause, and why this sandbox fixes it ---------
 *
 * This file's `afterAll` (bottom) explains at length why it checks exact
 * paths instead of sweeping the OS temp directory for `WORKTREE_DIR_PREFIX`:
 * the prefix is `worktree.ts`'s own constant, `createFixPr.test.ts` drives
 * real `createWorktree` calls using it and holds one open for up to ~20s, and
 * vitest runs test FILES concurrently.
 *
 * That reasoning was correct and was never applied to the two IN-TEST sweeps
 * — `tempDirsWithPrefix(WORKTREE_DIR_PREFIX)` taken before and after a call
 * and compared with `toEqual`. A sibling creating or removing its own
 * worktree between those two snapshots changes the set and fails the
 * assertion on code that did nothing wrong. That is the flake: seven
 * misfires under full-suite parallelism, never one in isolation, and the
 * `rmDir` retry hardening added in 1.7.2 could not have helped — nothing here
 * was failing to delete, the set was being changed by another process.
 *
 * `createWorktree` builds its directory with `mkdtempSync(join(tmpdir(), …))`
 * and `os.tmpdir()` re-reads TMPDIR/TEMP/TMP on every call, so pointing those
 * at a per-file sandbox confines BOTH the worktrees this file creates and the
 * sweeps that look for them to a directory no sibling can reach. Vitest 2.x
 * runs each test file in its own forked process, so the mutation cannot leak
 * sideways; it is restored at the end of `afterAll` regardless.
 *
 * The sandbox itself is created BEFORE the redirect, so it lives in the real
 * temp directory and `cleanupTempDirs` can remove it afterwards.
 */
const TMP_VARS = ['TMPDIR', 'TEMP', 'TMP'] as const;
const savedTmpVars = new Map<string, string | undefined>();

beforeAll(() => {
  const sandbox = makeTempDir('fixpr-tmproot-');
  for (const name of TMP_VARS) {
    savedTmpVars.set(name, process.env[name]);
    process.env[name] = sandbox;
  }
});

function restoreTmpVars(): void {
  for (const name of TMP_VARS) {
    const previous = savedTmpVars.get(name);
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
}

let repo: string;

/**
 * Every `guardian-fixpr-wt-*` / `fixpr-notrepo-*` path THIS FILE'S OWN tests
 * create, so the final `afterAll` below can check precisely those rather
 * than sweeping the whole OS temp directory for the prefix. The prefix
 * itself is not unique to this file: `createFixPr.test.ts` (Task 7) drives
 * real `createWorktree` calls of its own — using this exact same
 * `WORKTREE_DIR_PREFIX`, since it is `worktree.ts`'s own constant, not
 * something either test file controls — and holds one open for up to ~20s
 * at a time, far longer than this whole file typically takes to run.
 * Vitest runs test FILES concurrently by default, so a global "nothing with
 * this prefix exists anywhere" sweep at the end of THIS file can catch that
 * sibling's directory mid-use — legitimate, not leaked, just not this
 * file's to judge. Tracking exactly what this file itself created keeps the
 * check just as independent of `.remove()`'s own return value (still a raw
 * filesystem read, still not trusting the code under test to grade itself)
 * while making it immune to what a concurrently-running sibling is doing
 * with the same shared prefix.
 */
const ownWorktreePaths: string[] = [];
const ownNotRepoPaths: string[] = [];

function git(...args: string[]) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
}

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'fixpr-repo-'));
  execFileSync('git', ['init', '-q', '-b', 'main', repo]);
  execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
  execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
  // Windows-only wrinkle, not in the brief's own snippet: Git for Windows
  // commonly defaults `core.autocrlf` to true, so committing an LF-only
  // fixture file prints "LF will be replaced by CRLF" to stderr on every
  // `git add`/`git commit` below — `execFileSync` inherits stderr by
  // default, so it would otherwise leak into the test run's own output.
  // Pinned false so the fixture repo behaves identically on every platform
  // and the test output stays pristine.
  execFileSync('git', ['-C', repo, 'config', 'core.autocrlf', 'false']);
  writeFileSync(join(repo, 'a.txt'), 'one\n');
  git('add', '.');
  git('commit', '-q', '-m', 'first');
});

afterEach(() => { rmDir(repo); });

describe('createWorktree', () => {
  it('creates a worktree on a new branch from committed HEAD', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    expect(existsSync(join(r.worktree.path, 'a.txt'))).toBe(true);
    expect(git('worktree', 'list')).toContain(r.worktree.path);
    await r.worktree.remove();
  });

  it('leaves the user\'s uncommitted work untouched and out of the worktree', async () => {
    // The whole point of branching from HEAD rather than the working tree.
    writeFileSync(join(repo, 'a.txt'), 'dirty\n');
    writeFileSync(join(repo, 'untracked.txt'), 'mine\n');
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    expect(existsSync(join(r.worktree.path, 'untracked.txt'))).toBe(false);
    // and the user's tree is unchanged
    expect(git('status', '--porcelain')).toContain('a.txt');
    await r.worktree.remove();
  });

  it('removes the worktree and deregisters it', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    const p = r.worktree.path;
    const out = await r.worktree.remove();
    expect(out.removed).toBe(true);
    expect(existsSync(p)).toBe(false);
    // Observing the world, not the finally block.
    expect(git('worktree', 'list')).not.toContain(p);
  });

  it('removes a worktree that has uncommitted changes in it', async () => {
    // `git worktree remove` refuses a dirty worktree without --force. A fix
    // that failed halfway leaves exactly that, and it must still be removable.
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    writeFileSync(join(r.worktree.path, 'a.txt'), 'changed by a half-applied fix\n');
    const out = await r.worktree.remove();
    expect(out.removed).toBe(true);
    expect(git('worktree', 'list')).not.toContain(r.worktree.path);
  });

  it('is idempotent — a second remove() does not throw or report failure', async () => {
    // It is called from a finally and may already have run on the error path.
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    await r.worktree.remove();
    await expect(r.worktree.remove()).resolves.toEqual(
      expect.objectContaining({ removed: true }),
    );
  });

  it('refuses cleanly when the path is not a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    ownNotRepoPaths.push(notRepo);
    const r = await createWorktree({ projectPath: notRepo, branch: 'x' });
    expect(r.ok).toBe(false);
    rmDir(notRepo);
  });

  it('refuses when the branch already exists, rather than reusing it', async () => {
    // Reusing a branch would silently build on someone else's commits.
    git('branch', 'dev-guardian/fix-npm-abc');
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/exists/i);
  });
});

describe('createWorktree — additional coverage beyond the brief', () => {
  it('a concurrent (overlapping, not sequential) double remove() settles both calls to removed:true', async () => {
    // The brief's own idempotency test calls remove() twice SEQUENTIALLY.
    // worktree.ts additionally caches an in-flight promise (mirroring
    // mcp/src/ci/appRunner.ts's `makeStop`, which fixed a real bug there: a
    // boolean "already removing" flag set before an await let an
    // OVERLAPPING call resolve early, while the real teardown was still in
    // flight) — cheap, and avoids redundant `git` spawns under a genuine
    // overlap. Disclosed honestly, not asserted: mutation-tested by
    // deleting that cache and re-running this exact test five times, which
    // stayed green throughout, because — unlike appRunner's original bug —
    // `removeWorktree` always re-observes `existsSync` before answering, on
    // EVERY call, cached or not, so there is no "trust a flag, skip the
    // check" path here for this test to catch. What this test does verify:
    // two truly overlapping `remove()` calls neither throw nor reject, and
    // both settle to the correct, actually-true final state.
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-concurrent' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    ownWorktreePaths.push(r.worktree.path);
    const p = r.worktree.path;
    const [a, b] = await Promise.all([r.worktree.remove(), r.worktree.remove()]);
    expect(a).toEqual({ removed: true, warning: null });
    expect(b).toEqual({ removed: true, warning: null });
    expect(existsSync(p)).toBe(false);
  });

  it('leaves no guardian-fixpr-wt- directory behind after a create+remove cycle', async () => {
    // Guards specifically against the canonical-path lookup (worktree.ts
    // resolves its OWN mkdtemp path against `git worktree list --porcelain`
    // rather than trusting the string it handed to `worktree add` verbatim
    // — see that module's comment on why) latching onto the WRONG entry:
    // if it did, `remove()` would operate on some other worktree and the
    // real directory this test created would leak, silently, forever.
    const before = tempDirsWithPrefix(WORKTREE_DIR_PREFIX);
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-straycheck' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    await r.worktree.remove();
    const after = tempDirsWithPrefix(WORKTREE_DIR_PREFIX);
    expect(after).toEqual(before);
  });

  it('refuses cleanly and leaves no worktree directory behind when the branch already exists', async () => {
    // The brief's own "branch already exists" test checks `r.ok`. This
    // checks the OTHER half of that failure path: the mkdtemp'd directory
    // `createWorktree` made for the (failed) worktree target must not
    // survive the refusal.
    git('branch', 'dev-guardian/fix-npm-existing');
    const before = tempDirsWithPrefix(WORKTREE_DIR_PREFIX);
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-existing' });
    expect(r.ok).toBe(false);
    const after = tempDirsWithPrefix(WORKTREE_DIR_PREFIX);
    expect(after).toEqual(before);
  });
});

afterAll(() => {
  // Final safety net across the whole file: whatever ran above, none of
  // THIS FILE's own worktree or non-repo fixture directories is still on
  // disk. Checked against the exact paths this file's own tests created
  // (see `ownWorktreePaths` / `ownNotRepoPaths` above) rather than a sweep
  // for every directory bearing the shared `WORKTREE_DIR_PREFIX` /
  // `fixpr-notrepo-` prefix anywhere in the OS temp directory: `createWorktree`
  // is not private to this file (`createFixPr.test.ts` drives real calls of
  // its own, holding a directory under this same prefix open for up to ~20s
  // at a time), and vitest runs test files concurrently by default, so a
  // whole-temp-dir sweep can catch a sibling file's legitimate, still-in-use
  // directory and misreport it as a leak. `fixpr-repo-` has no such sibling
  // — only this file's own `beforeEach` ever creates one — so it is still
  // safe to sweep for directly.
  expect(ownWorktreePaths.filter(existsSync)).toEqual([]);
  expect(ownNotRepoPaths.filter(existsSync)).toEqual([]);
  expect(tempDirsWithPrefix('fixpr-repo-')).toEqual([]);

  // Last, so every assertion above still reads the sandbox.
  restoreTmpVars();
  cleanupTempDirs();
});

function tempDirsWithPrefix(prefix: string): string[] {
  return readdirSync(tmpdir())
    .filter((name) => name.startsWith(prefix))
    .sort();
}
