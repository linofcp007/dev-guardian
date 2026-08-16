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

import { describe, expect, it, beforeEach, afterEach, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWorktree, WORKTREE_DIR_PREFIX } from '../../src/fixpr/worktree.js';

let repo: string;

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

afterEach(() => { rmSync(repo, { recursive: true, force: true }); });

describe('createWorktree', () => {
  it('creates a worktree on a new branch from committed HEAD', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
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
    expect(existsSync(join(r.worktree.path, 'untracked.txt'))).toBe(false);
    // and the user's tree is unchanged
    expect(git('status', '--porcelain')).toContain('a.txt');
    await r.worktree.remove();
  });

  it('removes the worktree and deregisters it', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
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
    await r.worktree.remove();
    await expect(r.worktree.remove()).resolves.toEqual(
      expect.objectContaining({ removed: true }),
    );
  });

  it('refuses cleanly when the path is not a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const r = await createWorktree({ projectPath: notRepo, branch: 'x' });
    expect(r.ok).toBe(false);
    rmSync(notRepo, { recursive: true, force: true });
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
  // Final safety net across the whole file: whatever ran above, the OS temp
  // directory carries no trace of it left over — this module's own worktree
  // directories, or a repo/non-repo fixture a test forgot to clean up.
  expect(tempDirsWithPrefix(WORKTREE_DIR_PREFIX)).toEqual([]);
  expect(tempDirsWithPrefix('fixpr-repo-')).toEqual([]);
  expect(tempDirsWithPrefix('fixpr-notrepo-')).toEqual([]);
});

function tempDirsWithPrefix(prefix: string): string[] {
  return readdirSync(tmpdir())
    .filter((name) => name.startsWith(prefix))
    .sort();
}
