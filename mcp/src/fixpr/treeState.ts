/**
 * `projectTreeState` — where a project sits in its repository, and which of
 * its files differ from HEAD. create_fix_pr applies and verifies every fix on
 * a checkout of HEAD, so a finding read from a file that differs from HEAD is
 * never a candidate (Task 11 fix round 1).
 *
 * `git status` runs with `--no-optional-locks` (Task 11 fix round 2): by
 * default it may take `index.lock` to refresh the index, which contends with
 * the user's own git or IDE working on the same repository at the same time.
 * A read has no business taking it.
 */

import { runProcess } from '../runners/processRunner.js';

export type TreeState = { ok: true; prefix: string; dirty: ReadonlySet<string> } | { ok: false; reason: string };

/**
 * The project's place in its repository (`git rev-parse --show-prefix`:
 * `''` at the root, `app/` for a subdirectory — the same subdirectory of any
 * worktree) and every path under it that differs from HEAD, repository-root
 * relative (`git status --porcelain -z` prints them that way from any
 * subdirectory — measured), untracked files and both sides of a rename
 * included. Fails — never answers "nothing changed" — when git cannot tell.
 */
export async function projectTreeState(projectPath: string, run: typeof runProcess = runProcess): Promise<TreeState> {
  const prefix = await run({
    command: 'git',
    args: ['--no-optional-locks', '-C', projectPath, 'rev-parse', '--show-prefix'],
    cwd: projectPath,
  });
  if (prefix.outcome !== 'completed') {
    return { ok: false, reason: `git rev-parse --show-prefix failed: ${prefix.stderr.trim()}` };
  }
  const status = await run({
    command: 'git',
    args: ['--no-optional-locks', '-C', projectPath, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--', '.'],
    cwd: projectPath,
  });
  if (status.outcome !== 'completed') {
    return { ok: false, reason: `git status failed — cannot tell which files have uncommitted changes: ${status.stderr.trim()}` };
  }
  const dirty = new Set<string>();
  const entries = status.stdout.split('\0');
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i] ?? '';
    if (entry.length < 4) continue;
    const xy = entry.slice(0, 2);
    dirty.add(entry.slice(3));
    // A rename or copy is followed by its source path.
    if (xy.includes('R') || xy.includes('C')) {
      const source = entries[i + 1];
      if (source !== undefined && source.length > 0) dirty.add(source);
      i += 1;
    }
  }
  return { ok: true, prefix: prefix.stdout.trim(), dirty };
}
