/**
 * Tiny helpers around `git status` used by the scan-tool factory to enforce
 * the `auto_fix` + `allow_dirty` contract from US-1 AC-4 (security tools)
 * and the "edge case: auto-fix conflicts with uncommitted changes" rule.
 *
 * Out of scope: anything that requires diffing — that belongs in the
 * `review_pr` tool, not here.
 */

import { execa } from 'execa';

export async function isWorkingTreeClean(projectPath: string): Promise<boolean> {
  try {
    const result = await execa('git', ['-C', projectPath, 'status', '--porcelain'], {
      reject: false,
      timeout: 10_000,
    });
    if (result.exitCode !== 0) return true; // not a git repo → treat as clean
    return result.stdout.trim().length === 0;
  } catch {
    // No git on PATH or sandbox blocked it — fail open; the dirtiness check
    // is a safety net, not a security boundary.
    return true;
  }
}

export async function isGitRepo(projectPath: string): Promise<boolean> {
  try {
    const result = await execa('git', ['-C', projectPath, 'rev-parse', '--is-inside-work-tree'], {
      reject: false,
      timeout: 5_000,
    });
    return result.exitCode === 0 && result.stdout.trim() === 'true';
  } catch {
    return false;
  }
}
