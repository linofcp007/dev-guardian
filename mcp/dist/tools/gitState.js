/**
 * Tiny helpers around `git status` used by the scan-tool factory to enforce
 * the `auto_fix` + `allow_dirty` contract from US-1 AC-4 (security tools)
 * and the "edge case: auto-fix conflicts with uncommitted changes" rule.
 *
 * **Tri-state, and only one state lets `auto_fix` through.** This used to be
 * a boolean that answered `true` ("clean") for a directory that is not a git
 * repository at all, for any git error (`fatal: detected dubious ownership`,
 * a `.git` file pointing at nothing) and for git missing from PATH. Every
 * one of those let `auto_fix` rewrite files git had never versioned — the
 * one case where a bad autofix cannot be undone. `clean` now means git ran,
 * succeeded and printed nothing; anything git could not vouch for is
 * `unknown`, and the factory refuses `auto_fix` on it unless the caller
 * passes `allow_dirty` knowingly.
 *
 * Out of scope: anything that requires diffing — that belongs in the
 * `review_pr` tool, not here.
 */
import { execa } from 'execa';
export async function workingTreeState(projectPath) {
    try {
        const result = await execa('git', ['-C', projectPath, 'status', '--porcelain'], {
            reject: false,
            timeout: 10_000,
        });
        if (result.exitCode !== 0) {
            const line = firstLine(result.stderr) ?? `git status exited ${String(result.exitCode)}`;
            return { state: 'unknown', reason: line };
        }
        const changed = result.stdout.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
        return changed === 0 ? { state: 'clean' } : { state: 'dirty', changed };
    }
    catch (e) {
        // No git on PATH, a timeout, or a sandbox that blocked the spawn: git
        // said nothing either way, which is not the same as "clean".
        return { state: 'unknown', reason: e instanceof Error ? e.message : String(e) };
    }
}
export async function isGitRepo(projectPath) {
    try {
        const result = await execa('git', ['-C', projectPath, 'rev-parse', '--is-inside-work-tree'], {
            reject: false,
            timeout: 5_000,
        });
        return result.exitCode === 0 && result.stdout.trim() === 'true';
    }
    catch {
        return false;
    }
}
function firstLine(text) {
    for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.length > 0)
            return trimmed;
    }
    return null;
}
//# sourceMappingURL=gitState.js.map