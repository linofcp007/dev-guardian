---
description: Scan only what this branch changed vs. main. Diff de branch contra main. Diff de la rama vs main.
---

Run a Guardian pass scoped to the **diff between the current branch and `main`** (or the configured default branch). Mid-weight scan: heavier than `guardian-diff` (covers committed work), lighter than `guardian-review` (no senior-style review prose).

The skill should:
1. Detect the default branch (`main` / `master` / `trunk`) via `git symbolic-ref refs/remotes/origin/HEAD`.
2. Compute the file set with `git diff --name-only <default>...HEAD`.
3. If on the default branch already, say so and route to `guardian-scan` instead.
4. Run `scan_sast`, `scan_secrets`, dep-diff, and a focused `bug_hunt` pass on the changed files only.
5. Persist as a scan row so `diff_scans` against future runs picks it up.

Output: 🔴 / 🟡 / 🟢 counts + per-author breakdown when the branch has commits from multiple authors.

Alternative base branch (optional, e.g. "develop", "release/v2"): $ARGUMENTS
