---
description: Fast scan of the staged / uncommitted diff only. Scan rápido do diff. Escaneo rápido del diff.
---

Run a **fast, narrow** Guardian pass against only the files in the current `git diff` (staged + unstaged). Designed to finish in seconds and run from the editor between edits — not a full audit.

The skill should:
1. Compute the diff set: `git diff --name-only HEAD` plus `git diff --cached --name-only`.
2. If there is nothing, say so and exit cleanly.
3. Run `scan_sast` and `scan_secrets` restricted to that set.
4. Run a focused `bug_hunt` pass against the diff hunks (not whole files).
5. Output a one-screen summary: 🔴 / 🟡 / 🟢 / ℹ️ counts plus the top 5 most important findings.

When the user has more than ~50 changed files, suggest they probably want `guardian-review` instead.

Optional path filter or focus hint: $ARGUMENTS
