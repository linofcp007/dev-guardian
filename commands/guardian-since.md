---
description: What changed since a tag, commit, or date. Desde a última release. Desde el último release.
---

Run a Guardian pass scoped to **everything that changed since a reference point** — typically the last release tag, a commit SHA, or a calendar date. Useful for retrospective reviews and release notes.

The skill should:

1. Resolve the reference from `$ARGUMENTS`: tag (`v1.2.3`), SHA (`abc1234`), or relative date (`"2 weeks ago"`, `"last monday"`).
2. Default reference = most recent tag (`git describe --tags --abbrev=0`).
3. Diff the file tree and dependency lockfiles between the reference and `HEAD`.
4. Run `scan_sast`, `scan_secrets`, `sbom_diff` on the delta.
5. Use `diff_scans` to compare against the scan stored at that reference point if one exists in `.guardian/guardian.db`.

Output groups findings as **new since reference**, **resolved since reference**, **still open**. Ideal input for release notes or a sprint retrospective.

Reference (tag / SHA / date — defaults to last tag): $ARGUMENTS
