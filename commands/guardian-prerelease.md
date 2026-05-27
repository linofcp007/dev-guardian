---
description: Release readiness — changelog, SBOM diff, license check, version bump. Antes da release. Antes del release.
---

Invoke the release-readiness checklist. Run this **before tagging a new release**.

Steps:

1. Diff dependencies and licenses against the previous release tag using `sbom_diff` + `license_compatibility`. Flag any new copyleft dependency that was not present before.
2. Run `audit_executive` against the release branch.
3. Generate a structured changelog from commits since the last tag, grouped by `feat:` / `fix:` / `chore:` / `breaking:`.
4. Verify the version bump in `package.json` / `pyproject.toml` / `*.csproj` / `composer.json` matches the diff (major for breaking, minor for new features, patch for fixes).
5. Confirm the CI on the tag candidate branch is green.

End with the proposed release notes (markdown) and the verdict: ✅ tag and release / ⚠️ release with notes / 🔴 do not release yet (list blockers).

Release name or version hint (e.g. "v1.4.0", "next-minor"): $ARGUMENTS
