---
description: Auto-generate changelog grouped by feat/fix/security/breaking. Gera changelog. Genera changelog.
---

Generate a **changelog** from commits since a reference point (last tag by default). Different from `guardian-prerelease` (which is a gate) — this just produces the document.

The skill should:

1. Resolve the reference (`$ARGUMENTS` or last tag via `git describe --tags --abbrev=0`).
2. Pull commits via `git log <ref>..HEAD`.
3. Group by conventional-commit prefix:
   - 🚨 **Breaking changes** (`!:` or `BREAKING CHANGE`)
   - 🔒 **Security** (CVE-related, secrets remediation — cross-reference with `cves` and `findings` tables)
   - ✨ **Features** (`feat:`)
   - 🐛 **Fixes** (`fix:`)
   - 🛠️ **Internal** (`chore:`, `refactor:`, `test:`, `docs:`)
4. For commits without conventional prefixes, classify heuristically based on the diff (touched paths, added files).
5. Cross-link to PR numbers when present in commit messages.

Output format defaults to Keep-a-Changelog markdown. Offer to write to `CHANGELOG.md` (prepending) if the user wants it persisted.

Reference (tag / SHA / "since last release"): $ARGUMENTS
