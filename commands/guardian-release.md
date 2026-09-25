---
description: Release gates — predeploy (before a production deploy) and prerelease (before tagging a release). Antes do deploy ou da release. Antes del despliegue o del release.
argument-hint: "<predeploy | prerelease> [deploy target or version]"
---

A go / no-go gate. The first word of the arguments picks the gate; the rest is the target (environment, URL or version). With no mode, ask which one.

End every run with a verdict — ✅ go / ⚠️ go with caveats (listed) / 🔴 do not — and always list the blocking findings behind a 🔴.

Arguments: $ARGUMENTS

## `predeploy` — before a production deploy

1. `audit_executive { project_path: "<project>" }` — security (`security_scan_full`), quality, dependencies (`deps_audit`) and compliance in one run, with the delta against the previous audit. Coverage `partial` is a caveat to list, never a pass.
2. **Environment hygiene**: `git ls-files` must list no `.env*` file other than examples; no production credentials in the tree (the secrets pass of step 1 covers history and uncommitted files); no `localhost` / `127.0.0.1` in production configuration.
3. **Personal data**: when the app handles it, `compliance_evidence { framework: "gdpr" }` and the `guardian-compliance` skill's checklist (privacy policy, cookie consent, retention).
4. **SBOM** for the artefact being deployed: `generate_sbom { project_path: "<project>", format: "cyclonedx-json" }`.
5. **CI** of the current branch is green: `gh run list --branch <branch> --limit 5` or `gh pr checks` when the GitHub CLI is available; otherwise ask.

## `prerelease` — before tagging a release

1. **Dependencies and licences since the last release**: `generate_sbom { project_path: "<project>" }`, then `sbom_diff { project_path: "<project>" }`, which compares the two latest SBOM scans. That is only a release diff when the previous SBOM was taken at the last release — if there is none, say so; this one becomes the reference for the next release.
2. `compliance_check { project_path: "<project>" }`, then `license_compatibility { project_path: "<project>" }` — flag any copyleft dependency that is new since the last release. `undetermined` is not compatible; say which ones.
3. `audit_executive { project_path: "<project>" }` on the release branch.
4. **Release notes** from `git log <last tag>..HEAD`, grouped as in `/guardian-report changelog`.
5. **Version bump** in `package.json` / `pyproject.toml` / `*.csproj` / `composer.json` matches the changes: major for breaking, minor for features, patch for fixes.
6. **CI** green on the release candidate.

Output the proposed release notes with the verdict.

Respond in the user's language (EN/PT/ES).
