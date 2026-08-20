# Agent rules — dev-guardian

This repository has the **dev-guardian MCP server** registered. It exposes
54 tools and 18 resources for security, quality, bugfix, deps,
compliance, observability, performance, plus first-class WordPress and
.NET (C#/F#) support. All scanners run locally, no telemetry, results
persisted in `.guardian/guardian.db`.

When working in this repo, **prefer invoking dev-guardian MCP tools over
running scanners directly via shell**. The MCP layer adds: regression
diffing, baselines, suppressions, severity-weighted risk scoring, and a
cache that avoids re-running unchanged scans.

## Intent → MCP tool

**Security**
- "is this safe?" / "audit security" → `security_scan_full`
- "secrets leaked?" → `scan_secrets`
- "vulnerable deps?" / "CVEs?" → `scan_deps` or `deps_audit`
- "Dockerfile / container" → `scan_containers`
- "Terraform / K8s / IaC" → `scan_iac`
- "deep bug hunt" → `bug_hunt`
- "is this AI skill / MCP server / agent safe to install?" → `scan_skill`
  (directory, file, .zip or git/HTTP(S) URL; prompt injection, exfiltration,
  excessive agency, tool poisoning, MCP least-privilege, plus OSV CVEs on
  declared deps - returns 0-100 risk and SAFE / REVIEW / CAUTION /
  DO_NOT_INSTALL. Run it BEFORE installing, not after)
- "what routes/endpoints does this app expose?" → `map_attack_surface`
- "active DAST / pen-test the running app" → `map_attack_surface` first for the
  route inventory, then `scan_dast` against the already-running app (loopback
  only unless `authorized_target: true` is set; a clean result is not evidence
  of injection safety — see its tool description)
- "is this finding actually reachable / exploitable?" → `map_attack_surface`
  (if no recent snapshot) then `validate_finding` — reachable / unreachable /
  unknown per finding with evidence, report-only, never suppresses or touches
  severity; `unreachable` is never available for Ruby, Java, C#, or PHP. It
  IS produced — and can be wrong — for a file reached only by a CLI/cron/queue
  entry point, or an unresolvable dynamic import — see its tool description
  for the full limits

**Quality**
- "review before PR" → `review_pr`
- "code quality / duplication" → `quality_check`

**Deps**
- "upgrade plan" → `deps_update_plan` (npm/pip/composer/cargo/go/bundler/dotnet)
- "audit deps" → `deps_audit`

**Compliance**
- "GDPR / SOC2 / ISO27001" → `compliance_check` + `compliance_evidence`
- "SBOM" → `generate_sbom`
- "license compatibility" → `license_compatibility`

**Ops**
- "bootstrap project" → `init_project`
- "my dev-guardian configs are out of date" / a scan warned about config drift →
  `init_project` with `refresh=true` (`apply=false` first — it reports what would
  change; `apply=true` never overwrites a config the user edited)
- "install scanners" → `install_toolchain`
- "which scanners are installed?" → `check_toolchain`
- "detect stack" → `detect_stack`
- "logging / metrics" → `observability_setup`
- "performance" → `perf_check`

**WordPress**
- "scan WP code" → `scan_wordpress`
- "audit live WP install" → `wp_audit`
- "any WP CVEs?" → `wp_vuln_check`
- "WP cron / backdoor check" → `wp_cron_audit`
- "WP REST API exposed?" → `wp_rest_audit`
- "WP posture overview" → `wp_describe_setup`
- "hardening checklist" → `wp_recommend_hardening`
- "check one plugin" → `wp_plugin_check`
- "audit N WP sites" → `bulk_audit_wordpress_sites`

**.NET / C#**
- ".NET secrets in configs?" → `scan_dotnet_secrets`
- "EOL frameworks?" → `dotnet_target_framework_check`
- "EF Core migration safety" → `dotnet_efcore_audit`
- ".NET posture overview" → `dotnet_describe_setup`

**Meta**
- "full audit" → `audit_executive` (stack-aware: includes WP / .NET tools)
- "risk score" → `risk_score`
- "what's new since last scan?" → `diff_scans`
- "set baseline" → `set_baseline`
- "noise reduction" → `triage_findings`
- "prioritise" → `prioritize_findings`
- "how do I fix X?" → `suggest_fix` (returns context; you write the patch)
- "apply the fixes a scanner already has and open a PR" → `create_fix_pr` —
  applies `deps_update_plan`'s pinned version bumps and Semgrep `--autofix`
  (only those two — it is not a patch author) inside an isolated git
  worktree, proves each with a scan differential and a test run, and opens
  one pull request per ecosystem/scanner via the local `gh` CLI. **`apply`
  defaults to `false`**: a dry run still creates the worktree, applies the
  fix and runs both differentials, but leaves nothing behind — not a
  branch, not a commit, not a worktree — and opens no PR until `apply: true`.
  Its own verification re-scan never becomes the project's latest scan
  either, so previewing can't repoint `guardian://findings/open` or
  `risk_score`
- "export report" → `report_export`
- "create GitHub issues" → `create_github_issues` (local `gh` CLI)
- "pre-commit hooks" → `precommit_install`
- "register custom Semgrep rules" → `register_custom_rules`
- "health check" → `health_status`
- "regression check" → `regression_alert`
- "SBOM diff" → `sbom_diff`
- "project health at a glance?" → `node cli/dev-guardian.mjs status` (CLI,
  one-screen summary) or `dashboard` (CLI, same data as a self-contained HTML
  page) — both read-only, report rather than gate
- "set up another AI host" → run `node cli/dev-guardian.mjs mcp-config <host>` (CLI)

## Resources

- Findings: `guardian://findings/open`, `guardian://findings/critical`,
  `guardian://findings/by-severity/{level}` (paginated via `?page=N&page_size=M`)
- Scans: `guardian://scans/latest`, `guardian://scans/history`,
  `guardian://scans/{scan_id}`
- Other: `guardian://cves/active`, `guardian://sbom`, `guardian://stack`,
  `guardian://compliance/status`, `guardian://baseline`
- WordPress: `guardian://wp/audit/latest`, `guardian://wp/audit/{id}`,
  `guardian://wp/cron`
- .NET: `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`
- Attack surface: `guardian://surface/latest`, `guardian://surface/{id}`

## Typical sequences

- **Bootstrap**: `detect_stack` → `init_project` → `install_toolchain` →
  `security_scan_full` (or `scan_wordpress`) → `set_baseline`
- **Before PR**: `review_pr` → `triage_findings` → `prioritize_findings` →
  `suggest_fix`
- **Audit**: `audit_executive` (stack-aware) → `risk_score` →
  `compliance_evidence framework=…`
- **WP-specific**: `scan_wordpress` + `wp_audit` + `wp_cron_audit` +
  `wp_rest_audit` → `wp_recommend_hardening`
- **.NET-specific**: `dotnet_target_framework_check` + `scan_dotnet_secrets`
  + `scan_sast` + `dotnet_efcore_audit` → `dotnet_describe_setup`
- **Active DAST**: `map_attack_surface` → `scan_dast` (the target app must
  already be running; `scan_dast` never starts, builds or stops it)
- **Reachability**: `map_attack_surface` → `validate_finding` — requires a
  prior surface snapshot; validates the open findings from whichever scan
  completed most recently, so run it right after a SAST scan, not right after
  `scan_dast`

## CI (headless, no MCP connection)

For a pipeline, not a conversation: `node cli/dev-guardian.mjs scan` runs the same
scan pipeline as the MCP tools, gated against a committed `.guardian/baseline.json`;
`dev-guardian baseline update` is the only command that writes it. Exit codes: `0`
pass, `1` gate failed, `2` incomplete scan (a scanner didn't run — never read as a
pass), `3` usage error. Distribution is `git clone --depth 1` at a pinned tag (not
`npx`) plus `npm ci` in `mcp/` — see the README's "Run scans in CI" section for a
copy-pasteable GitHub Actions job. `--start-command` (starts the app for the DAST
pass) is accepted **only on argv, never from `.guardian/ci.json`** — a repository
file declaring it is refused outright, because a fork's pull request could otherwise
run arbitrary code on the runner. A CI run leaves `.guardian/reports/` in the working
tree (only the SQLite database is ephemeral) — add `.guardian/` to `.gitignore` by
hand; the MCP server does this automatically every time it starts against a
project, but the CLI never starts that server.

## Local dashboard (offline, read-only)

For a developer at their own laptop, not a CI artifact and not a client
deliverable: `node cli/dev-guardian.mjs status` prints a one-screen summary
(risk score and band, open findings/CVEs by severity, both deltas, up to 3
hotspots ranked by finding count, missing-scanner consequences, active
suppressions); `dev-guardian dashboard` writes the same snapshot as a
self-contained `.guardian/dashboard.html` (no CDN, no network call of any
kind), opened automatically only when stdout is a TTY — `--no-open`
suppresses that, `--out <path>` relocates the file. Neither runs a scan,
mutates the database, or opens a socket, and both always exit `0` once they
render — including over a project full of criticals, or one never scanned —
because they report; `scan` is what gates. `3` is the only other exit code,
on a usage error. The page is a **snapshot, not live**: it does not update
when a later scan runs, so regenerate it to see one. The window itself is
bounded too — the latest scan plus two deltas, no multi-week trend
(`/guardian-trend` still asks for history nothing here computes).

## Anti-patterns

- Don't run `security_scan_full` for tiny changes — `review_pr` is 10×+ faster.
- Don't `suppress_finding` before `triage_findings`.
- Don't synthesise fixes without `suggest_fix` first.
- Don't shell out to scanners directly when an MCP tool exists.
- Don't run `scan_wordpress` on a non-WP project — `detect_stack` first.
- Don't run `wp_audit` without WP-CLI — `install_toolchain tools=["wp-cli"]`.
- Don't run `scan_dast` before `map_attack_surface` — it refuses with
  `no_surface_snapshot` and has no route inventory to probe.
- Don't read a clean `scan_dast` result as "no injection vulnerabilities" —
  the own engine sends no injection payloads at all; that class is delegated
  to an opt-in nuclei pass whose default templates test the origin, not this
  project's specific routes.
- Don't treat `validate_finding`'s `unreachable` as proof nothing can call the
  code, or suppress a finding on the strength of it alone — it is a
  reachability signal from an over-approximating import graph, unavailable for
  four stacks and blind to dynamic imports.
- Don't expect `create_fix_pr` to fix a finding with no `fix_available` —
  gitleaks, bandit, jscpd, the DAST checks and the .NET tools never set it,
  and a Semgrep rule with no `fix:` field can't be autofixed either; only
  `deps_update_plan` bumps and Semgrep `--autofix` are in reach. And it
  won't open a PR unless you pass `apply: true` — the default run is a
  dry run that proves the fix and reports it, nothing more.
- Three more `create_fix_pr` limits worth knowing before you rely on it:
  maven and gradle bumps are out of reach (inherited from
  `deps_update_plan`'s own ecosystem gap); a second hit of the same rule
  landing in a file it already fixed is not seen as a NEW finding, because
  the "no new finding" check compares `(rule_id, file_path)` rather than
  fingerprint (a fingerprint moves whenever the fix shifts a line); and
  `fix_applied` never flips to `1` — it is a dead column on `findings`, and
  the opened pull request is the record instead.
