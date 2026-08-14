# Copilot instructions — dev-guardian

This project uses the **dev-guardian MCP server** — 53 tools and 18
resources for security, quality, bugfix, deps, compliance, observability,
performance, WordPress, and .NET. All scanners run locally; results
persist in `.guardian/guardian.db` for diffing and baselines.

When the user's request matches an intent below, invoke the corresponding
MCP tool rather than the underlying scanner directly.

## Intent → tool

**Security**: `security_scan_full`, `scan_sast`, `scan_secrets`,
`scan_deps`, `scan_containers`, `scan_iac`, `bug_hunt`.

**Quality**: `review_pr`, `quality_check`.

**Deps**: `deps_audit`, `deps_update_plan` (npm/pip/composer/cargo/go/
bundler/dotnet).

**Compliance**: `compliance_check`, `generate_sbom`,
`license_compatibility`, `compliance_evidence`.

**Ops**: `init_project`, `install_toolchain`, `detect_stack`,
`observability_setup`, `perf_check`.

**WordPress**: `scan_wordpress`, `wp_audit`, `wp_vuln_check`,
`wp_cron_audit`, `wp_rest_audit`, `wp_describe_setup`,
`wp_recommend_hardening`, `wp_plugin_check`, `bulk_audit_wordpress_sites`.

**.NET / C#**: `scan_dotnet_secrets`, `dotnet_target_framework_check`,
`dotnet_efcore_audit`, `dotnet_describe_setup`.

**Attack surface**: `map_attack_surface` (static route/env-var/port
inventory), then either `scan_dast` (active DAST against the app once it is
already running — loopback-only unless `authorized_target: true`; a clean
result is not evidence of injection safety) or `validate_finding`
(per-finding reachability verdict — reachable / unreachable / unknown,
report-only; `unreachable` unavailable for Ruby/Java/C#/PHP — it IS produced,
and can be wrong, for a CLI/cron/queue-only file or an unresolvable dynamic
import).

**Meta**: `audit_executive` (stack-aware — includes WP/.NET tools when
detected), `risk_score`, `diff_scans`, `set_baseline`, `triage_findings`,
`prioritize_findings`, `suggest_fix`, `report_export`,
`create_github_issues` (local `gh` CLI), `precommit_install`,
`register_custom_rules`, `health_status`, `regression_alert`,
`sbom_diff`, `check_toolchain`,
`suppress_finding`.

## Resources

- Findings: `guardian://findings/open` (paginated `?page=N&page_size=M`),
  `guardian://findings/critical`, `guardian://findings/by-severity/{level}`
- Scans: `guardian://scans/latest`, `guardian://scans/history`,
  `guardian://scans/{scan_id}`
- Other: `guardian://cves/active`, `guardian://sbom`, `guardian://stack`,
  `guardian://compliance/status`, `guardian://baseline`
- WordPress: `guardian://wp/audit/latest`, `guardian://wp/audit/{id}`,
  `guardian://wp/cron`
- .NET: `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`
- Attack surface: `guardian://surface/latest`, `guardian://surface/{id}`

## Workflows

**Bootstrap**: `detect_stack` → `init_project` → `install_toolchain` →
`security_scan_full` (or `scan_wordpress` for WP) → `set_baseline`.

**Before PR**: `review_pr` → `triage_findings` → `prioritize_findings` →
`suggest_fix`.

**Audit**: `audit_executive` (stack-aware) → `risk_score` →
`compliance_evidence`.

**WP**: `scan_wordpress` + `wp_audit` + `wp_cron_audit` + `wp_rest_audit`
→ `wp_recommend_hardening`.

**.NET**: `dotnet_target_framework_check` + `scan_dotnet_secrets` +
`scan_sast` + `dotnet_efcore_audit` → `dotnet_describe_setup`.

**Active DAST**: `map_attack_surface` → `scan_dast` (target app must
already be running; `scan_dast` never starts, builds or stops it).

**Reachability**: `map_attack_surface` → `validate_finding` (requires a
prior surface snapshot; validates whichever scan completed most recently —
run it right after a SAST scan, not right after `scan_dast`).

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

## Anti-patterns

- Don't run `security_scan_full` for tiny changes — use `review_pr`.
- Don't `suppress_finding` before `triage_findings`.
- Don't propose fixes without `suggest_fix` first (returns source context).
- Don't shell out to scanners — you lose diff_scans, baselines, persistence.
- Don't run `scan_wordpress` on a non-WP project — `detect_stack` first.
- Don't run `wp_audit` without WP-CLI — `install_toolchain tools=["wp-cli"]`.
- Don't run `scan_dast` before `map_attack_surface` — it refuses with
  `no_surface_snapshot` and has no route inventory to probe.
- Don't read a clean `scan_dast` result as "no injection vulnerabilities" —
  the own engine sends none; that class is delegated to an opt-in nuclei
  pass whose default templates test the origin, not this project's routes.
- Don't treat `validate_finding`'s `unreachable` as proof the code can never
  run, or suppress a finding on it alone — it's a reachability signal from an
  import graph, unavailable for Ruby/Java/C#/PHP and blind to dynamic imports.
