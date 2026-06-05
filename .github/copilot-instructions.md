# Copilot instructions — dev-guardian

This project uses the **dev-guardian MCP server** — ~50 tools and 16
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

## Anti-patterns

- Don't run `security_scan_full` for tiny changes — use `review_pr`.
- Don't `suppress_finding` before `triage_findings`.
- Don't propose fixes without `suggest_fix` first (returns source context).
- Don't shell out to scanners — you lose diff_scans, baselines, persistence.
- Don't run `scan_wordpress` on a non-WP project — `detect_stack` first.
- Don't run `wp_audit` without WP-CLI — `install_toolchain tools=["wp-cli"]`.
