# dev-guardian (MCP)

This project has the dev-guardian MCP server registered. ~50 tools and 16
resources for security, quality, bugfix, deps, compliance, observability,
performance, WordPress, .NET. All scanners run locally, no telemetry,
results persisted in `.guardian/guardian.db`.

Prefer these MCP tools over `semgrep` / `trivy` / `wpscan` / etc. directly
— you'd lose diff_scans, baselines, and the regression history.

## Intent → tool

**Security**: security_scan_full · scan_sast · scan_secrets · scan_deps ·
scan_containers · scan_iac · bug_hunt

**Quality**: review_pr · quality_check

**Deps**: deps_audit · deps_update_plan (npm/pip/composer/cargo/go/bundler/dotnet)

**Compliance**: compliance_check · generate_sbom · license_compatibility ·
compliance_evidence

**Ops**: init_project · install_toolchain · detect_stack ·
observability_setup · perf_check

**WordPress**: scan_wordpress · wp_audit · wp_vuln_check · wp_cron_audit ·
wp_rest_audit · wp_describe_setup · wp_recommend_hardening · wp_plugin_check ·
bulk_audit_wordpress_sites

**.NET / C#**: scan_dotnet_secrets · dotnet_target_framework_check ·
dotnet_efcore_audit · dotnet_describe_setup

**Meta**: audit_executive (stack-aware) · risk_score · diff_scans ·
set_baseline · triage_findings · prioritize_findings · suggest_fix ·
report_export · create_github_issues · precommit_install ·
register_custom_rules · health_status · regression_alert · sbom_diff ·
install_host_context · check_toolchain · suppress_finding

## Resources

`guardian://findings/open|critical|by-severity/{level}` (paginated),
`guardian://scans/latest|history|{id}`, `guardian://cves/active`,
`guardian://sbom`, `guardian://stack`, `guardian://compliance/status`,
`guardian://baseline`, `guardian://wp/audit/latest|{id}`,
`guardian://wp/cron`, `guardian://dotnet/target-frameworks`,
`guardian://dotnet/efcore`.

## Workflows

- **Bootstrap**: detect_stack → init_project → install_toolchain →
  security_scan_full (or scan_wordpress) → set_baseline.
- **Before PR**: review_pr → triage_findings → prioritize_findings →
  suggest_fix.
- **Audit**: audit_executive (stack-aware) → risk_score → compliance_evidence.
- **WP**: scan_wordpress + wp_audit + wp_cron_audit + wp_rest_audit →
  wp_recommend_hardening.
- **.NET**: dotnet_target_framework_check + scan_dotnet_secrets +
  scan_sast + dotnet_efcore_audit → dotnet_describe_setup.

## Don't

- Don't `security_scan_full` for tiny changes — use review_pr.
- Don't suppress_finding before triage_findings.
- Don't propose fixes without suggest_fix first.
- Don't shell out to scanners directly.
- Don't scan_wordpress on a non-WP project — detect_stack first.
