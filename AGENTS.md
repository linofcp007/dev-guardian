# Agent rules — dev-guardian

This repository has the **dev-guardian MCP server** registered. It exposes
~50 tools and 16 resources for security, quality, bugfix, deps,
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
- "install scanners" → `install_toolchain`
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
- "export report" → `report_export`
- "create GitHub issues" → `create_github_issues` (local `gh` CLI)
- "pre-commit hooks" → `precommit_install`
- "register custom Semgrep rules" → `register_custom_rules`
- "health check" → `health_status`
- "regression check" → `regression_alert`
- "SBOM diff" → `sbom_diff`
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

## Anti-patterns

- Don't run `security_scan_full` for tiny changes — `review_pr` is 10×+ faster.
- Don't `suppress_finding` before `triage_findings`.
- Don't synthesise fixes without `suggest_fix` first.
- Don't shell out to scanners directly when an MCP tool exists.
- Don't run `scan_wordpress` on a non-WP project — `detect_stack` first.
- Don't run `wp_audit` without WP-CLI — `install_toolchain tools=["wp-cli"]`.
