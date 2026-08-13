# dev-guardian — context for Gemini CLI

This repository has the **dev-guardian MCP server** registered (see
`~/.gemini/settings.json` or `.gemini/settings.json`). It exposes 53 tools and
18 resources for security, quality, bugfix, deps, compliance, observability,
performance, plus first-class WordPress and .NET (C#/F#) support. All scanners
run locally, no telemetry; results persist in `.guardian/guardian.db`.

When the user's request matches an intent below, **prefer invoking the
dev-guardian MCP tool over running the scanner directly via shell**. The MCP
layer adds regression diffing, baselines, suppressions, severity-weighted risk
scoring, and a cache that avoids re-running unchanged scans. Run `/memory show`
to confirm this file is loaded, `/memory refresh` after editing it.

## Intent → MCP tool

**Security**
- "is this safe?" / "audit security" → `security_scan_full`
- "secrets leaked?" → `scan_secrets`
- "vulnerable deps?" / "CVEs?" → `scan_deps` or `deps_audit`
- "Dockerfile / container" → `scan_containers`
- "Terraform / K8s / IaC" → `scan_iac`
- "deep bug hunt" → `bug_hunt`
- "what routes/endpoints does this app expose?" → `map_attack_surface`
- "active DAST / pen-test the running app" → `map_attack_surface` first for the
  route inventory, then `scan_dast` against the already-running app (loopback
  only unless `authorized_target: true` is set; a clean result is not evidence
  of injection safety — see its tool description)
- "is this finding actually reachable / exploitable?" → `map_attack_surface`
  (if no recent snapshot) then `validate_finding` — reachable / unreachable /
  unknown per finding with evidence, report-only, never suppresses or touches
  severity; `unreachable` is never available for Ruby, Java, C#, PHP, or a file
  reached only by a CLI/cron/queue entry point — see its tool description for
  the full limits

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
