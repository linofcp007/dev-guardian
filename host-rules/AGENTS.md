# Agent rules — dev-guardian

This repository has the **dev-guardian MCP server** registered. It exposes
~35 tools and 11 resources for security, quality, bugfix, deps, compliance,
observability, and performance — all running open-source scanners locally,
no telemetry, results persisted in `.guardian/guardian.db`.

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
- "review before PR" / "diff-only scan" → `review_pr`
- "code quality" / "duplication" → `quality_check`

**Deps**
- "what should I update?" → `deps_update_plan`
- "audit deps" → `deps_audit`

**Compliance**
- "GDPR / SOC2 / ISO27001" → `compliance_check` + `compliance_evidence`
- "SBOM" → `generate_sbom`
- "license compatibility" → `license_compatibility`

**Ops**
- "bootstrap project" → `init_project`
- "install scanners" → `install_toolchain`
- "detect stack" → `detect_stack`
- "add logging / metrics" → `observability_setup`
- "performance" → `perf_check`

**Meta**
- "full audit" → `audit_executive`
- "risk score" → `risk_score`
- "what's new since last scan?" → `diff_scans`
- "set baseline" → `set_baseline`
- "noise reduction" → `triage_findings`
- "how do I fix finding X?" → `suggest_fix` (returns source context; you propose the patch)
- "export report" → `report_export`
- "create GitHub issues" → `create_github_issues` (uses local `gh` CLI)
- "pre-commit hooks" → `precommit_install`
- "health check" → `health_status`

## Resources

- `guardian://findings/open`, `guardian://findings/critical`, `guardian://findings/by-severity/{level}`
- `guardian://cves/active`
- `guardian://compliance/status`
- `guardian://baseline`
- `guardian://stack`
- `guardian://scans/latest`, `guardian://scans/history`, `guardian://scans/{scan_id}`

## Typical sequences

- **Bootstrap**: `detect_stack` → `init_project` → `install_toolchain` → `security_scan_full` → `set_baseline`
- **Before PR**: `review_pr` → `triage_findings` → `suggest_fix`
- **Audit**: `audit_executive` → `risk_score` → `compliance_evidence framework=…`

## Anti-patterns

- Don't run `security_scan_full` for tiny changes — `review_pr` is 10×+ faster.
- Don't `suppress_finding` before `triage_findings` classifies the noise.
- Don't synthesise fixes without `suggest_fix` first — you'd lack precise source context.
- Don't shell out to scanners directly when an MCP tool exists.
