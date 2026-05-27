# Copilot instructions — dev-guardian

This project uses the **dev-guardian MCP server** for security, quality,
bugfix, dependency, compliance, observability, and performance tasks. The
server exposes ~35 tools and 11 resources, all running open-source scanners
locally with results persisted in `.guardian/guardian.db`.

When the user's request matches one of the intents below, invoke the
corresponding MCP tool rather than running the underlying scanner directly:

## Intent → tool

### Security
- "is this safe?" / "audit security" / "scan vulnerabilities" → `security_scan_full`
- "any leaked secrets?" → `scan_secrets`
- "vulnerable dependencies?" / "CVEs?" → `scan_deps` (raw) or `deps_audit` (with bot detection)
- "Dockerfile / container security" → `scan_containers`
- "Terraform / Kubernetes / IaC" → `scan_iac`
- "bugs / race conditions / null safety" → `bug_hunt`

### Quality
- "review before PR" / "diff-scoped check" → `review_pr`
- "code quality" / "duplication" → `quality_check`

### Dependencies
- "what should I update?" → `deps_update_plan`
- "is renovate / dependabot configured?" → `deps_audit`

### Compliance
- "GDPR / SOC2 / ISO27001 evidence" → `compliance_check` + `compliance_evidence`
- "SBOM" → `generate_sbom`
- "license compatibility" → `license_compatibility`

### Operations
- "bootstrap / init project" → `init_project`
- "install scanners" → `install_toolchain`
- "detect stack" → `detect_stack`
- "add structured logging / metrics" → `observability_setup`
- "performance check / Lighthouse / k6" → `perf_check`

### Meta
- "full audit" → `audit_executive`
- "risk score" → `risk_score`
- "what's new since last scan?" → `diff_scans`
- "set baseline" → `set_baseline`
- "false positives" / "reduce noise" → `triage_findings`
- "how do I fix this finding?" → `suggest_fix` (returns context; you write the patch)
- "export HTML report" → `report_export`
- "open GitHub issues from top findings" → `create_github_issues` (uses local `gh` CLI; no API tokens needed)
- "wire pre-commit hooks" → `precommit_install`
- "is dev-guardian alive?" → `health_status`

## Resources

Read-only data the server exposes (via `guardian://...` URIs):

- `guardian://findings/open` — currently-open findings (suppressions filtered)
- `guardian://findings/critical` — severity=critical subset
- `guardian://cves/active` — CVEs from the latest deps scan
- `guardian://compliance/status` — licenses + policy docs
- `guardian://baseline` — active regression baseline
- `guardian://stack` — detected stack
- `guardian://scans/latest`, `guardian://scans/history`

## Typical workflows

**Bootstrap a fresh project**
1. `detect_stack`
2. `init_project` with `profile: "standard"`
3. `install_toolchain` (auto-install missing scanners)
4. `security_scan_full`
5. `set_baseline` to freeze the starting state

**Before opening a PR**
1. `review_pr` — diff-scoped, fast
2. `triage_findings` to bucket noise
3. `suggest_fix` for real findings (returns ±20 lines of source); propose patches

**Periodic audit**
1. `audit_executive`
2. `risk_score`
3. `compliance_evidence` for handover

## Anti-patterns to avoid

- Don't run `security_scan_full` for every small change — use `review_pr`.
- Don't `suppress_finding` before `triage_findings`.
- Don't propose patches without `suggest_fix` first (you'll lack precise line context).
- Don't shell out to scanners directly — you lose diff_scans, baselines, persistence.
