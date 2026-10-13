/**
 * The MCP tool annotations every tool declares (`tools/list` → `annotations`):
 * the four behaviour hints a host reads to decide how carefully to treat a
 * call. None of the 63 tools declared any (review 8, finding 7), so a host
 * could not tell `install_toolchain` — which installs software by default —
 * or `create_fix_pr` — which pushes branches and opens pull requests — from
 * `health_status`. `audit_mcp_tools` audits other servers' annotations; this
 * server now has its own.
 *
 * One table, keyed by tool name, rather than a field written into each tool
 * module: the four answers are easier to review side by side, and a tool
 * module may still declare `annotations` itself, which wins
 * (`registerToolModule`, `./index.ts`). `test/integration/toolSchemaListing.test.ts`
 * holds every registered tool to an entry here, and every entry to a tool;
 * a fold's entry (`./folds.ts`) covers each of its members' — the hidden
 * aliases keep their own.
 *
 * What each hint means HERE (the MCP specification leaves "environment" open):
 *
 *   - `readOnlyHint` — the call changes nothing a user could see: no file in
 *     the project or on the system, no remote state, and no row of the
 *     history (a scan, a finding, a suppression, a baseline). A refreshed
 *     CVE-intelligence cache does not count. Every scan records its result,
 *     so no scan is read-only.
 *   - `destructiveHint` — it can overwrite or delete something the user had:
 *     project source (`auto_fix` applies Semgrep's autofixes), managed
 *     configuration (`init_project` with `refresh`), system packages
 *     (`install_toolchain`), or a target application's data (`scan_dast`
 *     sends attack payloads to it).
 *   - `idempotentHint` — calling it again with the same arguments leaves the
 *     project, the system and any remote as the first call did; a second
 *     history row for the same scan does not count. False where a repeat
 *     opens a second pull request or issue, starts another plan, loads a
 *     target again, or imports a log twice.
 *   - `openWorldHint` — it can reach beyond this machine on a default call:
 *     Semgrep's registry rules, Trivy's vulnerability database, OSV, EPSS /
 *     CISA KEV, package registries, NuGet feeds (a .NET build), WordPress.org,
 *     GitHub, or a URL under test. `local_only` / `GUARDIAN_OFFLINE=1` narrow
 *     some of these; the hint describes the default.
 */

import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';

type Hints = Required<Pick<ToolAnnotations, 'readOnlyHint' | 'destructiveHint' | 'idempotentHint' | 'openWorldHint'>>;

/** Reads history, the project or the system, and changes nothing (see the module doc). */
const readOnly = (openWorld: boolean): Hints => ({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: openWorld,
});

/** Records what it found (history rows, `.guardian/reports/`); overwrites nothing; safe to repeat. */
const records = (openWorld: boolean): Hints => ({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: openWorld,
});

export const TOOL_ANNOTATIONS: Readonly<Record<string, Hints>> = {
  // ---- reads only
  check_toolchain: readOnly(false),
  health_status: readOnly(false),
  diff_scans: readOnly(false),
  regression_alert: readOnly(false),
  triage_findings: readOnly(false),
  suggest_fix: readOnly(false),
  license_compatibility: readOnly(false),
  compliance_evidence: readOnly(false),
  dotnet_describe_setup: readOnly(false),
  wp_describe_setup: readOnly(false),
  wp_recommend_hardening: readOnly(false),
  // EPSS / CISA KEV for the CVEs it ranks.
  prioritize_findings: readOnly(true),
  risk_score: readOnly(true),
  // The package registries' latest versions.
  deps_update_plan: readOnly(true),
  // The registry's metadata and OSV for each package named.
  vet_packages: readOnly(true),

  // ---- scans and reports: record their result, overwrite nothing
  detect_stack: records(false),
  map_attack_surface: records(false),
  quality_check: records(false),
  compliance_check: records(false),
  generate_sbom: records(false),
  sbom_diff: records(false),
  dotnet_target_framework_check: records(false),
  wp_cron_audit: records(false),
  wp_plugin_check: records(false),
  audit_agent_config: records(false),
  register_custom_rules: records(false),
  export_vex: records(false),
  report_export: records(false),
  observability_setup: records(false), // writes new files only: an existing one is skipped
  precommit_install: records(false),
  set_baseline: records(false),
  scan_deps: records(true), // Trivy's vulnerability database
  scan_iac: records(true),
  scan_containers: records(true), // registry images, Trivy's database, Sigstore
  scan_secrets: records(true), // `verify_live` asks each provider whether a key is live
  scan_dotnet_secrets: records(true), // a .NET build restores from NuGet feeds
  dotnet_efcore_audit: records(true),
  // Folds (./folds.ts): every member's hints covered — read-only only when all are, open-world when any is.
  dotnet_check: records(true),
  wp_report: records(false), // the plugin kind runs WP-CLI and records a row
  scan_skill: records(true), // OSV
  scan_wordpress: records(true), // Semgrep's registry PHP rules
  wp_vuln_check: records(true), // WordPress.org / WPScan
  wp_vuln_check_source: records(true),
  wp_audit: records(true), // `wp core verify-checksums` asks api.wordpress.org
  bulk_audit_wordpress_sites: records(true),
  wp_rest_audit: records(true), // requests to the site's REST routes
  deps_audit: records(true), // Trivy's database and the native auditors' advisories
  review_pr: records(true), // Semgrep's registry rules
  audit_executive: records(true),
  audit_mcp_tools: records(true), // starts the configured servers (remote ones with allow_remote)
  validate_finding: records(true), // EPSS / CISA KEV
  suppress_finding: records(true), // warns from EPSS / CISA KEV before hiding a CVE

  // ---- can rewrite project source: `auto_fix` applies Semgrep's autofixes
  scan_sast: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  bug_hunt: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  security_scan_full: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },

  // ---- writes the user does not undo with one call
  // Installs (and may upgrade) system packages, by default — `dry_run` previews.
  install_toolchain: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  // `refresh` rewrites the configuration files it manages.
  init_project: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  // Sends attack payloads to the application under test.
  scan_dast: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  // Load tests and Lighthouse runs against a URL.
  perf_check: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  // Pushes branches and opens pull requests on GitHub (in a disposable worktree, never the user's tree).
  create_fix_pr: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  // Files issues on GitHub unless `dry_run`.
  create_github_issues: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  // Adds a scan to the history per call.
  import_sarif: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  // The LLM scan's plan and its leases (the model's own sampling goes to the client, not out).
  llm_scan_start: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  llm_scan_task: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  llm_scan_submit: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
};
