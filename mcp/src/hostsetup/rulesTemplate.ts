/**
 * Single canonical source for every AI host's dev-guardian rules/context
 * file — item 7 (2026-09-25 full review).
 *
 * Before this: `host-rules/AGENTS.md`, `GEMINI.md`, `cursor.mdc`,
 * `windsurfrules`, `clinerules` and `copilot-instructions.md` were six
 * hand-maintained files that had drifted from each other and from the
 * dogfood copies (root `AGENTS.md`, `.cursor/rules/dev-guardian.mdc`,
 * `.windsurf/rules/dev-guardian.md`) — `.cursor/rules/dev-guardian.mdc` was
 * missing `scan_skill` and `check_toolchain`, `.windsurf/rules/
 * dev-guardian.md` was missing `scan_skill`, and root `AGENTS.md` was
 * missing the `severity_filter`/`filtered_reason` guidance `host-rules/
 * AGENTS.md` itself already had.
 *
 * Now: ONE canonical body (`RULES_BODY`, below) plus per-host frontmatter
 * (`HOST_FRONTMATTER` — only Cursor and Windsurf have one; every other host
 * reads the body directly). `mcp/scripts/generateHostRules.mjs` (run as part
 * of `npm run build`) writes every `host-rules/*` template AND every dogfood
 * copy from this one source, and `mcp/test/unit/hostsetup/
 * hostRulesDrift.test.ts` fails if a generated copy is ever hand-edited
 * without regenerating.
 *
 * `{{DEV_GUARDIAN_CLI}}` is the one piece of content that legitimately
 * differs per INSTALL, not per host: a `host-rules/*` template (shipped, and
 * copied into other projects via `mcp-config --write`) keeps the literal
 * placeholder text — `setupHost()`'s `installRulesOne` substitutes it with
 * the absolute CLI path at install time (item 6a: the old templates
 * hard-coded `node cli/dev-guardian.mjs`, a path that exists only in THIS
 * repo, so an installed rules file in another project told the agent to run
 * a script that was never there). A dogfood copy substitutes it with the
 * literal `cli/dev-guardian.mjs` — correct for this repo specifically, the
 * one project where that relative path is real.
 */

import type { HostName } from './hostSpecs.js';

/** See the module doc above — substituted at render time, never left in a
 *  file a human or an agent actually reads. */
export const CLI_PATH_PLACEHOLDER = '{{DEV_GUARDIAN_CLI}}';

/** Quotes `cliPath` for inclusion in an example shell command only when it
 *  contains whitespace (this repo's own path does, "CLAUDE SKILLS") —
 *  mirrors `mcpConfig.ts`'s `tomlString`: quote only when the value actually
 *  needs it, never unconditionally. */
export function formatCliPathForDoc(cliPath: string): string {
  return /\s/.test(cliPath) ? `"${cliPath}"` : cliPath;
}

/** Replaces every occurrence of the CLI placeholder in `body` with
 *  `cliPath`, formatted for display. Pure — no I/O. */
export function substituteCliPath(body: string, cliPath: string): string {
  return body.split(CLI_PATH_PLACEHOLDER).join(formatCliPathForDoc(cliPath));
}

/**
 * The canonical body, shared verbatim by every host. Deliberately does NOT
 * list slash commands by name (Task 14 of this same review renames them) —
 * where an earlier, host-specific version of this content named
 * `/guardian-trend` directly, this one points at "the plugin's own trend
 * command" instead, so a rename elsewhere in the plugin cannot leave this
 * file naming a command that no longer exists.
 */
export const RULES_BODY = `# dev-guardian

This project has the **dev-guardian MCP server**: 63 tools and 18 resources for security, bugs, quality,
dependencies, compliance, observability, performance, WordPress and .NET. Every scanner runs locally and results
persist in \`.guardian/guardian.db\`. dev-guardian sends no telemetry of its own;
Semgrep's registry mode sends metrics — pass \`local_only: true\` to avoid it.

## Rules

- **Prefer these MCP tools over running a scanner in the shell** — they keep baselines, regression diffs,
  suppressions, risk scores and a cache.
- **A scanner that did not run is a gap, never "0 findings."** Read \`tools_run\`, \`missing_tools\` and \`coverage\`
  before the findings.
- \`severity_min\` filters the response only: the scan records everything, so a baseline taken from a filtered
  scan is complete. \`severity_filter\` on the result says how many were held back.
- About to add a package? \`vet_packages\` BEFORE the install: the name exists, OSV malware and
  vulnerabilities, publish age, install scripts, typosquatting. \`unknown\` means a check could not run — never ok.
- \`create_fix_pr\` defaults to a dry run (\`apply: false\`); it opens a pull request only with \`apply: true\`, after
  the user agrees. It applies only fixes a scanner emitted — \`deps_update_plan\` bumps and Semgrep autofixes
  (\`fix_available\`) — and \`filtered\` / \`filtered_reason\` say what it skipped and why.
- \`scan_secrets\` with \`verify_live: true\` sends each secret to its provider: ask the user first.
- \`audit_mcp_tools\` STARTS the servers it audits: pass only the names the user gave.
- \`scan_dast\` probes an app that is already running, after \`map_attack_surface\`; loopback only unless the user
  attests \`authorized_target: true\`. A clean result is no proof of injection safety.
- \`validate_finding\`'s \`unreachable\` is a static, file-level signal blind to dynamic imports — never on its
  own a reason to suppress a finding.
- **Never run \`db adopt\` yourself.** If \`health_status\` returns \`storage_warning\`, or a scan warns that the
  project's database is not used, history goes to a per-user fallback: tell the user, and give them
  \`node ${CLI_PATH_PLACEHOLDER} db adopt --project <project>\` to run in their own terminal (\`--yes\` registers the database).
  Point them at \`suppressions.all_projects\` and \`storage.future_dated_scans_ignored\` first.
- Don't \`suppress_finding\` before \`triage_findings\`; don't write a fix before \`suggest_fix\`; don't run
  \`scan_wordpress\` before \`detect_stack\` says WordPress.

## Intent → MCP tool

- **Security** — the whole code: \`security_scan_full\` (a small change: \`review_pr\`) · SAST only:
  \`scan_sast\` · secrets: \`scan_secrets\` · dependency CVEs: \`scan_deps\`, \`deps_audit\` · Dockerfile / image /
  compose: \`scan_containers\` · Terraform, Kubernetes, GitHub Actions: \`scan_iac\` · implementation bugs:
  \`bug_hunt\` · a third-party skill or MCP server before installing it: \`scan_skill\` · the agent's own config (\`.mcp.json\`, …): \`audit_agent_config\` (reads, runs nothing) · the tools an
  MCP server serves, or whether they changed: \`audit_mcp_tools\` with \`servers: ["X"]\` · routes and endpoints:
  \`map_attack_surface\` · runtime probing: \`scan_dast\` · is a finding reachable: \`validate_finding\` · a model
  verifies the findings or hunts what scanners miss: \`llm_scan_start\` (below) · another tool's SARIF:
  \`import_sarif\`.
- **Quality** — duplication, complexity, smells: \`quality_check\`.
- **Dependencies** — upgrade plan: \`deps_update_plan\` · audit: \`deps_audit\` · VEX / "are we affected?":
  \`export_vex\`; a CVE is stated not_affected with \`suppress_finding\` (\`vex_status: not_affected\` + a
  justification).
- **Compliance** — GDPR / SOC 2 / ISO 27001: \`compliance_check\`, \`compliance_evidence\` · SBOM: \`generate_sbom\`,
  \`sbom_diff\` · licences: \`license_compatibility\`.
- **Setup** — bootstrap: \`detect_stack\` → \`init_project\` (configs out of date: \`init_project\` with refresh=true,
  \`apply=false\` first) → \`install_toolchain\` · installed scanners: \`check_toolchain\` · git hooks:
  \`precommit_install\` · custom Semgrep rules: \`register_custom_rules\` · logging / metrics: \`observability_setup\` ·
  performance: \`perf_check\`.
- **WordPress** — code: \`scan_wordpress\` · a live install: \`wp_audit\` (needs WP-CLI) ·
  CVEs from a live URL: \`wp_vuln_check\`, from source: \`wp_vuln_check_source\` · cron backdoors: \`wp_cron_audit\` ·
  REST exposure: \`wp_rest_audit\` · posture: \`wp_describe_setup\` · hardening: \`wp_recommend_hardening\` · one
  plugin: \`wp_plugin_check\` · many sites: \`bulk_audit_wordpress_sites\`.
- **.NET** — secrets in configs: \`scan_dotnet_secrets\` · end-of-life frameworks: \`dotnet_target_framework_check\` ·
  EF Core migrations: \`dotnet_efcore_audit\` · posture: \`dotnet_describe_setup\`.
- **History and reports** — full audit: \`audit_executive\` · \`risk_score\` · what is new: \`diff_scans\` ·
  regressions: \`regression_alert\` · \`set_baseline\` · noise: \`triage_findings\` · order: \`prioritize_findings\` ·
  how to fix X: \`suggest_fix\` (context; you write the patch) · scanner
  fixes as PRs: \`create_fix_pr\` · \`report_export\` · GitHub issues: \`create_github_issues\` · server health:
  \`health_status\`.
- **CLI** — a one-screen summary: \`node ${CLI_PATH_PLACEHOLDER} status\`; the same as a self-contained HTML page:
  \`node ${CLI_PATH_PLACEHOLDER} dashboard\` (both read-only) · another AI host: \`node ${CLI_PATH_PLACEHOLDER} mcp-config <host>\`.

Resources are read-only views of the same history: \`guardian://findings/open\`, \`guardian://scans/latest\`,
\`guardian://wp/audit/{scan_id}\` and the rest of \`findings/\`, \`scans/\`, \`cves/\`, \`wp/\`, \`dotnet/\`, \`surface/\`.

## LLM-assisted scan (\`llm_scan_start\` → \`llm_scan_task\` → \`llm_scan_submit\`)

\`llm_scan_start { project_path, modes }\` plans (\`verify\`; \`hunt\` after \`map_attack_surface\`): show the user the
token estimate and \`token_limit_note\` first, and pass \`confirm: true\` above \`max_estimated_tokens\` only after the
user agrees. Then \`llm_scan_task { plan_id }\` leases one task (\`brief\`, \`lease_token\`, 20 minutes); run THAT brief
as below and \`llm_scan_submit { plan_id, task_id, lease_token, independence, payload }\`; repeat until \`done\`.

- **Claude Code** — each \`llm_scan_task\` brief in a fresh subagent, one task per subagent: \`subagent\`.
- **Codex** — spawns a subagent only when asked: ask it to spawn one per \`llm_scan_task\` brief; otherwise
  \`same_context\`.
- **Cline** — no MCP-capable subagent: run the tasks sequentially, one after another: \`same_context\`.
- **Claude Desktop / Cowork chat** — no subagents: sequentially, one at a time: \`same_context\`.
- **MCP sampling (VS Code Copilot)** — \`llm_scan_task { plan_id, execute: "sampling" }\` runs verification
  tasks through the client's model.
- **Other hosts** — a fresh subagent per task if one can call these tools, else \`same_context\`.

Declare independence honestly: a \`same_context\` verdict never demotes or confirms a finding.

## CI and the dev-spec-driven gate

\`node ${CLI_PATH_PLACEHOLDER} scan\` runs the same pipeline headless, gated against a committed \`.guardian/baseline.json\`
(exit \`0\` pass, \`1\` blocked, \`2\` incomplete — never a pass, \`3\` usage error); only
\`node ${CLI_PATH_PLACEHOLDER} baseline update\` writes that file, and it accepts EVERY current finding — never run it to accept
one finding, and leave it to the user. Accept one reviewed finding with an inline suppression and a reason
(\`nosemgrep: <rule> -- <reason>\`, \`# nosec\`). Pipelines and pull requests: the plugin's \`docs/ci.md\`.
\`.gitignore\` keeps \`.guardian/\` out of git but its shared files: \`**/.guardian/*\`, \`!**/.guardian/baseline.json\`,
\`!**/.guardian/budgets.yml\`, \`!**/.guardian/hooks.config.json\`, \`!**/.guardian/hooks-allowlist.json\`,
\`!**/.guardian/scan.yml\` (never a bare \`.guardian/\`). dev-spec-driven 1.29+ runs this gate when it closes a feature; from
such a project the runnable line is \`node .specs/guardian.cjs <arguments>\`.
`;

/**
 * YAML frontmatter each host's rules file needs, keyed by `HostName`. Only
 * Cursor (\`.mdc\`) and Windsurf require one — every other host reads the
 * body directly, with no header of its own. Verified against each host's
 * own documented convention (both use \`trigger\`/\`alwaysApply\`-style
 * activation frontmatter; Windsurf's rules directory is \`.windsurf/rules/\`,
 * not the legacy \`.windsurfrules\` — item 6e).
 *
 * Both are AGENT-REQUESTED: the host shows the model the description and
 * loads the body when the task matches (Cursor: `alwaysApply: false` with a
 * description and no globs; Windsurf: `trigger: model_decision`). They were
 * always-on — 18.5 KB on every request, and past Windsurf's 12 000-character
 * rule cap, which silently dropped everything after the CI section, the
 * "never run db adopt" rule included. The description names the moments a
 * model must not miss (installing a package, an AI skill or an MCP server).
 */
export const RULES_DESCRIPTION =
  'dev-guardian MCP tools — use for security scans, secrets, dependency CVEs, bug hunts, code quality, ' +
  'compliance, WordPress or .NET audits, and before installing a package, an AI skill or an MCP server.';

export const HOST_FRONTMATTER: Partial<Record<HostName, string>> = {
  cursor: ['---', `description: ${RULES_DESCRIPTION}`, 'globs:', 'alwaysApply: false', '---'].join('\n'),
  windsurf: ['---', 'trigger: model_decision', `description: ${RULES_DESCRIPTION}`, '---'].join('\n'),
};

/** Renders the complete file content for `host`'s rules file — frontmatter
 *  (when it has one) followed by the canonical body. The CLI-path
 *  placeholder is left UNSUBSTITUTED here; callers substitute it themselves
 *  (`installRulesOne` for an install, the generator script for a dogfood
 *  copy) because the two need different values. */
export function renderHostRulesFile(host: HostName): string {
  const frontmatter = HOST_FRONTMATTER[host];
  return frontmatter ? `${frontmatter}\n\n${RULES_BODY}` : RULES_BODY;
}

/**
 * Hosts this repo dogfoods a rules file for, mapped to the file's path
 * relative to the repo root. A SUBSET of `HOST_SPECS`' own hosts-with-rules:
 * Cline is deliberately not dogfooded here (no root `.clinerules` exists —
 * this repo's own documented dogfood file list in `CLAUDE.md` never named
 * one), and Claude Desktop has no rules-file mechanism at all. Each path
 * below is identical to that same host's OWN `rules.target_path` in
 * `hostSpecs.ts` — not a coincidence: dogfooding IS applying the plugin's
 * own install layout to this repo as if it were a target project.
 */
export const DOGFOOD_RULE_TARGETS: Partial<Record<HostName, string>> = {
  codex: 'AGENTS.md',
  gemini: 'GEMINI.md',
  cursor: '.cursor/rules/dev-guardian.mdc',
  windsurf: '.windsurf/rules/dev-guardian.md',
  copilot: '.github/copilot-instructions.md',
};
