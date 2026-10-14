/**
 * The folds (`./fold.ts`): one listed tool per family, the members kept as
 * hidden aliases. Imported by `registerAll.ts` after every member.
 *
 * Each family shares one risk class — no fold joins a reader with a tool
 * that installs, pushes or probes a target its members do not already probe
 * (`toolFolds.test.ts` holds the annotations to it):
 *
 *   - `dotnet_check` — the four local .NET checks;
 *   - `wp_audit` — WP-CLI on an install: the audit, the cron audit, many sites;
 *   - `wp_vuln_check` — the network checks: WPScan, the Wordfence feed, REST probes;
 *   - `wp_report` — what is recorded about one WordPress project: posture,
 *     hardening, one plugin;
 *   - `diff_scans` — two scans compared: a diff, or a regression score;
 *   - `prioritize_findings` — the open findings ranked, or triaged;
 *   - `llm_scan` — the LLM scan's three steps: plan, lease a task, submit its
 *     answer. Each step keeps its member's required arguments (the fold
 *     parses with the member's schema). The prompts from v6 name
 *     `llm_scan { step: "submit" }`; a brief of an older plan names
 *     `llm_scan_submit`, which still answers.
 *
 * Not folded: `generate_sbom` and `sbom_diff` — two entries, little to save.
 */

import { registerFold } from './fold.js';

registerFold({
  name: 'dotnet_check',
  title: '.NET checks',
  description:
    'One .NET check. secrets: appsettings*.json, *.config, nuget.config and launchSettings.json for what ' +
    'gitleaks misses — SQL Server connection strings, Azure keys, NuGet feed credentials, JWT signing keys. ' +
    "target_framework: each project's TargetFramework (LTS, STS, end of life); no SDK needed. efcore: EF Core " +
    'migrations that drop tables or columns, add NOT NULL without a default, or embed credentials. setup: the ' +
    'recorded .NET posture (these checks, NuGet CVEs, open findings), no scanner run.',
  modeKey: 'check',
  modeDescription: 'The check to run.',
  modes: {
    secrets: 'scan_dotnet_secrets',
    target_framework: 'dotnet_target_framework_check',
    efcore: 'dotnet_efcore_audit',
    setup: 'dotnet_describe_setup',
  },
});

registerFold({
  name: 'wp_audit',
  title: 'WordPress install audit (WP-CLI)',
  description:
    'Audit a WordPress install with WP-CLI, changing nothing. mode install (default): core and plugin ' +
    'checksums (themes: not checked), administrators with risky logins, DISALLOW_FILE_EDIT / WP_DEBUG / ' +
    'FORCE_SSL_ADMIN, auto-updating plugins. mode cron: scheduled events with unknown hooks, base64-looking ' +
    'arguments or an inactive plugin — where backdoors persist. mode bulk: the install audit of up to 50 ' +
    'installs. Needs WP-CLI; checksums come from api.wordpress.org.',
  modeKey: 'mode',
  modeDescription: 'install (default), cron or bulk.',
  defaultMode: 'install',
  modes: { install: 'wp_audit', cron: 'wp_cron_audit', bulk: 'bulk_audit_wordpress_sites' },
  params: {
    wp_install_path: 'install, cron: the directory holding wp-config.php.',
    wp_install_paths: 'bulk: up to 50 install directories.',
    concurrency: 'bulk: installs audited at once, 1–10. Default 4.',
    include_users: 'install: list the administrators, flagging risky logins. Default true.',
    include_options: 'install: read the config flags. Default true.',
    risky_login_names: 'install: logins to flag, replacing the default list.',
  },
});

registerFold({
  name: 'wp_vuln_check',
  title: 'WordPress vulnerability checks',
  description:
    'Known WordPress vulnerabilities and exposure. mode live (default): WPScan against target_url (or a local ' +
    "install's URL) for core, plugin and theme CVEs; with no API token it reads not checked, never clean. mode " +
    "source: a local install's versions (project_path = the install root) against the Wordfence feed " +
    '(WORDFENCE_API_KEY; without it, partial) and wp.org (closed or stale plugins). mode rest: GET probes of the ' +
    'live REST API — users, drafts, comments, xmlrpc.php.',
  modeKey: 'mode',
  modeDescription: 'live (default), source or rest.',
  defaultMode: 'live',
  modes: { live: 'wp_vuln_check', source: 'wp_vuln_check_source', rest: 'wp_rest_audit' },
  params: {
    target_url: "live, rest: the live site's URL.",
    wp_install_path: 'live: a local install whose wp-config.php gives the URL.',
    timeout_ms: 'rest: per-request timeout, 1000–60000 ms. Default 15000.',
  },
});

registerFold({
  name: 'wp_report',
  title: 'WordPress recorded state',
  description:
    'What dev-guardian recorded about one WordPress install (project_path = its root); no service queried. kind ' +
    'setup: the latest install, cron and REST audits (target_url for those keyed by URL), open WordPress findings, ' +
    "CVEs. kind hardening: a prioritised checklist from the latest install audit. kind plugin: one slug's " +
    'recorded CVEs and, with a local wp_install_path, its version and state from WP-CLI, which boots the site ' +
    '(its PHP, its database). Run wp_audit or wp_vuln_check first for fresh data.',
  modeKey: 'kind',
  modeDescription: 'setup, hardening or plugin.',
  modes: { setup: 'wp_describe_setup', hardening: 'wp_recommend_hardening', plugin: 'wp_plugin_check' },
  params: {
    target_url: 'setup, plugin: the site URL its scans were recorded under (nothing is sent).',
    slug: 'plugin: the wp.org slug, e.g. "contact-form-7".',
    wp_install_path: "plugin: a local install; WP-CLI reads the plugin's version and state.",
  },
});

registerFold({
  name: 'diff_scans',
  title: 'Compare two scans',
  description:
    'Compare two scans of a project and type. mode diff (default): new, resolved, unchanged and ' +
    'not_remeasured findings (a type the newer scan did not measure — never resolved), matched by ' +
    'line-independent identity; from_scan_id / to_scan_id, else from (previous, baseline) to the latest. mode ' +
    'regression: the latest scan against its baseline (else the previous), weighted by severity; `regressed` ' +
    'past threshold. Suppressed findings count apart (summary.suppressed, suppressed_findings, ' +
    'suppressed_by_severity); unmeasured ones in not_remeasured_by_severity. Another project\'s scan id: ' +
    'unknown_scan_id.',
  modeKey: 'mode',
  modeDescription: 'diff (default) or regression.',
  defaultMode: 'diff',
  modes: { diff: 'diff_scans', regression: 'regression_alert' },
  params: {
    scan_type: 'Compare scans of this type. Default: the newest finding-producing scan.',
    threshold: 'regression: the weighted change that sets regressed. Default 5 (one new critical).',
  },
});

registerFold({
  name: 'prioritize_findings',
  title: 'Rank or triage open findings',
  description:
    "One project's open findings (newest usable scan of each type, suppressions out). view rank (default): by " +
    'severity, category, fix availability and age, boosted for CVEs on CISA KEV or with a high EPSS, each CVE ' +
    'with a CISA SSVC decision (Act, Attend, Track*, Track); missing data is named, never invented. view ' +
    'triage: likely_false_positive, probably_safe or keep, from paths (tests, generated code, fixtures) — ' +
    'suppress_finding candidates for you to judge.',
  modeKey: 'view',
  modeDescription: 'rank (default) or triage.',
  defaultMode: 'rank',
  modes: { rank: 'prioritize_findings', triage: 'triage_findings' },
  params: {
    limit: 'rank: how many to return, 1–500. Default 50.',
    mission_wellbeing: 'rank: SSVC Mission & Well-being of this system. Default medium.',
  },
});

registerFold({
  name: 'llm_scan',
  title: 'LLM-assisted scan',
  description:
    "Your model verifies the scanners' findings and hunts what they miss; the server calls no model. step " +
    'start: plan it, modes verify (a task per finding with a file and line) or hunt (needs ' +
    'map_attack_surface); returns plan_id and a token estimate. Above max_estimated_tokens nothing is handed ' +
    'out until confirm: true, which the user must agree to. step task: lease the next task; its brief goes to ' +
    "a fresh subagent, one per task; done: true and the report at the end. step submit: that task's answer " +
    'as payload; an invalid one is refused with the reasons, two more tries.',
  modeKey: 'step',
  modeDescription:
    'start: plan (with plan_id: its report). task {plan_id}: lease the next task. submit {plan_id, task_id, ' +
    "lease_token, independence, payload}: that task's answer.",
  modes: { start: 'llm_scan_start', task: 'llm_scan_task', submit: 'llm_scan_submit' },
  params: {
    plan_id:
      'task, submit: the plan step start returned. start: report on this plan instead of planning (confirm: ' +
      'true confirms it).',
    task_id: 'submit: the task, as step task returned it.',
    lease_token: 'submit: the lease_token step task returned with the task.',
    payload: "submit: the answer, matching the task's response_schema. At most 64 KiB serialized.",
  },
});
