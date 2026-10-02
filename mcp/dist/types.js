/**
 * Core types shared across the dev-guardian MCP server.
 *
 * Authoritative shapes — anything written to or read from SQLite, returned
 * from a tool, or served as a resource MUST use the types declared here.
 *
 * Stability promise: changing any exported type in this file is a schema
 * change. Migrations in `storage/migrations/` and tool/resource handlers
 * must be updated in lockstep.
 */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const SEVERITY_ORDER = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};
export const CATEGORIES = [
    'security',
    'bug',
    'quality',
    'license',
    'compliance',
    'performance',
];
export const SCAN_STATUSES = ['running', 'completed', 'failed', 'cancelled'];
export const SCAN_TYPES = [
    'security_full',
    'sast',
    'secrets',
    'deps',
    // `deps_audit` wrote 'deps' until 2.0.x, sharing its cache entries with
    // `scan_deps`; see `isDepsAuditScan` for reading those older rows.
    'deps_audit',
    'containers',
    'iac',
    'bugs',
    'quality',
    'review_pr',
    'compliance',
    'audit',
    'sbom',
    'detect_stack',
    'perf',
    'init',
    'observability',
    // WordPress family
    'wordpress',
    'wp_audit',
    'wp_vuln_check',
    // Source-based vulnerability matching (no live URL): wp_vuln_check_source.
    'wp_vuln_check_source',
    'wp_cron_audit',
    'wp_rest_audit',
    // .NET family
    'dotnet_secrets',
    'dotnet_target_framework',
    'dotnet_efcore_audit',
    // AI-agent supply chain
    'skill_audit',
    // Active DAST
    'dast',
    // Agent workspace / host-config audit
    'agent_audit',
    // What the configured MCP servers actually serve (audit_mcp_tools)
    'mcp_tool_audit',
    // A SARIF log another tool wrote, imported (import_sarif); one open-set slot per meta.source_tool
    'sarif_import',
];
/**
 * Scan types whose rows carry CVEs (`scan_cves`): the dependency scanners and
 * the full security scan, which runs Trivy too. For readers that want "the
 * latest scan that measured CVEs".
 */
export const CVE_SOURCE_SCAN_TYPES = ['deps_audit', 'deps', 'security_full'];
/**
 * Whether a scan row was written by `deps_audit` — the only tool that records
 * `bot_configured`. Rows from 2.0.x carry scan type 'deps', the type
 * `scan_deps` also writes, and are told apart by that very key: `scan_deps`
 * never wrote it. Without this, the latest `scan_deps` run shadowed the
 * latest `deps_audit` and read as "no dependency bot configured".
 */
export function isDepsAuditScan(scan) {
    if (scan.scan_type === 'deps_audit')
        return true;
    return scan.scan_type === 'deps' && scan.meta?.['bot_configured'] !== undefined;
}
export const TOOL_RUN_STATUSES = ['ok', 'skipped', 'failed'];
/**
 * OpenVEX's `not_affected` justification labels (OpenVEX spec v0.2.0, "Status
 * Justifications" — the labels of CISA's VEX Status Justifications, June 2022).
 */
export const OPENVEX_JUSTIFICATIONS = [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
];
export const HTTP_METHODS = [
    'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'ANY',
];
/**
 * Discriminated union covering every domain-level failure a tool can return.
 * Protocol-level failures (validation, internal exceptions) are surfaced as
 * MCP JSON-RPC errors instead — never as a `DomainError`.
 */
export const DOMAIN_ERROR_CODES = [
    'missing_scanner',
    'no_bash_shell',
    'not_a_git_repo',
    'working_tree_dirty',
    'unknown_scan_id',
    'unknown_finding',
    'requires_elevation',
    'unsupported_os',
    'output_too_large',
    'scanner_failed',
    'cancelled',
    'not_a_wordpress_install',
    'not_a_wordpress_project',
    'target_not_found',
    'unsupported_target',
    'target_not_authorized',
    'no_surface_snapshot',
    // import_sarif: why a log was refused (tools/importSarif.ts).
    'invalid_sarif',
    'outside_project',
    'refused_file',
    'not_found',
];
//# sourceMappingURL=types.js.map