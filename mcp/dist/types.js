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
    'wp_cron_audit',
    'wp_rest_audit',
    // .NET family
    'dotnet_secrets',
    'dotnet_target_framework',
    'dotnet_efcore_audit',
    // AI-agent supply chain
    'skill_audit',
];
export const TOOL_RUN_STATUSES = ['ok', 'skipped', 'failed'];
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
    'requires_elevation',
    'unsupported_os',
    'output_too_large',
    'scanner_failed',
    'cancelled',
    'not_a_wordpress_install',
    'not_a_wordpress_project',
    'target_not_found',
    'unsupported_target',
];
//# sourceMappingURL=types.js.map