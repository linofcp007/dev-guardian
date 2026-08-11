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

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_ORDER: Record<Severity, number> = {
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
] as const;
export type Category = (typeof CATEGORIES)[number];

export const SCAN_STATUSES = ['running', 'completed', 'failed', 'cancelled'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

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
] as const;
export type ScanType = (typeof SCAN_TYPES)[number];

export const TOOL_RUN_STATUSES = ['ok', 'skipped', 'failed'] as const;
export type ToolRunStatus = (typeof TOOL_RUN_STATUSES)[number];

/**
 * How complete a scan's coverage was. Derived (not persisted as a column)
 * from `tools_run` + `missing_tools`; see `tools/scanCoverage.ts`. Surfaced on
 * `ScanResult` so a "0 findings" result that scanned nothing never reads as
 * "all clear".
 */
export type ScanCoverage = 'full' | 'partial' | 'none';

export interface ToolRun {
  name: string;
  version?: string;
  status: ToolRunStatus;
  reason?: string;
}

export interface Finding {
  fingerprint: string;
  tool: string;
  rule_id?: string;
  severity: Severity;
  category: Category;
  subcategory?: string;
  title: string;
  message?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
  fix_available: boolean;
  fix_applied?: boolean;
}

export interface ScanRecord {
  scan_id: string;
  scan_type: ScanType;
  project_path: string;
  tree_hash: string;
  started_at: string;
  finished_at: string | null;
  status: ScanStatus;
  tools_run: ToolRun[];
  missing_tools: string[];
  report_paths: string[];
  cached?: boolean;
  cached_from?: string;
  meta?: Record<string, unknown>;
}

export type FindingsCountBySeverity = Record<Severity, number>;

export interface ScanResult extends ScanRecord {
  findings_count_by_severity: FindingsCountBySeverity;
  top_findings: Finding[];
  warnings: string[];
  /**
   * Trust signal for the severity counts above. 'none' means no scanner
   * actually ran — the counts are meaningless, not clean. Derived from
   * tools_run/missing_tools; see `tools/scanCoverage.ts`.
   */
  coverage?: ScanCoverage;
}

export interface Cve {
  cve_id: string;
  package_name: string;
  installed_version?: string;
  fixed_version?: string;
  severity: Severity;
  first_seen_scan_id: string;
  last_seen_scan_id: string;
}

export interface Suppression {
  id: number;
  finding_fingerprint: string;
  reason: string;
  created_at: string;
  expires_at?: string;
  created_by?: string;
}

export interface Baseline {
  id: number;
  scan_id: string;
  set_at: string;
  note?: string;
}

export interface StackSnapshot {
  os: 'linux' | 'darwin' | 'wsl' | 'debian' | 'rhel' | 'arch' | 'macos' | 'windows' | 'unknown';
  arch: string;
  languages: string[];
  package_managers: string[];
  frameworks: string[];
  existing_tools: string[];
  has_docker: boolean;
  has_compose: boolean;
  has_terraform: boolean;
  has_kubernetes: boolean;
  has_ansible: boolean;
  has_github_actions: boolean;
  has_gitlab_ci: boolean;
}

export const HTTP_METHODS = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'ANY',
] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/**
 * One externally reachable HTTP route, extracted statically.
 *
 * `path_raw` is what the source literally says at the match site.
 * `path_resolved` adds any prefix we could resolve (router mounting,
 * WordPress REST namespaces). When we know a prefix may be missing but could
 * not resolve it, `path_partial` is true — consumers must not treat
 * `path_resolved` as a complete URL path in that case.
 */
export interface RouteRecord {
  method: HttpMethod;
  path_raw: string;
  path_resolved: string;
  path_partial: boolean;
  file: string;
  line: number;
  framework: string;
  language: string;
  /**
   * Never inferred from the absence of an auth decorator — see the design
   * doc. 'none' is emitted only for affirmative public declarations such as
   * WordPress `permission_callback: '__return_true'`.
   */
  auth_hint: 'none' | 'required' | 'unknown';
  params: string[];
  confidence: 'high' | 'medium' | 'low';
  /**
   * Framework-level route namespace, when the framework has one. Currently
   * only WordPress: `register_rest_route('myplugin/v1', '/items')` yields
   * namespace 'myplugin/v1'. Semgrep cannot concatenate two metavariables
   * into a third, so the extractor keeps them as separate fields and the WP
   * resolver combines them.
   */
  namespace?: string;
}

/** A `app.use('/prefix', router)`-style mount, consumed by the Node resolver. */
export interface MountRecord {
  prefix: string;
  router_var: string;
  file: string;
  line: number;
}

export interface CoverageEntry {
  language: string;
  detected: boolean;
  routes_found: number;
  /**
   * 'no_rules' means the language was detected but the rule pack covers no
   * framework for it — the case most tools hide by reporting zero.
   */
  status: 'ok' | 'no_matches' | 'no_rules';
}

export interface AttackSurfaceSnapshot {
  routes: RouteRecord[];
  env_vars: { name: string; file: string; line: number }[];
  ports: { port: number; source: string }[];
  /** Precomputed view over `routes`; duplicated so consumers need no regex. */
  webhooks: RouteRecord[];
  coverage: CoverageEntry[];
  tools_run: ToolRun[];
  missing_tools: string[];
}

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
] as const;
export type DomainErrorCode = (typeof DOMAIN_ERROR_CODES)[number];

export interface DomainError {
  code: DomainErrorCode;
  message: string;
  retry_with?: Record<string, unknown>;
}

export type ToolResult<T> =
  | ({ ok: true } & T)
  | { ok: false; error: DomainError };
