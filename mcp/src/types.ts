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
  // Active DAST
  'dast',
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
 * Where a route came from. `'code'` means Semgrep matched a route registration
 * in source; `'spec'` means an OpenAPI or Swagger document declared it. The two
 * live in the same `routes[]` array so a consumer sees one inventory, but the
 * difference between them is the whole point of the spec diff — a route that is
 * only `'code'` is undocumented, and one that is only `'spec'` may not exist.
 */
export type RouteProvenance = 'code' | 'spec';

/**
 * One externally reachable HTTP route, extracted statically.
 *
 * `path_raw` is what the source literally says at the match site.
 * `path_resolved` adds any prefix we could resolve (router mounting,
 * WordPress REST namespaces).
 *
 * `path_partial` is true whenever `path_resolved` is not a usable URL path,
 * which happens for two distinct reasons:
 *   1. A prefix may be missing and we could not resolve it — the module is
 *      mounted twice, or at a computed prefix, or not mounted anywhere we can
 *      see.
 *   2. The captured value is not a literal path at all but a code expression
 *      (`self::NAMESPACE`, `Paths.ORDERS`, `$route`). No prefix is involved;
 *      the path itself is unknown. `path_resolved` then holds the raw source
 *      text so a human can read what was written, and `confidence` is 'low'.
 *      See `isLiteralPath` in surface/extract.ts.
 *
 * Either way consumers must not treat `path_resolved` as a complete URL path
 * — in particular, must not send a request to it.
 */
export interface RouteRecord {
  method: HttpMethod;
  provenance: RouteProvenance;
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

/**
 * Outcome of importing one OpenAPI 3.x or Swagger 2.0 document via
 * `surface/specImport.ts`. One report per spec file, regardless of how many
 * routes it yielded — a spec that parses cleanly but declares nothing is
 * still `'ok'` at the format-detection level, distinct from a document that
 * could not be parsed at all or names no recognisable version.
 */
export interface SpecFileReport {
  file: string;
  format: 'openapi-3' | 'swagger-2' | 'unknown';
  status: 'ok' | 'parse_error' | 'unsupported_version' | 'no_paths';
  routes_found: number;
  /** Present for every status except 'ok'. One line, names the cause. */
  reason?: string;
  /**
   * Path items whose value was a `$ref` this module did not turn into a
   * route — whether the ref is external (this module reads text, never a
   * filesystem, so it can't be followed) or internal (`#/...`): internal
   * `$ref`s are resolved for `parameters` entries only, never for a whole
   * path item, so an internal path-item ref is exactly as unresolved as an
   * external one. Counted, never ignored: a path item that vanished
   * silently would resurface as false dead documentation in the diff.
   */
  unresolved_refs: number;
}

/**
 * One row of `surface/specDiff.ts`'s comparison of code-extracted routes
 * against spec-declared ones. `path` is the normalised comparison key
 * (`normalisePath` output), not either route's raw or resolved path — read
 * that from `code_route` / `spec_route` when present.
 */
export interface SpecDiffEntry {
  method: HttpMethod;
  /** The normalised comparison key, human-readable: `/users/{}`. */
  path: string;
  code_route?: RouteRecord;
  spec_route?: RouteRecord;
  /** Present on `unmatchable` entries: one line saying why. */
  reason?: string;
}

/**
 * Output of `surface/specDiff.ts#diffSpecRoutes`. `null` at the call site
 * (never this type) is how "no spec was found" is distinguished from "the
 * spec documents nothing" — see that module's doc comment.
 */
export interface SpecDiff {
  /**
   * One row per (code route, spec route) PAIR sharing a normalised path and
   * a compatible method — not one row per route documented. A single `ANY`
   * code route paired against a spec path that declares both `get` and
   * `post` contributes two entries here, so `matched.length` can exceed the
   * number of distinct code or spec routes involved. Read it as "matched
   * pairs", never as "N routes are documented".
   */
  matched: SpecDiffEntry[];
  /** In the code, absent from every spec — shadow endpoints. */
  code_only: SpecDiffEntry[];
  /** In a spec, absent from the code — dead documentation. */
  spec_only: SpecDiffEntry[];
  /** Could not be classified either way. Never reported as a finding. */
  unmatchable: SpecDiffEntry[];
  /**
   * Resolvable code routes that looked like shadow endpoints — no spec route
   * matched them — but were withheld from `code_only` because a partial spec
   * route's raw path is a suffix of theirs: that spec route (its own prefix
   * unresolved, e.g. from a templated `servers[].url`) may be this very
   * route, so it was filed under `unmatchable` instead. Not a clean bill of
   * health: a single templated server URL can drive this arbitrarily high,
   * silently withholding every shadow-endpoint finding the diff would
   * otherwise report. Surfaced so that gap is visible, not just safe.
   */
  code_only_withheld: number;
  /**
   * The mirror of `code_only_withheld`: resolvable spec routes that looked
   * like dead documentation but were withheld from `spec_only` because a
   * partial code route's raw path is a suffix of theirs. Same caveat, other
   * direction — see that field's doc comment.
   */
  spec_only_withheld: number;
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
   * Matches Semgrep reported for this language whose captures could not be
   * read, so the routes exist but are absent from the inventory. Non-zero only
   * on a Semgrep that redacts match content AND when re-reading the source at
   * the reported offsets failed (see `surface/recoverMetavars.ts`) — no rule
   * family is refused, so this does not track any framework or language.
   */
  unreadable_matches: number;
  /**
   * 'no_rules' means the language was detected but the rule pack covers no
   * framework for it — the case most tools hide by reporting zero.
   *
   * 'unreadable' means Semgrep DID match routes here and we could not read
   * them. It exists so that case never collapses into 'no_matches', which a
   * consumer reads as "this language exposes nothing" — the inverse of the
   * truth, and the falsehood this whole tool is built to avoid.
   *
   * It no longer describes any rule family: every family is now recovered on
   * every Semgrep version. What remains is the genuine case — source that could
   * not be read at the offsets reported, e.g. a file rewritten mid-scan.
   */
  status: 'ok' | 'no_matches' | 'no_rules' | 'unreadable';
  /**
   * `guardian_kind: import` matches for this language whose specifier could
   * not be resolved to a file in the project — a bare/third-party specifier
   * (`'express'`, `'os'`), a target outside the scanned tree, or a language
   * whose imports are never resolvable at all (java, csharp, ruby, php — see
   * `RESOLVABLE_LANGUAGES` in `surface/moduleEdges.ts`). Counted rather than
   * silently dropped: `validate_finding`'s negative verdict depends on
   * knowing the import graph has a hole here. Non-zero for those four
   * languages BY DESIGN, not a defect — it is a different coverage
   * dimension from `status` above, which is about route extraction, not
   * import resolution, so a language can be `ok` here and still show 100%
   * unresolved imports.
   */
  unresolved_imports: number;
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
  spec_files: SpecFileReport[];
  /**
   * `null` when no spec parsed. Deliberately not an empty diff: "no spec was
   * found" and "the spec documents nothing" must stay distinguishable, or a
   * project without a spec reads as one where every endpoint is undocumented.
   */
  spec_diff: SpecDiff | null;
  /**
   * Resolved file-level import edges — the data source for `validate_finding`'s
   * import graph (`mcp/src/validate/importGraph.ts`; see that module's doc
   * comment for why file-level, not call-level). Produced by
   * `surface/moduleEdges.ts`'s `extractModuleEdges` + `resolveModuleEdges`,
   * a second, wider extraction over the same `guardian_kind: import`
   * matches `mapAttackSurface.ts` already reads for mount resolution — this
   * one requires no bound symbol, so it covers languages the mount-
   * resolution extraction does not.
   *
   * Every `module_file` here is confirmed to be a file Semgrep actually
   * scanned in this run. An edge whose target could not be resolved to a
   * real file is counted in `coverage[].unresolved_imports` instead of
   * appearing here — never guessed, because a fabricated edge would read as
   * reachability to a later consumer.
   */
  imports: { file: string; module_file: string }[];
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
  'target_not_authorized',
  'no_surface_snapshot',
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
