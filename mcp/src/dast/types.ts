/**
 * Shared shapes for the DAST engine.
 *
 * Kept in their own module (rather than in the top-level `types.ts`) because
 * none of them are persisted: they are the in-flight vocabulary of one scan.
 * The only DAST shape that reaches storage is `Finding`, which already exists.
 */

import type { HttpMethod, RouteRecord } from '../types.js';

export type TargetClass = 'loopback' | 'private' | 'public';

export interface TargetDecision {
  allowed: boolean;
  target_class: TargetClass;
  /** Normalised origin, e.g. `http://localhost:3000`. Empty when unparseable. */
  origin: string;
  host: string;
  /** Human-readable refusal. `null` exactly when `allowed` is true. */
  reason: string | null;
}

export const DAST_CHECKS = [
  'reachability',
  'anonymous_exposure',
  'differential_authz',
  'cors',
  'security_headers',
  'info_disclosure',
  'method_surface',
  'open_redirect',
  'rate_limit',
] as const;
export type DastCheck = (typeof DAST_CHECKS)[number];

/**
 * Why a check produced no findings. `ok` is the only value that means "this
 * check ran and what it found is what there is"; every other value means the
 * check did not run, and must never be read as a clean result.
 */
export type CheckStatus =
  | 'ok'
  | 'skipped_envelope'
  | 'no_candidate'
  | 'needs_credentials'
  | 'target_error';

export type SkipReason = 'partial_path' | 'method_envelope' | 'duplicate' | 'cap';

export type ProbeVariant =
  | 'anonymous'
  | 'authenticated'
  | 'cors'
  | 'options'
  | 'rate_limit';

export interface ProbeRequest {
  /** Stable within one plan: `${variant} ${method} ${path}`. */
  id: string;
  method: Exclude<HttpMethod, 'ANY'>;
  /** Resolved path with any parameters substituted. Always starts with '/'. */
  path: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  variant: ProbeVariant;
  /** True when at least one path parameter was filled with a synthetic value. */
  synthetic_params: boolean;
  /** Index into `PlanOutcome.routes`; null for origin-level probes. */
  route_index: number | null;
}

export interface ProbeResult {
  request: ProbeRequest;
  outcome: 'completed' | 'timeout' | 'network_error';
  status: number | null;
  /** Header names lower-cased. */
  headers: Record<string, string>;
  /** First `BODY_PREFIX_BYTES` of the body, for evidence and signature checks. */
  body_prefix: string;
  /** sha256 over the (capped) body. Empty string when nothing was read. */
  body_hash: string;
  elapsed_ms: number;
  error: string | null;
}

export interface PlanSkip {
  method: string;
  path: string;
  reason: SkipReason;
}

export interface PlanOutcome {
  requests: ProbeRequest[];
  /** Routes that survived the envelope; `ProbeRequest.route_index` indexes this. */
  routes: RouteRecord[];
  skipped: PlanSkip[];
  /** True when the request ceiling cut the plan. Always reported. */
  truncated: boolean;
}
