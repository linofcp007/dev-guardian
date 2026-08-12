/**
 * The finding the rate-limit probe produces — and only the negative one. A
 * limiter that fired is a pass, not a finding; it is reported in the scan
 * summary instead.
 *
 * Why this lives here and not somewhere more obvious:
 *
 *   - Not in `rateLimit.ts`, which is the pure target-selection and verdict
 *     engine. This is the finding's severity and wording, a separate concern
 *     that changes for separate reasons.
 *   - Not in `analyze.ts`, which analyses `ProbeResult[]` from the main plan;
 *     the burst is planned, executed and judged outside that pipeline
 *     (`probe_rate_limit: true` is its own authorisation, scoped to one
 *     route).
 *   - Not in `tools/scanDast.ts`: the orchestrator holds no detection logic
 *     and no severity decisions (design §3).
 *
 * The wording is load-bearing. Design §11 forbids ever rewording this into
 * "rate limiting is missing": a limiter whose threshold sits above the burst
 * size is indistinguishable from none at this sample size, and the message a
 * reader actually sees has to say so. The two clauses "not proof" and
 * "indistinguishable" are pinned by test.
 */

import type { RouteRecord, Severity } from '../types.js';
import { dastFingerprint, dastRuleId, type DastFinding } from './analyze.js';

export const RATE_LIMIT_FINDING_TITLE = 'No rate limiting observed on an authentication endpoint';

/**
 * Between `anonymous_exposure` (high — a confirmed bypass) and a missing
 * security header (low — a hardening gap). An unlimited authentication
 * endpoint is a real credential-stuffing exposure, but the burst size bounds
 * what it can prove, which rules out anything higher.
 */
const RATE_LIMIT_SEVERITY: Severity = 'medium';

/** The method `rateLimit.ts#buildBurst` always sends, whatever the route says. */
const BURST_METHOD = 'POST';

export function noRateLimitObservedFinding(args: {
  route: RouteRecord;
  /** The resolved path actually burst (parameters already substituted). */
  path: string;
  /** The shared `ProbeRequest.id` of the burst. */
  evidenceId: string;
  /** Requests the target actually answered. */
  sent: number;
  /** Requests the burst was willing to send. */
  planned: number;
}): DastFinding {
  const { route, path, evidenceId, sent, planned } = args;
  return {
    fingerprint: dastFingerprint('rate_limit', BURST_METHOD, path, route.file),
    tool: 'dast',
    rule_id: dastRuleId('rate_limit', BURST_METHOD, path),
    severity: RATE_LIMIT_SEVERITY,
    category: 'security',
    subcategory: 'rate_limit',
    title: RATE_LIMIT_FINDING_TITLE,
    message:
      `${sent} of ${planned} identical ${BURST_METHOD} requests to ${path}, all carrying the same ` +
      `synthetic un-ownable credential, were answered without a 429 or a Retry-After header. ` +
      `This is not proof that rate limiting is missing: a limiter whose threshold sits above ` +
      `${sent} requests is indistinguishable from no limiter at all at this sample size.`,
    fix_available: false,
    file_path: route.file,
    line_start: route.line,
    check: 'rate_limit',
    evidence_id: evidenceId,
  };
}
