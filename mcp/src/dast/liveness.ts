/**
 * The liveness probe — one request that answers "is anything there?".
 *
 * It exists so that "nothing is listening at base_url" comes back as its own
 * refusal (`target_not_found`) instead of as a scan whose every probe timed
 * out and whose every check therefore found nothing. A dead target and a
 * clean target must never render alike.
 *
 * Its result is deliberately NOT fed into `analyze.ts`. It is a connectivity
 * check aimed at `/`, a path the route inventory may never have listed;
 * letting it reach the checks would produce findings about a path nobody
 * asked to probe (an `Allow` header at `/` would fire `method_surface`
 * against an empty known-method set, for one).
 */

import type { ProbeRequest, ProbeResult, TargetDecision } from './types.js';

export function livenessRequest(origin: string): ProbeRequest {
  return {
    // `ProbeVariant` has no 'liveness' member, and this request never reaches
    // the analyser, so 'anonymous' is a label here and nothing more.
    id: 'liveness GET /',
    method: 'GET',
    path: '/',
    url: `${origin}/`,
    headers: { accept: '*/*' },
    variant: 'anonymous',
    synthetic_params: false,
    route_index: null,
  };
}

/**
 * Names the origin, says which way it failed, and says explicitly that this
 * is a refusal rather than an empty result — the sentence a reader needs when
 * an agent relays "scan_dast returned nothing".
 */
export function livenessMessage(
  target: TargetDecision,
  liveness: ProbeResult,
  timeoutMs: number,
): string {
  const detail =
    liveness.outcome === 'timeout'
      ? `nothing answered within ${timeoutMs}ms`
      : `the connection failed (${liveness.error ?? 'no detail'})`;
  return (
    `Nothing is listening at ${target.origin} — ${detail}. Start the application first, then ` +
    're-run scan_dast. This is a refusal, not a scan that found no problems: no probes were ' +
    'sent and nothing was recorded.'
  );
}
