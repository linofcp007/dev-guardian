/**
 * The rate-limit probe: the one check that crosses the write envelope.
 *
 * `probe_rate_limit: true` is ITSELF the authorization for this burst, scoped
 * to exactly one route. It does not open write methods for any other check.
 *
 * The burst is thirty identical requests carrying a synthetic, un-ownable
 * username — never a dictionary, never a real account. Guessing real
 * credentials would lock out the very account whose lockout control is being
 * measured, and answers "is there a limiter?" no better than this does.
 *
 * The absence of a 429 across the burst is reported as `no_rate_limit_observed`
 * and never as "rate limiting is missing": a limiter whose threshold sits above
 * the burst size is indistinguishable from none at this sample size, and the
 * finding has to say so.
 */

import type { HttpMethod, RouteRecord } from '../types.js';
import { substituteParams } from './plan.js';
import type { ProbeRequest, ProbeResult } from './types.js';

export const RATE_LIMIT_BURST = 30;

export const AUTH_PATH_HINTS = [
  'login', 'signin', 'sign-in', 'auth', 'authenticate', 'token', 'session', 'oauth',
] as const;

/**
 * The synthetic credential pair every burst request carries. `.invalid` is a
 * reserved TLD (RFC 2606): it can never resolve and no one can register an
 * account under it, so this username cannot collide with a real one no
 * matter what the target's user base looks like — see `buildBurst`'s doc
 * comment for the full trace. The trailing digit is a fixed literal, not a
 * per-request counter: the whole burst must be byte-identical (this is a
 * limiter probe, not a guessing attack), so nothing here may vary by request
 * index, wall-clock time, or randomness.
 */
const SYNTHETIC_USERNAME = 'dev-guardian-probe-1@invalid';
const SYNTHETIC_PASSWORD = 'dev-guardian-probe';

/**
 * Explicit-first target selection. A caller who names `rate_limit_path` gets
 * exactly that route probed, or nothing at all. The wrong implementation
 * falls back to inference when the named path is not in the inventory,
 * which silently bursts a different endpoint than the one the caller
 * asked about — worse than refusing, because the operator believes the
 * named route was the one tested. Inference only runs when the caller named
 * nothing, and additionally requires the candidate be `isWriteCapable` —
 * see that function's doc comment for why a path match alone is not enough.
 * `path_partial` routes are never selectable either way: they are not a
 * usable URL path (see `RouteRecord.path_partial`), so there is nothing a
 * burst could be aimed at.
 *
 * The explicit branch applies no method filter. A caller who names an exact
 * path has made a deliberate choice; the same reasoning that already sends
 * a named-but-absent path to `null` rather than a substitute bounds the
 * risk here too, and second-guessing a deliberate, named choice is a
 * different (and worse) failure than refusing an inferred guess.
 */
export function selectRateLimitTarget(
  routes: readonly RouteRecord[],
  explicitPath: string | null,
): { route: RouteRecord; inferred: boolean } | null {
  if (explicitPath !== null) {
    const named = routes.find((r) => !r.path_partial && r.path_resolved === explicitPath);
    return named === undefined ? null : { route: named, inferred: false };
  }
  const guessed = routes.find(
    (r) => !r.path_partial && looksLikeAuthPath(r.path_resolved) && isWriteCapable(r.method),
  );
  return guessed === undefined ? null : { route: guessed, inferred: true };
}

/**
 * Whole-segment equality against `AUTH_PATH_HINTS`, never a substring test.
 * `auth` and `authenticate` are both listed on purpose: if matching were
 * substring-based, `authenticate` would be redundant (it already contains
 * `auth`) and the hint would also fire on unrelated paths like `/authors`.
 * A path segment must equal a whole hint.
 */
function looksLikeAuthPath(path: string): boolean {
  const segments = path.toLowerCase().split('/');
  return AUTH_PATH_HINTS.some((hint) => segments.includes(hint));
}

/**
 * Methods structurally capable of answering `buildBurst`'s hardcoded POST.
 * A server-rendered login PAGE — `{ method: 'GET', path_resolved: '/login' }`
 * — matches `AUTH_PATH_HINTS` on path alone exactly as well as the form
 * handler that actually checks credentials, but a GET-only route cannot be
 * that handler. Inferring it anyway sends the burst to a route the
 * target's own router rejects before the request ever reaches
 * authentication code: thirty 404s or 405s, never a 429 — a
 * confident-shaped `{ observed: false, sent: 30 }` produced by a
 * methodologically empty test, indistinguishable from a genuine negative to
 * anything reading `rateLimitVerdict`'s output. `ANY` qualifies: an
 * `app.all()`-style route answers POST by construction.
 */
const WRITE_CAPABLE_METHODS: readonly string[] = ['POST', 'PUT', 'PATCH', 'DELETE', 'ANY'];

function isWriteCapable(method: HttpMethod): boolean {
  return WRITE_CAPABLE_METHODS.includes(method);
}

/**
 * `size` identical requests, method always `POST` regardless of what the
 * inventory recorded for this route. The credential pair is only meaningful
 * as a write, and `probe.ts` drops the body entirely on `GET`/`HEAD`
 * requests; echoing whatever method the static extractor happened to record
 * — including `ANY`, which `ProbeRequest.method` cannot even represent —
 * would risk silently turning the burst into a bodiless no-op against a
 * mis-tagged or verb-agnostic route. `path` is resolved through
 * `substituteParams`, the same helper `plan.ts` uses, so a parameterised
 * auth path (`/orgs/{orgId}/login`) is never sent to the target with a
 * literal, unresolved placeholder still in it.
 *
 * Every one of the `size` requests is a distinct object but carries the
 * exact same id/method/path/url/headers/body — see `SYNTHETIC_USERNAME`'s
 * doc comment for why the body in particular must never vary.
 */
export function buildBurst(route: RouteRecord, origin: string, size: number): ProbeRequest[] {
  const { path, synthetic } = substituteParams(route.path_resolved);
  const body = JSON.stringify({ username: SYNTHETIC_USERNAME, password: SYNTHETIC_PASSWORD });
  const id = `rate_limit POST ${path}`;
  return Array.from({ length: size }, () => ({
    id,
    method: 'POST',
    path,
    url: `${origin}${path}`,
    headers: { accept: '*/*', 'content-type': 'application/json' },
    body,
    variant: 'rate_limit',
    synthetic_params: synthetic,
    route_index: null,
  }));
}

/**
 * `429` is the status IANA/RFC 6585 reserve for "too many requests" and
 * counts on its own, `Retry-After` or not — real limiters routinely omit
 * that header. `503` counts only alongside `Retry-After`: unlike `429`, a
 * bare `503` ("Service Unavailable") is generic and shows up for reasons
 * that have nothing to do with a limiter, so treating it as one without
 * `Retry-After` would fabricate a finding the response never supported.
 */
function isLimiterSignal(r: ProbeResult): boolean {
  if (r.status === 429) return true;
  return r.status === 503 && r.headers['retry-after'] !== undefined;
}

/**
 * Works on however many results it is given — never assumes the full burst
 * ran. The orchestrator stops the burst early on the first `429`, so a
 * 3-element array here can be the entire story for a fast-tripping limiter.
 * `sent` (the not-observed branch only) counts `completed` results alone: a
 * `network_error` or `timeout` is not a request the target ever answered,
 * and folding it in would overstate how many chances the limiter got to
 * fire.
 */
export function rateLimitVerdict(
  results: readonly ProbeResult[],
): { observed: true; at_request: number } | { observed: false; sent: number } {
  let sent = 0;
  for (const r of results) {
    if (r.outcome !== 'completed') continue;
    sent += 1;
    if (isLimiterSignal(r)) return { observed: true, at_request: sent };
  }
  return { observed: false, sent };
}
