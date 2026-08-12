/**
 * Turn probe results into findings. Pure — no I/O, no clock, no randomness.
 *
 * Severity is a property of the check, not of the response: an auth-required
 * route served anonymously is critical whether it returned 200 or 206.
 *
 * Every check here is written to under-report rather than over-report. A DAST
 * finding is an accusation about a running system; a fabricated one costs the
 * reader more than a missed one, and the two previous features in this
 * sub-project were spent removing values that had acquired the appearance of
 * being known.
 */

import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import type { Finding, RouteRecord, Severity } from '../types.js';
import { CORS_PROBE_ORIGIN, substituteParams } from './plan.js';
import type { DastCheck, PlanOutcome, ProbeRequest, ProbeResult } from './types.js';

export interface AnalyzeInput {
  plan: PlanOutcome;
  results: readonly ProbeResult[];
  origin: string;
  /** From the surface snapshot's spec diff: paths the code has and no spec documents. */
  shadowPaths: ReadonlySet<string>;
  /** Paths a spec declares and the code does not implement. */
  deadDocPaths: ReadonlySet<string>;
  hasCredentials: boolean;
}

export interface DastFinding extends Finding {
  check: DastCheck;
  evidence_id: string;
}

/**
 * The canonical `rule_id` shape for every DAST finding. Shared by
 * `dastFingerprint` and `buildFinding` so the string stored on the `Finding`
 * and the one fed to the hash can never drift apart.
 */
function dastRuleId(check: DastCheck, method: string, path: string): string {
  return `${check}:${method}:${path}`;
}

/**
 * Fingerprint for a DAST finding. Stable over (check, method, path, file) —
 * design doc §8 — and deliberately excludes the HTTP status and response
 * body: a fixed app restarting and flipping 500 -> 200 must not spawn a "new"
 * finding, and surviving exactly that is this function's whole job.
 */
export function dastFingerprint(
  check: DastCheck,
  method: string,
  path: string,
  file?: string,
): string {
  const fp: Parameters<typeof computeFingerprint>[0] = {
    tool: 'dast',
    rule_id: dastRuleId(check, method, path),
  };
  if (file !== undefined) fp.file_path = file;
  return computeFingerprint(fp);
}

interface BuildFindingArgs {
  check: DastCheck;
  severity: Severity;
  title: string;
  message: string;
  route: RouteRecord | undefined;
  request: ProbeRequest;
}

/**
 * Every check funnels its finding through here so `evidence_id`, `rule_id`
 * and the fingerprint are always built the same way. `evidence_id` identifies
 * the probe request/response pair that produced the finding: it is exactly
 * the request's own `id`, never a counter or anything random, so it stays
 * deterministic across runs.
 */
function buildFinding(args: BuildFindingArgs): DastFinding {
  const { check, severity, title, message, route, request } = args;
  const path = route?.path_resolved ?? request.path;
  const finding: DastFinding = {
    fingerprint: dastFingerprint(check, request.method, path, route?.file),
    tool: 'dast',
    rule_id: dastRuleId(check, request.method, path),
    severity,
    category: 'security',
    subcategory: check,
    title,
    message,
    fix_available: false,
    check,
    evidence_id: request.id,
  };
  if (route !== undefined) {
    finding.file_path = route.file;
    finding.line_start = route.line;
  }
  return finding;
}

function routeFor(
  routes: readonly RouteRecord[],
  routeIndex: number | null,
): RouteRecord | undefined {
  return routeIndex === null ? undefined : routes[routeIndex];
}

/**
 * A route the inventory marked `auth_hint: 'required'` answering an anonymous
 * request with 2xx is a confirmed authentication bypass — the strongest
 * finding this tool can produce. `'unknown'` never fires: most routes carry no
 * declared auth requirement at all, and treating silence as a requirement
 * would light up every public homepage in existence.
 */
function checkAnonymousExposure(input: AnalyzeInput, findings: DastFinding[]): void {
  for (const r of input.results) {
    if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null) continue;
    if (r.status < 200 || r.status >= 300) continue;
    const route = routeFor(input.plan.routes, r.request.route_index);
    if (route === undefined || route.auth_hint !== 'required') continue;

    findings.push(buildFinding({
      check: 'anonymous_exposure',
      severity: 'critical',
      title: 'Auth-required route served anonymously',
      message:
        `${r.request.method} ${route.path_resolved} is marked auth_hint: 'required' in the ` +
        `route inventory but returned ${r.status} to a request carrying no credentials.`,
      route,
      request: r.request,
    }));
  }
}

/** Shared tail of `checkReachability`'s two branches. */
function reachabilityFinding(
  route: RouteRecord,
  r: ProbeResult,
  severity: Severity,
  title: string,
  message: string,
): DastFinding {
  return buildFinding({ check: 'reachability', severity, title, message, route, request: r.request });
}

/**
 * Confirms what the static spec diff could only suspect. A 404 on a
 * synthetic-parameter path is ambiguous ("no such route" vs "no such record")
 * and must never produce a verdict either way — see `plan.ts#substituteParams`,
 * which is where `synthetic_params` comes from.
 */
function checkReachability(input: AnalyzeInput, findings: DastFinding[]): void {
  for (const r of input.results) {
    if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null) continue;
    const route = routeFor(input.plan.routes, r.request.route_index);
    if (route === undefined) continue;

    const live = r.status !== 404;
    if (!live && r.request.synthetic_params) continue;

    if (route.provenance === 'code' && live && input.shadowPaths.has(route.path_resolved)) {
      findings.push(reachabilityFinding(route, r, 'medium', 'Confirmed shadow endpoint',
        `${r.request.method} ${route.path_resolved} is undocumented in any spec but the ` +
        `running server answers it (status ${r.status}).`));
    } else if (route.provenance === 'spec' && input.deadDocPaths.has(route.path_resolved)) {
      if (live) {
        findings.push(reachabilityFinding(route, r, 'info', 'Extractor coverage gap',
          `${r.request.method} ${route.path_resolved} is documented and answers ` +
          `(status ${r.status}), but the static extractor found no implementing code route — ` +
          `a tooling gap, not dead documentation.`));
      } else {
        findings.push(reachabilityFinding(route, r, 'medium', 'Confirmed dead documentation',
          `${r.request.method} ${route.path_resolved} is documented but the running server ` +
          `returns 404.`));
      }
    }
  }
}

/**
 * Broken authorization confirmed without needing a spec at all: if the
 * response to the same request is byte-identical with and without a
 * credential, the credential is not being checked. Equality only, never a
 * similarity score — timestamps and CSRF tokens make near-duplicates cheap to
 * produce, and that noise must cost a missed finding, never a fabricated one.
 */
function checkDifferentialAuthz(input: AnalyzeInput, findings: DastFinding[]): void {
  if (!input.hasCredentials) return;
  const anonByKey = new Map<string, ProbeResult>();
  for (const r of input.results) {
    if (r.request.variant === 'anonymous') anonByKey.set(`${r.request.method} ${r.request.path}`, r);
  }

  for (const authed of input.results) {
    if (authed.request.variant !== 'authenticated' || authed.outcome !== 'completed') continue;
    const anon = anonByKey.get(`${authed.request.method} ${authed.request.path}`);
    if (anon === undefined || anon.outcome !== 'completed' || anon.status === null) continue;
    if (anon.status < 200 || anon.status >= 300) continue;
    if (anon.status !== authed.status || anon.body_hash !== authed.body_hash) continue;

    const route = routeFor(input.plan.routes, anon.request.route_index);
    findings.push(buildFinding({
      check: 'differential_authz',
      severity: 'high',
      title: 'Anonymous response matches the authenticated response',
      message:
        `${anon.request.method} ${anon.request.path} returns a byte-identical response ` +
        `(status ${anon.status}) with and without credentials.`,
      route,
      request: anon.request,
    }));
  }
}

/**
 * The one CORS shape that matters: a browser only exposes a credentialed
 * response to a page on another origin when the server BOTH reflects that
 * origin (or wildcards it) AND opts in to credentials. Either alone is inert,
 * so both are required — reflecting an origin with no credentials flag is the
 * ordinary, safe way to serve a public API. Matching against `CORS_PROBE_ORIGIN`
 * specifically (never any non-wildcard value the server happens to return) is
 * what makes "reflected" provable: a fixed real domain the server always
 * returns could be a legitimate trusted-partner allowlist, not a reflection.
 */
function checkCors(input: AnalyzeInput, findings: DastFinding[]): void {
  for (const r of input.results) {
    if (r.request.variant !== 'cors' || r.outcome !== 'completed') continue;
    const allowOrigin = r.headers['access-control-allow-origin'];
    const allowCreds = r.headers['access-control-allow-credentials'];
    if (allowOrigin === undefined || allowCreds?.toLowerCase() !== 'true') continue;
    const wildcard = allowOrigin === '*';
    if (!wildcard && allowOrigin !== CORS_PROBE_ORIGIN) continue;

    const route = routeFor(input.plan.routes, r.request.route_index);
    findings.push(buildFinding({
      check: 'cors',
      severity: 'critical',
      title: wildcard
        ? 'CORS allows any origin alongside credentials'
        : 'CORS reflects the request origin alongside credentials',
      message:
        `Access-Control-Allow-Origin: ${allowOrigin} combined with ` +
        `Access-Control-Allow-Credentials: true lets a page on any origin read this response ` +
        `with the caller's credentials attached.`,
      route,
      request: r.request,
    }));
  }
}

/**
 * `Location` is resolved against the request URL before comparison — a
 * relative value is same-origin by construction and must not fire. An
 * unparseable `Location` is not a finding either; it is not evidence of
 * anything. Manual redirects (`probe.ts` never follows one) are what makes
 * this observable at all.
 */
function checkOpenRedirect(input: AnalyzeInput, findings: DastFinding[]): void {
  for (const r of input.results) {
    if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null) continue;
    if (r.status < 300 || r.status >= 400) continue;
    const location = r.headers['location'];
    if (location === undefined || location.trim() === '') continue;

    let resolved: URL;
    try {
      resolved = new URL(location, r.request.url);
    } catch {
      continue;
    }
    if (resolved.origin === input.origin) continue;

    const route = routeFor(input.plan.routes, r.request.route_index);
    findings.push(buildFinding({
      check: 'open_redirect',
      severity: 'medium',
      title: 'Redirect leaves the target origin',
      message:
        `${r.status} on ${r.request.path} redirects to ${resolved.origin}, outside the ` +
        `target origin.`,
      route,
      request: r.request,
    }));
  }
}

/**
 * `null` means an `ANY` route already covers this path — an `ANY` route means
 * the server was already known to answer any verb, so nothing `Allow` says is
 * news. Otherwise the union of concrete methods the inventory declares for
 * the path, computed through the same `substituteParams` the planner used, so
 * `/users/1` matches an inventory entry at `/users/{id}`.
 */
function knownMethodsForPath(routes: readonly RouteRecord[], path: string): Set<string> | null {
  const known = new Set<string>();
  for (const route of routes) {
    if (route.path_partial) continue;
    if (substituteParams(route.path_resolved).path !== path) continue;
    if (route.method === 'ANY') return null;
    known.add(route.method);
  }
  return known;
}

/**
 * The server admits a verb the static extractor never saw. Deduped per path:
 * the same `Allow` fact can surface on more than one probe to the same
 * resource, and repeating it would bury every other finding in the report.
 */
function checkMethodSurface(input: AnalyzeInput, findings: DastFinding[]): void {
  const reported = new Set<string>();
  for (const r of input.results) {
    if (r.request.variant !== 'anonymous' || r.outcome !== 'completed') continue;
    const allow = r.headers['allow'];
    if (allow === undefined || allow.trim() === '' || reported.has(r.request.path)) continue;

    const known = knownMethodsForPath(input.plan.routes, r.request.path);
    if (known === null) continue;
    const extra = allow.split(',').map((m) => m.trim().toUpperCase()).filter((m) => m !== '' && !known.has(m));
    if (extra.length === 0) continue;
    reported.add(r.request.path);

    const route = routeFor(input.plan.routes, r.request.route_index);
    findings.push(buildFinding({
      check: 'method_surface',
      severity: 'medium',
      title: 'Server answers an undocumented HTTP method',
      message:
        `Allow on ${r.request.path} advertises ${extra.join(', ')}, absent from the extracted ` +
        `route inventory.`,
      route,
      request: r.request,
    }));
  }
}

export function analyzeRoutes(input: AnalyzeInput): DastFinding[] {
  const findings: DastFinding[] = [];
  checkAnonymousExposure(input, findings);
  checkReachability(input, findings);
  checkDifferentialAuthz(input, findings);
  checkCors(input, findings);
  checkMethodSurface(input, findings);
  checkOpenRedirect(input, findings);
  return findings;
}
