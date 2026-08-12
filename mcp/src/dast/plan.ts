/**
 * Turn a route inventory into a concrete list of HTTP requests.
 *
 * This module is the safety envelope. Everything that stops `scan_dast` from
 * doing damage is a rule here, in a pure function, with a named test — not a
 * check scattered through the executor. A regression is then a failing test
 * rather than a live misfire against someone's staging database.
 *
 * The rules, in the order they apply:
 *   1. `path_partial: true` is never probed. The whole `unmatchable`
 *      discipline in `surface/specDiff.ts` exists because a DAST tool sends
 *      requests to whatever path it is handed; a templated or unresolved path
 *      is not a path.
 *   2. Write methods are dropped unless `allowWriteMethods`, and when allowed
 *      are sent with an empty body — the 400/422-vs-401/403 signal answers the
 *      authorization question without writing anything.
 *   3. `ANY` expands to whatever the envelope currently permits — three read
 *      methods by default, all seven with writes on. It is the most permissive
 *      surface in a project, so under-probing it hides the most.
 *   4. Duplicates collapse; the cap truncates. Both are reported, never
 *      silently applied.
 */

import { PARAM_SYNTAX } from '../surface/specDiff.js';
import type { HttpMethod, RouteRecord } from '../types.js';
import type { PlanOutcome, PlanSkip, ProbeRequest, ProbeVariant } from './types.js';

export const READ_METHODS = ['GET', 'HEAD', 'OPTIONS'] as const;
export const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;
export const DEFAULT_MAX_REQUESTS = 750;

/**
 * The Origin sent by the CORS probe. `.invalid` is reserved by RFC 2606 and
 * can never resolve, so a server that reflects it back proves the reflection
 * without naming a domain anyone owns.
 */
export const CORS_PROBE_ORIGIN = 'https://dev-guardian-cors-probe.invalid';

const SYNTHETIC_PARAM_VALUE = '1';

export interface PlanOptions {
  origin: string;
  allowWriteMethods: boolean;
  /** Already resolved from `auth_header_env` by the caller; never a var name. */
  authHeaderValue: string | null;
  maxRequests: number;
}

export function planProbes(
  routes: readonly RouteRecord[],
  opts: PlanOptions,
): PlanOutcome {
  const requests: ProbeRequest[] = [];
  const kept: RouteRecord[] = [];
  const skipped: PlanSkip[] = [];
  const seen = new Set<string>();

  for (const r of routes) {
    if (r.path_partial) {
      skipped.push({ method: r.method, path: r.path_resolved, reason: 'partial_path' });
      continue;
    }

    const methods = expandMethods(r.method, opts.allowWriteMethods);
    if (methods.length === 0) {
      skipped.push({ method: r.method, path: r.path_resolved, reason: 'method_envelope' });
      continue;
    }

    const { path, synthetic } = substituteParams(r.path_resolved);
    const dedupeKey = `${methods.join(',')} ${path}`;
    if (seen.has(dedupeKey)) {
      skipped.push({ method: r.method, path: r.path_resolved, reason: 'duplicate' });
      continue;
    }
    seen.add(dedupeKey);

    const routeIndex = kept.length;
    kept.push(r);

    for (const method of methods) {
      requests.push(build(method, path, 'anonymous', {}, opts, synthetic, routeIndex));
      if (opts.authHeaderValue !== null) {
        requests.push(
          build(
            method,
            path,
            'authenticated',
            { authorization: opts.authHeaderValue },
            opts,
            synthetic,
            routeIndex,
          ),
        );
      }
    }
    requests.push(
      build('GET', path, 'cors', { origin: CORS_PROBE_ORIGIN }, opts, synthetic, routeIndex),
    );
  }

  if (requests.length <= opts.maxRequests) {
    return { requests, routes: kept, skipped, truncated: false };
  }

  const cut = requests.slice(opts.maxRequests);
  for (const r of cut) {
    skipped.push({ method: r.method, path: r.path, reason: 'cap' });
  }
  return {
    requests: requests.slice(0, opts.maxRequests),
    routes: kept,
    skipped,
    truncated: true,
  };
}

function expandMethods(
  method: HttpMethod,
  allowWrites: boolean,
): Exclude<HttpMethod, 'ANY'>[] {
  if (method === 'ANY') {
    return allowWrites ? [...READ_METHODS, ...WRITE_METHODS] : [...READ_METHODS];
  }
  const isWrite = (WRITE_METHODS as readonly string[]).includes(method);
  if (isWrite && !allowWrites) return [];
  return [method];
}

function build(
  method: Exclude<HttpMethod, 'ANY'>,
  path: string,
  variant: ProbeVariant,
  extraHeaders: Record<string, string>,
  opts: PlanOptions,
  synthetic: boolean,
  routeIndex: number,
): ProbeRequest {
  const isWrite = (WRITE_METHODS as readonly string[]).includes(method);
  const req: ProbeRequest = {
    id: `${variant} ${method} ${path}`,
    method,
    path,
    url: `${opts.origin}${path}`,
    headers: { accept: '*/*', ...extraHeaders },
    variant,
    synthetic_params: synthetic,
    route_index: routeIndex,
  };
  // Empty, never a crafted payload: the point is to learn whether authorization
  // rejects us BEFORE validation does, not to make the write succeed.
  if (isWrite) req.body = '';
  return req;
}

/**
 * Replace every path parameter with a synthetic value, reusing the parameter
 * syntaxes `specDiff` already knows. A path that needed substitution is
 * flagged `synthetic` — `analyze.ts` must never call such a route
 * "unreachable" on a 404, because a 404 there is ambiguous between "no such
 * route" and "no such record".
 */
export function substituteParams(path: string): { path: string; synthetic: boolean } {
  let out = path;
  let synthetic = false;
  for (const pattern of PARAM_SYNTAX) {
    // A fresh RegExp per use: the shared patterns are module-level objects
    // with the `g` flag, and cloning removes any dependence on their
    // `lastIndex` state being where this function assumes it is.
    const re = new RegExp(pattern.source, pattern.flags);
    out = out.replace(re, () => {
      synthetic = true;
      return SYNTHETIC_PARAM_VALUE;
    });
  }
  return { path: out, synthetic };
}
