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
 *   5. Every request URL is built by `buildProbeUrl` below and nowhere else.
 *      A `path_resolved` missing its leading slash (`api/users/`, a common
 *      shape from Django/Laravel/Rails/Spring extractors) concatenated onto
 *      `origin` as a bare string — the wrong implementation this replaces —
 *      produces a request to a DIFFERENT HOST (`http://localhostapi`, never
 *      `http://localhost/api`). `rateLimit.ts#buildBurst` shares this same
 *      helper for exactly the same reason: it is the one other place a
 *      request URL is composed, and its burst is credentialed, so an
 *      off-origin URL there leaks a credential to a host nobody authorised.
 */
import { PARAM_SYNTAX } from '../surface/specDiff.js';
export const READ_METHODS = ['GET', 'HEAD', 'OPTIONS'];
export const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
export const DEFAULT_MAX_REQUESTS = 750;
/**
 * The Origin sent by the CORS probe. `.invalid` is reserved by RFC 2606 and
 * can never resolve, so a server that reflects it back proves the reflection
 * without naming a domain anyone owns.
 */
export const CORS_PROBE_ORIGIN = 'https://dev-guardian-cors-probe.invalid';
const SYNTHETIC_PARAM_VALUE = '1';
/**
 * The one function that turns `(origin, path)` into a request URL — see rule
 * 5 above. Two steps, in order:
 *
 *   1. Normalise: a path missing its leading slash is prefixed with one. This
 *      alone fixes the common case (a framework path with no leading `/`)
 *      but is NOT the safety property — see step 2.
 *   2. Build via `new URL(path, origin)`, never string concatenation, and
 *      require `url.origin === origin`. This is what actually stops a
 *      protocol-relative path (`//evil.example/x`, a network-path reference
 *      per RFC 3986) from resolving to a different host: normalising its
 *      leading slash does nothing (it already has one), and only comparing
 *      the BUILT url's origin against the target catches it. A userinfo-style
 *      capture (`@evil.example/x`) is caught differently: `new URL` given an
 *      absolute-path argument can never reinterpret an `@` inside it as a
 *      userinfo separator the way naive string concatenation
 *      (`` `${origin}${path}` `` → `http://localhost@evil.example/x`) can, so
 *      step 1 alone already defuses it — step 2 is the backstop for
 *      everything step 1 does not.
 *
 * `path` is assumed non-partial (`path_partial: true` routes never reach
 * here — see rule 1). A partial path is not a URL at all, resolved or not.
 */
export function buildProbeUrl(origin, path) {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    let url;
    try {
        url = new URL(normalized, origin);
    }
    catch {
        return { ok: false, reason: 'off_origin' };
    }
    if (url.origin !== origin)
        return { ok: false, reason: 'off_origin' };
    return { ok: true, url: url.toString(), path: normalized };
}
export function planProbes(routes, opts) {
    const requests = [];
    const kept = [];
    const skipped = [];
    const seen = new Set();
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
        const { path: substituted, synthetic } = substituteParams(r.path_resolved);
        // Every URL this route could ever produce is built here, ONCE, before any
        // variant/method is planned — see rule 5. Off-origin excludes the whole
        // route, exactly like `partial_path` and `method_envelope` above: there
        // is no method-by-method distinction to make, since the URL a route
        // resolves to does not depend on which HTTP method probes it.
        const built = buildProbeUrl(opts.origin, substituted);
        if (!built.ok) {
            skipped.push({ method: r.method, path: r.path_resolved, reason: 'off_origin' });
            continue;
        }
        const path = built.path;
        // Dedupe at (method, path) granularity, NOT on the route's whole expanded
        // method set. Keying on the set gives `DELETE /users/1` and
        // `ANY /users/1` different keys, so both plan an anonymous DELETE at the
        // same URL: two destructive-shaped requests at a live target, sharing an
        // identical `id` that downstream correlation keys on. A spec declaring
        // `delete` alongside an `app.all()` in code produces exactly that pair.
        // (method, path) is also the natural granularity for `PlanSkip`, whose
        // own shape is `{ method, path, reason }`.
        const fresh = [];
        for (const method of methods) {
            if (seen.has(`${method} ${path}`)) {
                skipped.push({ method, path: r.path_resolved, reason: 'duplicate' });
            }
            else {
                fresh.push(method);
            }
        }
        const corsKey = `cors ${path}`;
        const needCors = !seen.has(corsKey);
        // Nothing new for this route: every method already planned and the path
        // already carries a cors probe.
        if (fresh.length === 0 && !needCors)
            continue;
        const routeIndex = kept.length;
        kept.push(r);
        for (const method of fresh) {
            seen.add(`${method} ${path}`);
            requests.push(build(method, path, built.url, 'anonymous', {}, synthetic, routeIndex));
            if (opts.authHeaderValue !== null) {
                requests.push(build(method, path, built.url, 'authenticated', { authorization: opts.authHeaderValue }, synthetic, routeIndex));
            }
        }
        if (needCors) {
            seen.add(corsKey);
            requests.push(build('GET', path, built.url, 'cors', { origin: CORS_PROBE_ORIGIN }, synthetic, routeIndex));
        }
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
function expandMethods(method, allowWrites) {
    if (method === 'ANY') {
        return allowWrites ? [...READ_METHODS, ...WRITE_METHODS] : [...READ_METHODS];
    }
    const isWrite = WRITE_METHODS.includes(method);
    if (isWrite && !allowWrites)
        return [];
    return [method];
}
/**
 * `url` is always the ALREADY-BUILT, already origin-checked result of
 * `buildProbeUrl` — this function never composes a URL itself, so there is
 * exactly one place in this file (and, via `rateLimit.ts#buildBurst`, in the
 * whole DAST engine) that can get that construction wrong.
 */
function build(method, path, url, variant, extraHeaders, synthetic, routeIndex) {
    const isWrite = WRITE_METHODS.includes(method);
    const req = {
        id: `${variant} ${method} ${path}`,
        method,
        path,
        url,
        headers: { accept: '*/*', ...extraHeaders },
        variant,
        synthetic_params: synthetic,
        route_index: routeIndex,
    };
    // Empty, never a crafted payload: the point is to learn whether authorization
    // rejects us BEFORE validation does, not to make the write succeed.
    if (isWrite)
        req.body = '';
    return req;
}
/**
 * Replace every path parameter with a synthetic value, reusing the parameter
 * syntaxes `specDiff` already knows. A path that needed substitution is
 * flagged `synthetic` — `analyze.ts` must never call such a route
 * "unreachable" on a 404, because a 404 there is ambiguous between "no such
 * route" and "no such record".
 */
export function substituteParams(path) {
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
//# sourceMappingURL=plan.js.map