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
import { CORS_PROBE_ORIGIN, substituteParams } from './plan.js';
/**
 * The canonical `rule_id` shape for every DAST finding. Shared by
 * `dastFingerprint` and `buildFinding` so the string stored on the `Finding`
 * and the one fed to the hash can never drift apart.
 */
function dastRuleId(check, method, path) {
    return `${check}:${method}:${path}`;
}
/**
 * Fingerprint for a DAST finding. Stable over (check, method, path, file) —
 * design doc §8 — and deliberately excludes the HTTP status and response
 * body: a fixed app restarting and flipping 500 -> 200 must not spawn a "new"
 * finding, and surviving exactly that is this function's whole job.
 *
 * `line_start` is deliberately excluded too, even though the route it comes
 * from always has one (see `buildFinding`, which still puts it on the
 * `Finding` for display). Hashing it in means inserting one blank line above
 * a route registration — no behaviour change at all — makes every finding on
 * that route look brand new on the next scan. That destroys the diffability
 * the fingerprint exists to provide, the same reason the status code is
 * excluded. Do not "improve" this by adding it back in.
 */
export function dastFingerprint(check, method, path, file) {
    const fp = {
        tool: 'dast',
        rule_id: dastRuleId(check, method, path),
    };
    if (file !== undefined)
        fp.file_path = file;
    return computeFingerprint(fp);
}
/**
 * Every check funnels its finding through here so `evidence_id`, `rule_id`
 * and the fingerprint are always built the same way. `evidence_id` identifies
 * the probe request/response pair that produced the finding: it is exactly
 * the request's own `id`, never a counter or anything random, so it stays
 * deterministic across runs.
 */
function buildFinding(args) {
    const { check, severity, title, message, route, request } = args;
    const path = route?.path_resolved ?? request.path;
    const finding = {
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
function routeFor(routes, routeIndex) {
    return routeIndex === null ? undefined : routes[routeIndex];
}
/**
 * A route the inventory marked `auth_hint: 'required'` answering an anonymous
 * request with 2xx is a confirmed authentication bypass — the strongest
 * finding this tool can produce. `'unknown'` never fires: most routes carry no
 * declared auth requirement at all, and treating silence as a requirement
 * would light up every public homepage in existence.
 */
function checkAnonymousExposure(input, findings) {
    for (const r of input.results) {
        if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null)
            continue;
        if (r.status < 200 || r.status >= 300)
            continue;
        const route = routeFor(input.plan.routes, r.request.route_index);
        if (route === undefined || route.auth_hint !== 'required')
            continue;
        findings.push(buildFinding({
            check: 'anonymous_exposure',
            // 'high', not 'critical': auth_hint 'required' can be INHERITED from a
            // document-level OpenAPI `security` default, not just declared on the
            // operation (see `authHint` in surface/specImport.ts). A genuinely
            // public route whose author forgot `security: []` inherits 'required'
            // and would otherwise be reported as a critical auth bypass on a
            // homepage — severity inflation, which is over-reporting by another
            // name.
            severity: 'high',
            title: 'Auth-required route served anonymously',
            message: `${r.request.method} ${route.path_resolved} is marked auth_hint: 'required' in the ` +
                `route inventory but returned ${r.status} to a request carrying no credentials.`,
            route,
            request: r.request,
        }));
    }
}
/** Shared tail of `checkReachability`'s two branches. */
function reachabilityFinding(route, r, severity, title, message) {
    return buildFinding({ check: 'reachability', severity, title, message, route, request: r.request });
}
/**
 * Confirms what the static spec diff could only suspect. A 404 on a
 * synthetic-parameter path is ambiguous ("no such route" vs "no such record")
 * and must never produce a verdict either way — see `plan.ts#substituteParams`,
 * which is where `synthetic_params` comes from.
 */
function checkReachability(input, findings) {
    for (const r of input.results) {
        if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null)
            continue;
        const route = routeFor(input.plan.routes, r.request.route_index);
        if (route === undefined)
            continue;
        const live = r.status !== 404;
        if (!live && r.request.synthetic_params)
            continue;
        if (route.provenance === 'code' && live && input.shadowPaths.has(route.path_resolved)) {
            findings.push(reachabilityFinding(route, r, 'medium', 'Confirmed shadow endpoint', `${r.request.method} ${route.path_resolved} is undocumented in any spec but the ` +
                `running server answers it (status ${r.status}).`));
        }
        else if (route.provenance === 'spec' && input.deadDocPaths.has(route.path_resolved)) {
            if (live) {
                findings.push(reachabilityFinding(route, r, 'info', 'Extractor coverage gap', `${r.request.method} ${route.path_resolved} is documented and answers ` +
                    `(status ${r.status}), but the static extractor found no implementing code route — ` +
                    `a tooling gap, not dead documentation.`));
            }
            else {
                findings.push(reachabilityFinding(route, r, 'medium', 'Confirmed dead documentation', `${r.request.method} ${route.path_resolved} is documented but the running server ` +
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
function checkDifferentialAuthz(input, findings) {
    if (!input.hasCredentials)
        return;
    const anonByKey = new Map();
    for (const r of input.results) {
        if (r.request.variant === 'anonymous')
            anonByKey.set(`${r.request.method} ${r.request.path}`, r);
    }
    for (const authed of input.results) {
        if (authed.request.variant !== 'authenticated' || authed.outcome !== 'completed')
            continue;
        const anon = anonByKey.get(`${authed.request.method} ${authed.request.path}`);
        if (anon === undefined || anon.outcome !== 'completed' || anon.status === null)
            continue;
        if (anon.status < 200 || anon.status >= 300)
            continue;
        if (anon.status !== authed.status || anon.body_hash !== authed.body_hash)
            continue;
        const route = routeFor(input.plan.routes, anon.request.route_index);
        findings.push(buildFinding({
            check: 'differential_authz',
            severity: 'high',
            title: 'Anonymous response matches the authenticated response',
            message: `${anon.request.method} ${anon.request.path} returns a byte-identical response ` +
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
function checkCors(input, findings) {
    for (const r of input.results) {
        if (r.request.variant !== 'cors' || r.outcome !== 'completed')
            continue;
        const allowOrigin = r.headers['access-control-allow-origin'];
        const allowCreds = r.headers['access-control-allow-credentials'];
        if (allowOrigin === undefined || allowCreds?.toLowerCase() !== 'true')
            continue;
        const wildcard = allowOrigin === '*';
        if (!wildcard && allowOrigin !== CORS_PROBE_ORIGIN)
            continue;
        const route = routeFor(input.plan.routes, r.request.route_index);
        findings.push(buildFinding({
            check: 'cors',
            severity: 'critical',
            title: wildcard
                ? 'CORS allows any origin alongside credentials'
                : 'CORS reflects the request origin alongside credentials',
            message: `Access-Control-Allow-Origin: ${allowOrigin} combined with ` +
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
function checkOpenRedirect(input, findings) {
    for (const r of input.results) {
        if (r.request.variant !== 'anonymous' || r.outcome !== 'completed' || r.status === null)
            continue;
        if (r.status < 300 || r.status >= 400)
            continue;
        const location = r.headers['location'];
        if (location === undefined || location.trim() === '')
            continue;
        let resolved;
        try {
            resolved = new URL(location, r.request.url);
        }
        catch {
            continue;
        }
        if (resolved.origin === input.origin)
            continue;
        const route = routeFor(input.plan.routes, r.request.route_index);
        findings.push(buildFinding({
            check: 'open_redirect',
            severity: 'medium',
            title: 'Redirect leaves the target origin',
            message: `${r.status} on ${r.request.path} redirects to ${resolved.origin}, outside the ` +
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
function knownMethodsForPath(routes, path) {
    const known = new Set();
    for (const route of routes) {
        if (route.path_partial)
            continue;
        if (substituteParams(route.path_resolved).path !== path)
            continue;
        if (route.method === 'ANY')
            return null;
        known.add(route.method);
    }
    return known;
}
/**
 * The server admits a verb the static extractor never saw. Deduped per path:
 * the same `Allow` fact can surface on more than one probe to the same
 * resource, and repeating it would bury every other finding in the report.
 */
function checkMethodSurface(input, findings) {
    const reported = new Set();
    for (const r of input.results) {
        if (r.request.variant !== 'anonymous' || r.outcome !== 'completed')
            continue;
        const allow = r.headers['allow'];
        if (allow === undefined || allow.trim() === '' || reported.has(r.request.path))
            continue;
        const known = knownMethodsForPath(input.plan.routes, r.request.path);
        if (known === null)
            continue;
        const extra = allow.split(',').map((m) => m.trim().toUpperCase()).filter((m) => m !== '' && !known.has(m));
        if (extra.length === 0)
            continue;
        reported.add(r.request.path);
        const route = routeFor(input.plan.routes, r.request.route_index);
        findings.push(buildFinding({
            check: 'method_surface',
            severity: 'medium',
            title: 'Server answers an undocumented HTTP method',
            message: `Allow on ${r.request.path} advertises ${extra.join(', ')}, absent from the extracted ` +
                `route inventory.`,
            route,
            request: r.request,
        }));
    }
}
export function analyzeRoutes(input) {
    const findings = [];
    checkAnonymousExposure(input, findings);
    checkReachability(input, findings);
    checkDifferentialAuthz(input, findings);
    checkCors(input, findings);
    checkMethodSurface(input, findings);
    checkOpenRedirect(input, findings);
    return findings;
}
//# sourceMappingURL=analyze.js.map