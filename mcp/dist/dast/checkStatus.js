/**
 * Per-check status for a DAST run. Pure — this is bookkeeping about whether a
 * check could run at all, not detection: it never inspects a response body or
 * decides anything is wrong.
 *
 * Design §9 is the whole point of this module: "a check that never ran is
 * visible as such rather than as a check that found nothing". Every check
 * therefore reports a status even when it produced no findings, and `ok` is
 * the only value that means "this check ran, and what it found is what there
 * is" (see `CheckStatus`'s doc comment in `types.ts`).
 *
 * Which value goes where:
 *
 *   - **Nothing to run the check against** (`cors` when no CORS probe was
 *     planned, `anonymous_exposure` when no route declares `auth_hint:
 *     'required'`, `reachability` when the snapshot carries no spec diff) is
 *     `no_candidate`.
 *   - **Gated off by the envelope** — the rate-limit burst without
 *     `probe_rate_limit`, nuclei without `use_nuclei` — is `skipped_envelope`.
 *   - **The engine that performs the check is not installed** — nuclei
 *     requested and unresolvable — is `scanner_missing`, never
 *     `skipped_envelope`: the envelope did not exclude it, a missing binary
 *     did. The fuller cause is still reported in `tools_run` (status
 *     `skipped`, with the reason), in `missing_tools`, and through the
 *     resulting `coverage: 'partial'`.
 *   - **The check had candidates and the target answered none of them** —
 *     probes planned, none completed — is `target_error`. That must never
 *     round down to "found nothing".
 *
 * One ambiguity this vocabulary cannot express on its own: probes cut by the
 * scan's wall-clock ceiling record `outcome: 'cancelled'`, so a check whose
 * every probe was cut reads `target_error` even though the target was never
 * at fault. The orchestrator resolves it out of band — `summary.timed_out`,
 * `summary.probes_cut`, a degraded `coverage`, and a warning that says in
 * words that a `target_error` after a time cut may simply mean the probe was
 * never sent.
 */
import { DAST_CHECKS } from './types.js';
/**
 * `no_candidate` when nothing was planned for this check, `ok` when at least
 * one of its probes came back, `target_error` when probes were planned and
 * none of them did. The three are genuinely different and collapsing any two
 * is how "the target was down" starts reading as "the target was clean".
 */
function fromProbes(planned, completed) {
    if (!planned)
        return 'no_candidate';
    return completed ? 'ok' : 'target_error';
}
export function computeCheckStatuses(input) {
    const { plan, results } = input;
    const plannedAnonymous = plan.requests.some((r) => r.variant === 'anonymous');
    const completedAnonymous = results.some((r) => r.request.variant === 'anonymous' && r.outcome === 'completed');
    const plannedAuthenticated = plan.requests.some((r) => r.variant === 'authenticated');
    const completedAuthenticated = results.some((r) => r.request.variant === 'authenticated' && r.outcome === 'completed');
    const plannedCors = plan.requests.some((r) => r.variant === 'cors');
    const completedCors = results.some((r) => r.request.variant === 'cors' && r.outcome === 'completed');
    const plannedAny = plan.requests.length > 0;
    const completedAny = results.some((r) => r.outcome === 'completed');
    const anonymousExposureCandidates = plan.routes.some((r) => r.auth_hint === 'required');
    const statuses = {
        reachability: fromProbes(input.hasSpecDiff && plannedAnonymous, completedAnonymous),
        anonymous_exposure: fromProbes(anonymousExposureCandidates && plannedAnonymous, completedAnonymous),
        differential_authz: !input.hasCredentials
            ? 'needs_credentials'
            : fromProbes(plannedAuthenticated, completedAuthenticated),
        cors: fromProbes(plannedCors, completedCors),
        security_headers: fromProbes(plannedAny, completedAny),
        info_disclosure: fromProbes(plannedAny, completedAny),
        method_surface: fromProbes(plannedAnonymous, completedAnonymous),
        open_redirect: fromProbes(plannedAnonymous, completedAnonymous),
        rate_limit: rateLimitStatus(input.rateLimit),
        nuclei: nucleiStatus(input.nuclei),
    };
    // Belt and braces against a future `DastCheck` value being added and
    // silently missing from the map above — a check absent from the result is
    // exactly as invisible as one reported `ok`.
    for (const check of DAST_CHECKS) {
        if (statuses[check] === undefined)
            throw new Error(`No status computed for check '${check}'`);
    }
    return statuses;
}
function rateLimitStatus(outcome) {
    switch (outcome) {
        case 'not_requested':
            return 'skipped_envelope';
        case 'no_candidate':
            return 'no_candidate';
        case 'no_response':
            return 'target_error';
        case 'ran':
            return 'ok';
    }
}
function nucleiStatus(outcome) {
    switch (outcome) {
        case 'not_requested':
            return 'skipped_envelope';
        case 'unavailable':
            return 'scanner_missing';
        case 'failed':
            return 'target_error';
        case 'ran':
            return 'ok';
    }
}
//# sourceMappingURL=checkStatus.js.map