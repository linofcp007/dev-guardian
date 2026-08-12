/**
 * The two opt-in passes, both of which run outside the main
 * plan → probe → analyse pipeline and each of which is separately
 * rejectable: the rate-limit burst and the nuclei run.
 *
 * They live together, and outside `tools/scanDast.ts`, because they are the
 * two riskiest things this tool does — one crosses the write envelope, the
 * other spawns an external active scanner — and each deserves to be read on
 * its own rather than buried in the middle of a ten-step orchestration.
 *
 * Neither holds detection logic. The burst's verdict comes from
 * `rateLimit.ts#rateLimitVerdict`, its finding from `rateLimitFinding.ts`,
 * and nuclei's findings from `normalizeNuclei.ts`; what is here is I/O,
 * sequencing and honest reporting of what did or did not run.
 */
import { join } from 'node:path';
import { buildBurstEvidence } from './evidence.js';
import { invokeNuclei } from './nuclei.js';
import { normalizeNucleiJsonl } from './normalizeNuclei.js';
import { substituteParams } from './plan.js';
import { executeProbe } from './probe.js';
import { buildBurst, rateLimitVerdict, selectRateLimitTarget, RATE_LIMIT_BURST } from './rateLimit.js';
import { noRateLimitObservedFinding } from './rateLimitFinding.js';
/** Wall-clock ceiling for the whole nuclei pass, not per template. */
export const NUCLEI_TIMEOUT_MS = 300_000;
/**
 * Sequential on purpose, not merely "within the concurrency cap". Running the
 * burst one request at a time makes `rateLimitVerdict`'s `at_request` mean
 * what it says — with parallel lanes the request the target answers 429 is
 * not the one sitting at that index in the results array — and it keeps the
 * one check that crosses the write envelope from also being the heaviest
 * traffic the scan sends. It stops the moment a limiter answers: a working
 * limiter costs a handful of requests, not thirty.
 *
 * `sent === 0` (the target answered none of the burst) is `no_response`, not
 * a finding. "No 429 was seen" would be literally true and worthless there —
 * nothing was measured.
 */
export async function runRateLimitBurst(opts) {
    const empty = {
        outcome: 'not_requested',
        finding: null,
        summary: null,
        evidence: new Map(),
    };
    if (!opts.requested)
        return empty;
    const selected = selectRateLimitTarget(opts.routes, opts.explicitPath);
    if (selected === null)
        return { ...empty, outcome: 'no_candidate' };
    const requests = buildBurst(selected.route, opts.origin, RATE_LIMIT_BURST);
    const burstResults = [];
    for (const request of requests) {
        const result = await executeProbe(request, opts.probeOpts);
        burstResults.push(result);
        if (rateLimitVerdict([result]).observed)
            break;
        if (opts.aborted())
            break;
    }
    const verdict = rateLimitVerdict(burstResults);
    const base = {
        path: selected.route.path_resolved,
        inferred: selected.inferred,
        burst_planned: RATE_LIMIT_BURST,
    };
    if (verdict.observed) {
        return {
            outcome: 'ran',
            finding: null,
            summary: { ...base, sent: verdict.at_request, observed: true, at_request: verdict.at_request },
            evidence: new Map(),
        };
    }
    if (verdict.sent === 0) {
        return {
            outcome: 'no_response',
            finding: null,
            summary: { ...base, sent: 0, observed: false },
            evidence: new Map(),
        };
    }
    const path = substituteParams(selected.route.path_resolved).path;
    const finding = noRateLimitObservedFinding({
        route: selected.route,
        path,
        // Every burst request shares one id by design (see `buildBurst`), which
        // is exactly why the evidence for this finding is a single aggregate
        // record keyed by fingerprint rather than one file per request.
        evidenceId: requests[0]?.id ?? `rate_limit POST ${path}`,
        sent: verdict.sent,
        planned: RATE_LIMIT_BURST,
    });
    return {
        outcome: 'ran',
        finding,
        summary: { ...base, sent: verdict.sent, observed: false },
        evidence: new Map([
            [
                finding.fingerprint,
                buildBurstEvidence(finding, opts.origin, burstResults, RATE_LIMIT_BURST, false),
            ],
        ]),
    };
}
/**
 * Absence is reported, never silenced — a `skipped` entry in `tools_run` plus
 * an entry in `missing_tools`, which together drive `coverage` down to
 * 'partial' so the finding count is never mistaken for a complete one. The
 * same applies to a run that started and failed, which reports `failed`
 * rather than zero nuclei findings.
 */
export async function runNuclei(opts) {
    if (!opts.requested) {
        return { outcome: 'not_requested', findings: [], toolRun: null, missing: false };
    }
    if (opts.binaryPath === null) {
        return {
            outcome: 'unavailable',
            findings: [],
            toolRun: {
                name: 'nuclei',
                status: 'skipped',
                reason: 'requested via use_nuclei but not installed — run install_toolchain, or drop use_nuclei ' +
                    'to scan with the own engine only',
            },
            missing: true,
        };
    }
    const outputPath = join(opts.outputDir, 'nuclei.jsonl');
    const run = await invokeNuclei({
        binaryPath: opts.binaryPath,
        targetUrl: opts.origin,
        outputPath,
        // The default envelope excludes intrusive templates entirely, and this
        // tool exposes no flag that widens it (design §7).
        allowIntrusive: false,
        timeoutMs: NUCLEI_TIMEOUT_MS,
        ...(opts.signal === undefined ? {} : { signal: opts.signal }),
    });
    if (!run.ok) {
        return {
            outcome: 'failed',
            findings: [],
            toolRun: { name: 'nuclei', status: 'failed', reason: run.reason ?? 'nuclei run failed' },
            missing: true,
        };
    }
    // nuclei writes `-output` only when a template matched, so a missing file is
    // zero matches rather than a broken run.
    const jsonl = opts.readOutput(outputPath);
    const findings = jsonl === null ? [] : normalizeNucleiJsonl(jsonl, opts.routes);
    return {
        outcome: 'ran',
        findings,
        toolRun: {
            name: 'nuclei',
            status: 'ok',
            reason: jsonl === null ? 'no template matched' : `${findings.length} template match(es)`,
        },
        missing: false,
    };
}
//# sourceMappingURL=passes.js.map