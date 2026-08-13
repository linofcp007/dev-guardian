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
import type { RouteRecord, ToolRun } from '../types.js';
import type { DastFinding } from './analyze.js';
import type { NucleiOutcome, RateLimitOutcome } from './checkStatus.js';
import { buildBurstEvidence, type EvidenceRecord } from './evidence.js';
import { invokeNuclei } from './nuclei.js';
import { normalizeNucleiJsonl } from './normalizeNuclei.js';
import { substituteParams } from './plan.js';
import { executeProbe, type ProbeOptions } from './probe.js';
import { buildBurst, rateLimitVerdict, selectRateLimitTarget, RATE_LIMIT_BURST } from './rateLimit.js';
import { noRateLimitObservedFinding } from './rateLimitFinding.js';
import type { ProbeResult } from './types.js';

/** Wall-clock ceiling for the whole nuclei pass, not per template. */
export const NUCLEI_TIMEOUT_MS = 300_000;

/* -------------------------------------------------------------------- */
/* Rate-limit burst                                                      */
/* -------------------------------------------------------------------- */

/**
 * `path` is the route's inventory spelling — the value a caller passed (or
 * could pass) as `rate_limit_path`, and the answer to "which route did you
 * choose". The URL actually sent has any parameters substituted; it appears
 * in the finding's message and in the evidence record, so a parameterised
 * auth path is never reported as if the placeholder had gone down the wire.
 */
interface RateLimitSummaryBase {
  path: string;
  inferred: boolean;
  burst_planned: number;
  sent: number;
  /**
   * True when the burst stopped before sending `burst_planned` requests for a
   * reason that was not a limiter — in practice the scan's wall-clock
   * ceiling. A `no_rate_limit_observed` derived from five requests is a
   * different claim from one derived from thirty, and a reader has to be able
   * to tell which they are holding. Always present, including on the observed
   * branch, so the shape does not change under the reader.
   */
  cut_by_ceiling: boolean;
}

export type RateLimitSummary =
  | (RateLimitSummaryBase & { observed: true; at_request: number })
  | (RateLimitSummaryBase & { observed: false });

export interface BurstOutcome {
  outcome: RateLimitOutcome;
  finding: DastFinding | null;
  summary: RateLimitSummary | null;
  /** Fingerprint → the burst's single aggregate evidence record. */
  evidence: Map<string, EvidenceRecord>;
}

export interface BurstOptions {
  requested: boolean;
  /** Explicit target path, or null to infer one and report the choice. */
  explicitPath: string | null;
  routes: readonly RouteRecord[];
  origin: string;
  probeOpts: ProbeOptions;
  aborted: () => boolean;
}

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
export async function runRateLimitBurst(opts: BurstOptions): Promise<BurstOutcome> {
  const empty: BurstOutcome = {
    outcome: 'not_requested',
    finding: null,
    summary: null,
    evidence: new Map(),
  };
  if (!opts.requested) return empty;

  const selected = selectRateLimitTarget(opts.routes, opts.explicitPath);
  if (selected === null) return { ...empty, outcome: 'no_candidate' };

  const requests = buildBurst(selected.route, opts.origin, RATE_LIMIT_BURST);
  const burstResults: ProbeResult[] = [];
  for (const request of requests) {
    const result = await executeProbe(request, opts.probeOpts);
    burstResults.push(result);
    if (rateLimitVerdict([result]).observed) break;
    if (opts.aborted()) break;
  }

  const verdict = rateLimitVerdict(burstResults);
  // Derived rather than tracked through the loop: the burst was cut short
  // exactly when fewer requests were sent than planned and no limiter was
  // what stopped it. A flag set at the `break` would have to be kept in step
  // with every future exit from that loop; this cannot drift.
  const cutByCeiling = burstResults.length < requests.length && !verdict.observed;
  const base = {
    path: selected.route.path_resolved,
    inferred: selected.inferred,
    burst_planned: RATE_LIMIT_BURST,
    cut_by_ceiling: cutByCeiling,
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
    cutByCeiling,
  });
  return {
    outcome: 'ran',
    finding,
    summary: { ...base, sent: verdict.sent, observed: false },
    evidence: new Map<string, EvidenceRecord>([
      [
        finding.fingerprint,
        buildBurstEvidence(finding, opts.origin, burstResults, RATE_LIMIT_BURST, false),
      ],
    ]),
  };
}

/* -------------------------------------------------------------------- */
/* nuclei                                                                */
/* -------------------------------------------------------------------- */

export interface NucleiStep {
  outcome: NucleiOutcome;
  findings: DastFinding[];
  toolRun: ToolRun | null;
  /** True when the caller asked for nuclei and did not get a clean run. */
  missing: boolean;
}

export interface NucleiOptions {
  requested: boolean;
  /** Resolved binary path, or null when it is not installed. */
  binaryPath: string | null;
  origin: string;
  outputDir: string;
  routes: readonly RouteRecord[];
  /** Reads the JSONL file back; injected so the caller owns all filesystem access policy. */
  readOutput: (path: string) => string | null;
  /**
   * True when the scan's wall-clock ceiling fired before this pass could
   * start. nuclei is not started at all in that case — a 5-minute external
   * scan begun after the ceiling expired would make the ceiling meaningless —
   * and the reason says so rather than blaming the target or the install.
   */
  cutByDeadline: boolean;
  signal?: AbortSignal;
}

/**
 * Absence is reported, never silenced — a `skipped` entry in `tools_run` plus
 * an entry in `missing_tools`, which together drive `coverage` down to
 * 'partial' so the finding count is never mistaken for a complete one. The
 * same applies to a run that started and failed, which reports `failed`
 * rather than zero nuclei findings.
 */
export async function runNuclei(opts: NucleiOptions): Promise<NucleiStep> {
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
        reason:
          'requested via use_nuclei but not installed — run install_toolchain, or drop use_nuclei ' +
          'to scan with the own engine only',
      },
      missing: true,
    };
  }

  if (opts.cutByDeadline) {
    return {
      outcome: 'failed',
      findings: [],
      toolRun: {
        name: 'nuclei',
        status: 'skipped',
        reason:
          'not started: the scan reached its wall-clock ceiling before the nuclei pass began — ' +
          'raise wall_clock_ms and re-run',
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
