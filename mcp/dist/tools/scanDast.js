/**
 * `scan_dast` — active DAST driven by the static route inventory.
 *
 * The only tool in this server that sends traffic to a live system, so the
 * order of operations below is the safety design, not a convenience:
 *
 *   1. `resolveProjectPath` — where the snapshot and the reports live.
 *   2. `classifyTarget` — **before any network I/O at all**. Loopback probes
 *      directly; anything else needs `authorized_target: true`.
 *   3. The surface snapshot. No snapshot is a refusal naming
 *      `map_attack_surface`, never an empty scan: "zero routes probed" and
 *      "zero problems found" must not read alike.
 *   4. Credentials, from `auth_header_env` (recommended) or `auth_header`.
 *   5. A liveness probe. Nothing listening is `target_not_found` — again a
 *      refusal, not a clean run.
 *
 * A refused target, a missing snapshot and a dead target are three distinct
 * outcomes and are returned as three distinct error codes. None of them
 * persists a scan row: an empty `dast` scan in the history would be read by
 * `diff_scans` and `risk_score` as a scan that found nothing.
 *
 * This file is glue. Every decision about what a response *means* lives in
 * the pure modules (`target`, `plan`, `analyze`, `checkStatus`,
 * `rateLimitFinding`, `normalizeNuclei`); nothing here inspects a status code
 * or a body to decide anything is wrong.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { analyzeOrigin, analyzeRoutes, } from '../dast/analyze.js';
import { computeCheckStatuses } from '../dast/checkStatus.js';
import { armDeadline, DEFAULT_WALL_CLOCK_MS } from '../dast/deadline.js';
import { buildEvidence, writeEvidenceFiles } from '../dast/evidence.js';
import { livenessMessage, livenessRequest } from '../dast/liveness.js';
import { runNuclei, runRateLimitBurst } from '../dast/passes.js';
import { DEFAULT_MAX_REQUESTS, planProbes } from '../dast/plan.js';
import { DEFAULT_CONCURRENCY, DEFAULT_PROBE_TIMEOUT_MS, executeProbe, executeProbes, } from '../dast/probe.js';
import { collectSecrets, makeRedactor, redactObject } from '../dast/redact.js';
import { classifyTarget } from '../dast/target.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import { SEVERITY_ORDER, } from '../types.js';
import { registerToolModule } from './index.js';
import { assessCoverage } from './scanCoverage.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';
/** Name the own engine reports under in `tools_run`. Not a binary. */
const DAST_ENGINE = 'guardian-dast';
/**
 * Share of the PLANNED probes that must go unanswered — timed out or failed
 * to connect — before the run declares a coverage gap of its own.
 *
 * 10%, and the number is a balance between two ways of misleading a reader.
 * At 0 every scan with one flaky socket reports 'partial', which trains the
 * reader to ignore the field that exists to be believed. Too high and a
 * target answering a handful of probes out of hundreds still reports
 * `coverage: 'full'` — a "0 findings" result that scanned almost nothing,
 * which is precisely the failure `computeCoverage` was written to prevent.
 * One in ten planned probes going unanswered is past what flake explains.
 *
 * Measured against the plan rather than against what was attempted: probes
 * cut by the wall-clock ceiling record `cancelled` and are reported by the
 * separate `:wall-clock` entry, so they neither count here nor hide anything.
 */
const UNANSWERED_COVERAGE_THRESHOLD = 0.1;
const inputSchema = {
    project_path: ProjectPath,
    base_url: z
        .string()
        .min(1)
        .describe('Origin of the ALREADY-RUNNING application, e.g. http://localhost:3000. This tool never ' +
        'starts, builds or stops the app; if nothing answers it returns target_not_found.'),
    authorized_target: z
        .boolean()
        .optional()
        .describe('Attestation that you are authorised to send scan traffic to a non-loopback host. ' +
        'Required for every host that is not localhost / 127.0.0.0/8 / ::1 — including a ' +
        'hostname that merely resolves to loopback, because classification is lexical and never ' +
        'resolves DNS. Recorded in the scan for audit. Do not set this on a caller\'s behalf.'),
    allow_write_methods: z
        .boolean()
        .optional()
        .describe('Allow POST/PUT/PATCH/DELETE probes, always with an empty body (the 400/422-vs-401/403 ' +
        'signal answers the authorization question without writing). Default: false — read-only ' +
        'GET/HEAD/OPTIONS. A 2xx on a write method is reported as "may have mutated state".'),
    probe_rate_limit: z
        .boolean()
        .optional()
        .describe('Send a bounded burst of identical requests carrying a synthetic, un-ownable credential to ' +
        'one authentication endpoint, to see whether a limiter answers. Default: false. This ' +
        'flag is its own authorization and does not open write methods for any other check.'),
    rate_limit_path: z
        .string()
        .min(1)
        .optional()
        .describe('Exact path (as it appears in the inventory) to aim the rate-limit burst at. When omitted ' +
        'the target is inferred from auth-shaped paths and the chosen route is reported; when ' +
        'the named path is not in the inventory the check reports no_candidate rather than ' +
        'bursting something else.'),
    auth_header_env: z
        .string()
        .min(1)
        .optional()
        .describe('RECOMMENDED credential path: the NAME of an environment variable holding an Authorization ' +
        'header value. The secret never enters the conversation or the MCP request log. An unset ' +
        'variable is reported as a warning, never a silent anonymous run. WARNING: the named ' +
        'variable lives in this server\'s own environment — any OTHER scanner this session spawns ' +
        '(semgrep, trivy, gitleaks, git) inherits it too. nuclei is the one exception: it is ' +
        'always spawned with a scrubbed environment that excludes it.'),
    auth_header: z
        .string()
        .min(1)
        .optional()
        .describe('Literal Authorization header value. Lands in the transcript — prefer auth_header_env. ' +
        'Never persisted and redacted from every finding, evidence file and result field.'),
    use_nuclei: z
        .boolean()
        .optional()
        .describe('Also run nuclei against the origin. Default: false (nuclei is an active scanner with a ' +
        'large template download). When requested and not installed the gap is reported in ' +
        'tools_run and missing_tools, never silently skipped. nuclei\'s default templates test ' +
        'the ORIGIN, not this project\'s routes — the own engine is what tests those.'),
    max_requests: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Global request ceiling. Default: ${DEFAULT_MAX_REQUESTS}. Reported when it cuts.`),
    timeout_ms: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Per-request timeout in milliseconds. Default: ${DEFAULT_PROBE_TIMEOUT_MS}.`),
    wall_clock_ms: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Global wall-clock ceiling for the probing phase, in milliseconds. Default: ` +
        `${DEFAULT_WALL_CLOCK_MS}. Bounds the total, which neither timeout_ms (one request) nor ` +
        `max_requests (how many are planned) does. When it cuts, the run still returns and says ` +
        `so: summary.timed_out, summary.probes_cut, and a degraded coverage. Probes it cut ` +
        `record outcome 'cancelled', never 'timeout' — the target did not fail to answer, this ` +
        `tool stopped asking. Does not cover the one liveness request, which timeout_ms bounds.`),
};
const tool = {
    name: 'scan_dast',
    title: 'Probe a running application against its route inventory',
    // The description is the only discovery surface an agent has, so it states
    // the preconditions and the envelope, not just the capability: the two
    // things that make a caller pick this tool wrongly are not knowing the app
    // must already be running, and not knowing a prior map_attack_surface run
    // is required.
    description: 'ACTIVE DAST: sends real HTTP requests to an ALREADY-RUNNING application and reports what is ' +
        'actually reachable, what is served without credentials, and what leaks. REQUIRES a prior ' +
        'map_attack_surface run — it probes that route inventory and refuses with no_surface_snapshot ' +
        'when there is none. The app must already be up: this tool never starts, builds or stops it, ' +
        'and returns target_not_found when nothing answers at base_url. Safety envelope: LOOPBACK ' +
        'TARGETS ONLY (localhost / 127.0.0.0/8 / ::1) unless the caller passes authorized_target: ' +
        'true attesting they may scan that host; READ-ONLY methods (GET/HEAD/OPTIONS) unless ' +
        'allow_write_methods is set, and even then with empty bodies — plus the opt-in ' +
        'probe_rate_limit burst, the one exception, which sends POST to exactly one route; ' +
        'redirects are never followed; ' +
        'no injection payloads and no credential guessing. Checks reachability against the spec diff, ' +
        'anonymous exposure of auth-required routes, differential authorization, CORS, security ' +
        'headers, information disclosure, method surface and open redirects, plus an opt-in benign ' +
        'rate-limit burst and an optional nuclei pass. Findings persist with scan_type dast and point ' +
        'at the source file the route was extracted from. A clean result is NOT evidence of injection ' +
        'safety.',
    inputSchema,
    handler: (input, ctx, callMeta) => handler(input, ctx, callMeta),
};
registerToolModule(tool);
function fail(code, message, retryWith) {
    return {
        ok: false,
        error: { code, message, ...(retryWith === undefined ? {} : { retry_with: retryWith }) },
    };
}
async function handler(input, ctx, callMeta) {
    const inp = input;
    // ---- 1. Project path -------------------------------------------------
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        // Same code map_attack_surface and detect_stack return for an unusable
        // project_path, so hosts and skills handle one failure and not three.
        return fail('not_a_git_repo', e.message);
    }
    // ---- 2. Target authorization, BEFORE any network I/O -----------------
    const target = classifyTarget(inp.base_url ?? '', inp.authorized_target === true);
    if (!target.allowed) {
        // An empty origin means the URL never parsed (or was not http/https) —
        // that is a malformed argument, not a refusal to touch someone else's
        // host, and conflating the two would send a caller looking for an
        // attestation flag that would not have helped.
        const code = target.origin === '' ? 'unsupported_target' : 'target_not_authorized';
        return fail(code, target.reason ?? 'Target refused.');
    }
    // ---- 3. The surface snapshot ----------------------------------------
    const persisted = ctx.storage.surface.getLatest();
    if (persisted === null) {
        return fail('no_surface_snapshot', 'No attack-surface snapshot exists for this project, so there is no route inventory to ' +
            'probe. Run map_attack_surface first, then re-run scan_dast. This is a refusal and not ' +
            'an empty scan on purpose: "zero routes probed" must never read as "zero problems found".', { run_first: 'map_attack_surface', project_path: projectPath });
    }
    const snapshot = persisted.snapshot;
    // ---- 4. Credentials --------------------------------------------------
    const warnings = [];
    const credential = resolveCredential(inp, warnings);
    const redact = makeRedactor(collectSecrets(credential.value));
    const timeoutMs = typeof inp.timeout_ms === 'number' && inp.timeout_ms > 0
        ? Math.floor(inp.timeout_ms)
        : DEFAULT_PROBE_TIMEOUT_MS;
    const maxRequests = typeof inp.max_requests === 'number' && inp.max_requests > 0
        ? Math.floor(inp.max_requests)
        : DEFAULT_MAX_REQUESTS;
    const wallClockMs = typeof inp.wall_clock_ms === 'number' && inp.wall_clock_ms > 0
        ? Math.floor(inp.wall_clock_ms)
        : DEFAULT_WALL_CLOCK_MS;
    const aborted = () => callMeta?.signal?.aborted === true;
    // ---- 5. Liveness -----------------------------------------------------
    // Deliberately NOT fed into the analysis: it is a connectivity check, not a
    // planned probe, and letting an unplanned request at `/` reach the checks
    // would produce findings about a path the inventory never listed. It runs
    // outside the wall-clock ceiling, which is armed below: this is one request
    // already bounded by `timeoutMs`, and arming the ceiling first would make a
    // deadline that fired here indistinguishable from a dead target.
    const livenessOpts = { timeoutMs, concurrency: 1 };
    if (callMeta?.signal !== undefined)
        livenessOpts.signal = callMeta.signal;
    const liveness = await executeProbe(livenessRequest(target.origin), livenessOpts);
    if (liveness.outcome !== 'completed') {
        if (aborted())
            return fail('cancelled', 'Scan was cancelled by the host.');
        return fail('target_not_found', livenessMessage(target, liveness, timeoutMs));
    }
    // ---- 6. Scan row + report directory ----------------------------------
    const scanId = randomUUID();
    const treeHash = await computeTreeHash(projectPath);
    if (persisted.tree_hash !== treeHash) {
        warnings.push('The attack-surface snapshot was taken at a different working-tree state than the one on ' +
            'disk now — routes added or moved since then were not probed. Re-run map_attack_surface ' +
            'for an up-to-date inventory.');
    }
    const evidenceDir = ensureReportDir(projectPath, scanId, 'dast');
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'dast',
        project_path: projectPath,
        tree_hash: treeHash,
        report_dir: evidenceDir,
    });
    // ---- 7. Plan, probe, analyse ----------------------------------------
    const plan = planProbes(snapshot.routes, {
        origin: target.origin,
        allowWriteMethods: inp.allow_write_methods === true,
        authHeaderValue: credential.value,
        maxRequests,
    });
    if (snapshot.routes.length === 0) {
        warnings.push('The attack-surface snapshot contains no routes, so nothing was probed. Every per-route ' +
            'check reports no_candidate rather than a clean result — this is not a scan that found ' +
            'nothing.');
    }
    if (plan.truncated) {
        warnings.push(`The max_requests ceiling (${maxRequests}) cut the plan: ` +
            `${plan.skipped.filter((s) => s.reason === 'cap').length} request(s) were not sent. ` +
            'Raise max_requests to cover the whole inventory.');
    }
    // The wall-clock ceiling is armed here, around the probing phase only —
    // the part whose duration scales with the inventory and which neither
    // `timeoutMs` (one request) nor `maxRequests` (how many are planned)
    // bounds. It shares the AbortSignal mechanism `probe.ts` already honours,
    // so a probe it cuts records `outcome: 'cancelled'`, never `'timeout'`.
    const deadline = armDeadline(wallClockMs, callMeta?.signal);
    const probeOpts = {
        timeoutMs,
        concurrency: DEFAULT_CONCURRENCY,
        signal: deadline.signal,
    };
    // A host cancellation is a half-finished scan. Finalizing it `cancelled`
    // rather than `completed` is what keeps a partial run out of `getLatest()`
    // and out of every diff and baseline computed from it.
    const cancel = () => {
        deadline.dispose();
        ctx.storage.scans.finalize({
            scan_id: scanId,
            status: 'cancelled',
            tools_run: [{ name: DAST_ENGINE, status: 'failed', reason: 'cancelled by the host' }],
            missing_tools: [],
        });
        return fail('cancelled', 'Scan was cancelled by the host.');
    };
    const results = await executeProbes(plan.requests, probeOpts);
    if (aborted())
        return cancel();
    const analyzeInput = {
        plan,
        // The full inventory alongside the probed subset, for the same reason the
        // rate-limit burst above gets `snapshot.routes`: the default read-only
        // envelope drops every write route from `plan.routes`, and a check that
        // asks "does the inventory know about this method?" against the probed
        // subset alone accuses the caller of routes this very snapshot contains.
        inventoryRoutes: snapshot.routes,
        results,
        origin: target.origin,
        shadowPaths: specPaths(snapshot, 'code_only'),
        deadDocPaths: specPaths(snapshot, 'spec_only'),
        hasCredentials: credential.value !== null,
    };
    const findings = [...analyzeRoutes(analyzeInput), ...analyzeOrigin(analyzeInput)];
    const outcomes = outcomeCounts(results);
    const completed = outcomes.completed;
    // The engine "ran" when it either measured something or had nothing to
    // measure; it FAILED when probes were planned and the target answered none
    // of them. That second case used to report `ok` unconditionally, which made
    // a scan whose every probe timed out come back `coverage: 'full'` — a
    // "0 findings" result that scanned nothing, reading as a clean bill of
    // health. `computeCoverage`'s own contract says a run with nothing to do is
    // 'full' (no gaps, just no work), which is why zero planned requests is not
    // a failure here.
    const engineFailed = plan.requests.length > 0 && completed === 0;
    const toolsRun = [
        {
            name: DAST_ENGINE,
            status: engineFailed ? 'failed' : 'ok',
            reason: `${plan.requests.length} request(s) planned, ${completed} completed, ` +
                `${outcomes.timeout} timed out, ${outcomes.network_error} failed to connect` +
                (outcomes.cancelled > 0 ? `, ${outcomes.cancelled} cut short` : ''),
        },
    ];
    // A run in which the target answered SOME probes but silently dropped a
    // material share of them is not a full-coverage run, and `engineFailed`
    // above cannot say so — it only fires when literally nothing completed. A
    // target answering 1 of 300 used to report `tools_run: ok`, `coverage:
    // 'full'` and no warning, with `probe_outcomes.timeout: 299` sitting two
    // fields away contradicting it. Lose the same probes to the wall clock
    // instead and coverage correctly degrades; losing them to the target must
    // read the same way.
    //
    // A separate entry rather than a status on the engine's own, mirroring the
    // `:wall-clock` entry below: "the target did not answer" and "this tool
    // stopped asking" are different gaps, and keeping them apart is what lets
    // `computeCoverage` report 'partial' for a run that measured part of the
    // inventory instead of collapsing everything to 'none'.
    const unanswered = outcomes.timeout + outcomes.network_error;
    if (!engineFailed &&
        plan.requests.length > 0 &&
        unanswered / plan.requests.length >= UNANSWERED_COVERAGE_THRESHOLD) {
        toolsRun.push({
            name: `${DAST_ENGINE}:unanswered`,
            status: 'failed',
            reason: `the target never answered ${unanswered} of ${plan.requests.length} probe(s) ` +
                `(${outcomes.timeout} timed out, ${outcomes.network_error} failed to connect) — ` +
                'the checks covering those routes reached no verdict, so this scan is not a ' +
                'complete picture of the inventory',
        });
    }
    const missingTools = [];
    // ---- 8. Optional rate-limit burst ------------------------------------
    const burst = await runRateLimitBurst({
        requested: inp.probe_rate_limit === true,
        explicitPath: inp.rate_limit_path ?? null,
        // The full inventory, not `plan.routes`: the burst's target is almost
        // always a POST, which the default read-only envelope drops from the
        // plan. `probe_rate_limit` is its own authorization for exactly that one
        // route (design §6).
        routes: snapshot.routes,
        origin: target.origin,
        // Shares the deadline's signal, so the burst is inside the ceiling too:
        // it is thirty requests, and thirty per-request timeouts after the
        // ceiling expired would put the total right back where it started.
        probeOpts,
        aborted: () => aborted() || deadline.hit(),
    });
    if (burst.finding !== null)
        findings.push(burst.finding);
    // The ceiling governs the probe plan and the burst, and nothing after, so
    // this is both the last moment it can fire and the right moment to read it.
    //
    // ONE read, held in ONE variable, used by every channel that reports the
    // cut. Reading `deadline.hit()` separately at each use site is how the
    // first version of this got it wrong: the flag was captured right after
    // `executeProbes`, so a ceiling that fired *during* the burst truncated the
    // rate-limit sample while the result still said `timed_out: false`, carried
    // no warning and reported full coverage — and, with nuclei requested, sat
    // next to a nuclei entry that DID re-read the flag and said the ceiling had
    // fired. Self-contradictory output in one object.
    //
    // Reading it here rather than after the nuclei pass also keeps a long
    // nuclei run — which has its own timeout and is deliberately outside this
    // ceiling — from being reported as a cut probe plan.
    const timedOut = deadline.hit();
    deadline.dispose();
    if (timedOut) {
        // A separate `tools_run` entry, not a status on the engine's own: "the
        // run was cut" is a distinct gap from "the target did not answer", and
        // keeping them apart is what lets `computeCoverage` report 'partial' for
        // a run that measured some of the inventory before the ceiling fired, and
        // 'none' for one that measured nothing at all.
        toolsRun.push({
            name: `${DAST_ENGINE}:wall-clock`,
            status: 'failed',
            reason: `cut after ${completed} of ${plan.requests.length} probe(s): the ${wallClockMs}ms ` +
                'wall-clock ceiling was reached',
        });
        warnings.push(`The scan reached its wall-clock ceiling (${wallClockMs}ms) and was cut: ` +
            `${outcomes.cancelled} of ${plan.requests.length} probe(s) never ran` +
            (burst.summary?.cut_by_ceiling === true
                ? `, and the rate-limit burst stopped after ${burst.summary.sent} of ` +
                    `${burst.summary.burst_planned} requests`
                : '') +
            '. Any check reporting target_error below may simply not have been reached rather ' +
            'than having failed against the target — raise wall_clock_ms and re-run before ' +
            'drawing a conclusion from it.');
    }
    // ---- 9. Optional nuclei pass -----------------------------------------
    const nuclei = await runNuclei({
        requested: inp.use_nuclei === true,
        binaryPath: inp.use_nuclei === true ? await scannerAvailable('nuclei') : null,
        origin: target.origin,
        outputDir: evidenceDir,
        routes: snapshot.routes,
        readOutput: readJsonSafe,
        // The same value the summary reports, not a second read — that divergence
        // is exactly the contradiction described above.
        cutByDeadline: timedOut,
        ...(callMeta?.signal === undefined ? {} : { signal: callMeta.signal }),
    });
    findings.push(...nuclei.findings);
    if (nuclei.toolRun !== null)
        toolsRun.push(nuclei.toolRun);
    if (nuclei.missing)
        missingTools.push('nuclei');
    // The burst and the nuclei pass both stop early on cancellation, so a
    // second check here is what stops a half-run being written as `completed`.
    if (aborted())
        return cancel();
    // ---- 10. Evidence + persistence --------------------------------------
    const ordered = [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.fingerprint.localeCompare(b.fingerprint));
    const records = ordered.map((f) => burst.evidence.get(f.fingerprint) ?? buildEvidence(f, target.origin, results));
    const written = writeEvidenceFiles(evidenceDir, records, redact);
    if (written.capped > 0) {
        warnings.push(`${written.capped} finding(s) have no evidence file: the per-scan evidence cap was reached. ` +
            'The findings themselves are complete; only their raw request/response pairs were dropped.');
    }
    if (written.failed > 0) {
        warnings.push(`${written.failed} evidence file(s) could not be written to ${evidenceDir}.`);
    }
    // Redaction is applied to the stored rows as a whole, not to a hand-picked
    // set of fields — see `redact.ts` for why "we never put it there" is not a
    // guarantee.
    ctx.storage.findings.bulkInsert(ordered.map((f) => redactObject(toInsertInput(f, scanId, written.written.has(f.fingerprint) ? evidenceDir : null), redact)));
    const checks = computeCheckStatuses({
        plan,
        results,
        hasSpecDiff: snapshot.spec_diff !== null,
        hasCredentials: credential.value !== null,
        rateLimit: burst.outcome,
        nuclei: nuclei.outcome,
    });
    const { coverage, warning: coverageWarning } = assessCoverage('dast', toolsRun, missingTools);
    if (coverageWarning !== null)
        warnings.unshift(coverageWarning);
    const meta = {
        target_origin: target.origin,
        target_class: target.target_class,
        target_host: target.host,
        // Recorded for the audit trail the design asks for: a non-loopback scan
        // must show that someone attested to it.
        authorized_target: inp.authorized_target === true,
        allow_write_methods: inp.allow_write_methods === true,
        // The env var NAME is not a secret; the value never appears anywhere.
        credential_source: credential.source,
        requests_planned: plan.requests.length,
        requests_completed: completed,
        truncated: plan.truncated,
        timed_out: timedOut,
        checks,
        evidence_dir: evidenceDir,
    };
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        // Through the choke point, not because a credential is known to be in
        // here but because requirement 2 is unconditional. `tools_run` carries
        // one string this codebase does not author — nuclei's first stderr line,
        // stored verbatim (`nuclei.ts#interpretRun`) — and "we never put it
        // there" is the exact argument that failed for the evidence files.
        tools_run: redactObject(toolsRun, redact),
        missing_tools: redactObject(missingTools, redact),
        report_dir: evidenceDir,
        meta: redactObject(meta, redact),
    });
    const record = ctx.storage.scans.getById(scanId);
    const payload = {
        scan_id: scanId,
        scan_type: 'dast',
        project_path: projectPath,
        tree_hash: treeHash,
        started_at: record?.started_at ?? new Date().toISOString(),
        finished_at: record?.finished_at ?? new Date().toISOString(),
        status: 'completed',
        tools_run: toolsRun,
        missing_tools: missingTools,
        report_paths: [evidenceDir],
        evidence_dir: evidenceDir,
        coverage,
        findings_count_by_severity: countBySeverity(ordered),
        // `top_findings` is the `ScanResult` contract every roll-up already reads
        // (`audit_executive`, `guardian://scans/{id}`); `findings` is the full
        // list, which a DAST run can afford to inline because its size is bounded
        // by the request ceiling. The overlap is deliberate, not an oversight.
        top_findings: ordered.slice(0, 10),
        findings: ordered,
        warnings,
        target: {
            origin: target.origin,
            host: target.host,
            target_class: target.target_class,
            authorized_target: inp.authorized_target === true,
        },
        summary: {
            routes_in_snapshot: snapshot.routes.length,
            routes_planned: plan.routes.length,
            requests_planned: plan.requests.length,
            requests_completed: completed,
            requests_failed: results.length - completed,
            /** completed / timeout / cancelled / network_error, so a run cut by the
             *  ceiling is not mistaken for a target that stopped answering. */
            probe_outcomes: outcomes,
            truncated: plan.truncated,
            max_requests: maxRequests,
            /** True when the wall-clock ceiling cut the run. Never silent. */
            timed_out: timedOut,
            wall_clock_ms: wallClockMs,
            /**
             * Probes the wall-clock ceiling cut. NOT "probes that never touched the
             * target": up to `DEFAULT_CONCURRENCY` of these were in flight when the
             * ceiling fired and had already reached the target, and the executor
             * cannot say afterwards which. It was called `probes_not_run`, which
             * claimed the stronger, unknowable thing and had an active scanner
             * under-reporting its own traffic — the wrong direction for an audit
             * trail. Renamed rather than adjusted by a guess: the count of probes
             * cut is exact, the count of probes untouched is not.
             */
            probes_cut: timedOut ? outcomes.cancelled : 0,
            skipped: plan.skipped,
            checks,
            rate_limit: burst.summary,
        },
    };
    // The final choke point: every string on the way out, whatever produced it.
    return { ok: true, ...redactObject(payload, redact) };
}
/**
 * `auth_header_env` wins when both are supplied: it is the recommended path
 * and the one whose secret never entered the transcript. An unset variable is
 * a reported warning and not a silent anonymous run — the caller asked for
 * authenticated probing and did not get it, and a scan that quietly drops the
 * credential reports `differential_authz` as if it had been tested.
 */
function resolveCredential(inp, warnings) {
    const envName = inp.auth_header_env;
    if (envName !== undefined && envName !== '') {
        if (inp.auth_header !== undefined) {
            warnings.push(`Both auth_header_env and auth_header were supplied; auth_header_env (${envName}) was ` +
                'used and the literal auth_header was ignored.');
        }
        const value = process.env[envName];
        if (value === undefined || value === '') {
            warnings.push(`auth_header_env named the environment variable ${envName}, but it is not set in this ` +
                'process. The scan ran ANONYMOUSLY: the differential-authorization check did not run ' +
                'and no authenticated probe was sent. Export the variable and re-run.');
            return { value: null, source: `env:${envName} (unset)` };
        }
        return { value, source: `env:${envName}` };
    }
    if (inp.auth_header !== undefined && inp.auth_header !== '') {
        return { value: inp.auth_header, source: 'literal' };
    }
    return { value: null, source: 'none' };
}
/* -------------------------------------------------------------------- */
/* Small helpers                                                         */
/* -------------------------------------------------------------------- */
/**
 * The resolved paths of the spec diff's `code_only` (shadow endpoints) or
 * `spec_only` (dead documentation) entries. An entry whose route is absent
 * contributes nothing: `SpecDiffEntry.path` is the normalised comparison key
 * (`/users/{}`), not a path `analyze.ts` can match a `RouteRecord` against.
 */
function specPaths(snapshot, side) {
    const out = new Set();
    const diff = snapshot.spec_diff;
    if (diff === null)
        return out;
    for (const entry of diff[side]) {
        const route = side === 'code_only' ? entry.code_route : entry.spec_route;
        if (route !== undefined)
            out.add(route.path_resolved);
    }
    return out;
}
/**
 * `DastFinding` carries `check` and `evidence_id`, which are not columns.
 * They go into `raw` alongside the evidence file's path so a stored finding
 * still points at its proof, per design §8 ("pointed at by the finding, not
 * inlined into the SQLite row").
 *
 * `evidenceDir` is null when this finding's evidence file was capped or
 * failed to write. The pointer is then `null` rather than a path that looks
 * real and resolves to nothing — an absent value beats a fabricated one.
 */
function toInsertInput(finding, scanId, evidenceDir) {
    const { check, evidence_id, ...rest } = finding;
    return {
        ...rest,
        scan_id: scanId,
        raw: {
            check,
            evidence_id,
            evidence_file: evidenceDir === null ? null : join(evidenceDir, `${finding.fingerprint}.json`),
        },
    };
}
function countBySeverity(findings) {
    const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const finding of findings)
        out[finding.severity] += 1;
    return out;
}
/**
 * The four probe outcomes, counted. Reported because `requests_completed`
 * alone cannot tell "the target stopped answering" (`timeout`) from "this
 * tool stopped asking" (`cancelled`) — the distinction `probe.ts` was
 * deliberately built to preserve, and the one a wall-clock cut turns on.
 */
function outcomeCounts(results) {
    const out = {
        completed: 0,
        timeout: 0,
        cancelled: 0,
        network_error: 0,
    };
    for (const result of results)
        out[result.outcome] += 1;
    return out;
}
//# sourceMappingURL=scanDast.js.map