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
import type { PluginContext } from '../context.js';
import {
  analyzeOrigin,
  analyzeRoutes,
  type AnalyzeInput,
  type DastFinding,
} from '../dast/analyze.js';
import { computeCheckStatuses } from '../dast/checkStatus.js';
import { buildEvidence, writeEvidenceFiles, type EvidenceRecord } from '../dast/evidence.js';
import { livenessMessage, livenessRequest } from '../dast/liveness.js';
import { runNuclei, runRateLimitBurst } from '../dast/passes.js';
import { DEFAULT_MAX_REQUESTS, planProbes } from '../dast/plan.js';
import {
  DEFAULT_CONCURRENCY,
  DEFAULT_PROBE_TIMEOUT_MS,
  executeProbe,
  executeProbes,
  type ProbeOptions,
} from '../dast/probe.js';
import { collectSecrets, makeRedactor, redactObject } from '../dast/redact.js';
import { classifyTarget } from '../dast/target.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import {
  SEVERITY_ORDER,
  type AttackSurfaceSnapshot,
  type Finding,
  type Severity,
  type ToolResult,
  type ToolRun,
} from '../types.js';
import { registerToolModule, type ToolCallMeta, type ToolModule } from './index.js';
import { assessCoverage } from './scanCoverage.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';

/** Name the own engine reports under in `tools_run`. Not a binary. */
const DAST_ENGINE = 'guardian-dast';

const inputSchema = {
  project_path: ProjectPath,
  base_url: z
    .string()
    .min(1)
    .describe(
      'Origin of the ALREADY-RUNNING application, e.g. http://localhost:3000. This tool never ' +
        'starts, builds or stops the app; if nothing answers it returns target_not_found.',
    ),
  authorized_target: z
    .boolean()
    .optional()
    .describe(
      'Attestation that you are authorised to send scan traffic to a non-loopback host. ' +
        'Required for every host that is not localhost / 127.0.0.0/8 / ::1 — including a ' +
        'hostname that merely resolves to loopback, because classification is lexical and never ' +
        'resolves DNS. Recorded in the scan for audit. Do not set this on a caller\'s behalf.',
    ),
  allow_write_methods: z
    .boolean()
    .optional()
    .describe(
      'Allow POST/PUT/PATCH/DELETE probes, always with an empty body (the 400/422-vs-401/403 ' +
        'signal answers the authorization question without writing). Default: false — read-only ' +
        'GET/HEAD/OPTIONS. A 2xx on a write method is reported as "may have mutated state".',
    ),
  probe_rate_limit: z
    .boolean()
    .optional()
    .describe(
      'Send a bounded burst of identical requests carrying a synthetic, un-ownable credential to ' +
        'one authentication endpoint, to see whether a limiter answers. Default: false. This ' +
        'flag is its own authorization and does not open write methods for any other check.',
    ),
  rate_limit_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      'Exact path (as it appears in the inventory) to aim the rate-limit burst at. When omitted ' +
        'the target is inferred from auth-shaped paths and the chosen route is reported; when ' +
        'the named path is not in the inventory the check reports no_candidate rather than ' +
        'bursting something else.',
    ),
  auth_header_env: z
    .string()
    .min(1)
    .optional()
    .describe(
      'RECOMMENDED credential path: the NAME of an environment variable holding an Authorization ' +
        'header value. The secret never enters the conversation or the MCP request log. An unset ' +
        'variable is reported as a warning, never a silent anonymous run.',
    ),
  auth_header: z
    .string()
    .min(1)
    .optional()
    .describe(
      'Literal Authorization header value. Lands in the transcript — prefer auth_header_env. ' +
        'Never persisted and redacted from every finding, evidence file and result field.',
    ),
  use_nuclei: z
    .boolean()
    .optional()
    .describe(
      'Also run nuclei against the origin. Default: false (nuclei is an active scanner with a ' +
        'large template download). When requested and not installed the gap is reported in ' +
        'tools_run and missing_tools, never silently skipped. nuclei\'s default templates test ' +
        'the ORIGIN, not this project\'s routes — the own engine is what tests those.',
    ),
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
};

const tool: ToolModule = {
  name: 'scan_dast',
  title: 'Probe a running application against its route inventory',
  // The description is the only discovery surface an agent has, so it states
  // the preconditions and the envelope, not just the capability: the two
  // things that make a caller pick this tool wrongly are not knowing the app
  // must already be running, and not knowing a prior map_attack_surface run
  // is required.
  description:
    'ACTIVE DAST: sends real HTTP requests to an ALREADY-RUNNING application and reports what is ' +
    'actually reachable, what is served without credentials, and what leaks. REQUIRES a prior ' +
    'map_attack_surface run — it probes that route inventory and refuses with no_surface_snapshot ' +
    'when there is none. The app must already be up: this tool never starts, builds or stops it, ' +
    'and returns target_not_found when nothing answers at base_url. Safety envelope: LOOPBACK ' +
    'TARGETS ONLY (localhost / 127.0.0.0/8 / ::1) unless the caller passes authorized_target: ' +
    'true attesting they may scan that host; READ-ONLY methods (GET/HEAD/OPTIONS) unless ' +
    'allow_write_methods is set, and even then with empty bodies; redirects are never followed; ' +
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

interface Inputs {
  project_path?: string;
  base_url?: string;
  authorized_target?: boolean;
  allow_write_methods?: boolean;
  probe_rate_limit?: boolean;
  rate_limit_path?: string;
  auth_header_env?: string;
  auth_header?: string;
  use_nuclei?: boolean;
  max_requests?: number;
  timeout_ms?: number;
}

/**
 * Every way this tool can refuse. Narrowed to exactly these six rather than
 * the full `DomainErrorCode` union so the set is readable in one glance —
 * they are the contract, and each one means a different thing to a caller.
 */
type RefusalCode =
  | 'not_a_git_repo'
  | 'unsupported_target'
  | 'target_not_authorized'
  | 'no_surface_snapshot'
  | 'target_not_found'
  | 'cancelled';

function fail(
  code: RefusalCode,
  message: string,
  retryWith?: Record<string, unknown>,
): ToolResult<Record<string, unknown>> {
  return {
    ok: false,
    error: { code, message, ...(retryWith === undefined ? {} : { retry_with: retryWith }) },
  };
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as Inputs;

  // ---- 1. Project path -------------------------------------------------
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // Same code map_attack_surface and detect_stack return for an unusable
    // project_path, so hosts and skills handle one failure and not three.
    return fail('not_a_git_repo', (e as Error).message);
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
    return fail(
      'no_surface_snapshot',
      'No attack-surface snapshot exists for this project, so there is no route inventory to ' +
        'probe. Run map_attack_surface first, then re-run scan_dast. This is a refusal and not ' +
        'an empty scan on purpose: "zero routes probed" must never read as "zero problems found".',
      { run_first: 'map_attack_surface', project_path: projectPath },
    );
  }
  const snapshot: AttackSurfaceSnapshot = persisted.snapshot;

  // ---- 4. Credentials --------------------------------------------------
  const warnings: string[] = [];
  const credential = resolveCredential(inp, warnings);
  const redact = makeRedactor(collectSecrets(credential.value));

  const timeoutMs =
    typeof inp.timeout_ms === 'number' && inp.timeout_ms > 0
      ? Math.floor(inp.timeout_ms)
      : DEFAULT_PROBE_TIMEOUT_MS;
  const maxRequests =
    typeof inp.max_requests === 'number' && inp.max_requests > 0
      ? Math.floor(inp.max_requests)
      : DEFAULT_MAX_REQUESTS;
  const probeOpts: ProbeOptions = { timeoutMs, concurrency: DEFAULT_CONCURRENCY };
  if (callMeta?.signal !== undefined) probeOpts.signal = callMeta.signal;
  const aborted = (): boolean => callMeta?.signal?.aborted === true;

  // ---- 5. Liveness -----------------------------------------------------
  // Deliberately NOT fed into the analysis: it is a connectivity check, not a
  // planned probe, and letting an unplanned request at `/` reach the checks
  // would produce findings about a path the inventory never listed.
  const liveness = await executeProbe(livenessRequest(target.origin), probeOpts);
  if (liveness.outcome !== 'completed') {
    if (aborted()) return fail('cancelled', 'Scan was cancelled by the host.');
    return fail('target_not_found', livenessMessage(target, liveness, timeoutMs));
  }

  // ---- 6. Scan row + report directory ----------------------------------
  const scanId = randomUUID();
  const treeHash = await computeTreeHash(projectPath);
  if (persisted.tree_hash !== treeHash) {
    warnings.push(
      'The attack-surface snapshot was taken at a different working-tree state than the one on ' +
        'disk now — routes added or moved since then were not probed. Re-run map_attack_surface ' +
        'for an up-to-date inventory.',
    );
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
    warnings.push(
      'The attack-surface snapshot contains no routes, so nothing was probed. Every per-route ' +
        'check reports no_candidate rather than a clean result — this is not a scan that found ' +
        'nothing.',
    );
  }
  if (plan.truncated) {
    warnings.push(
      `The max_requests ceiling (${maxRequests}) cut the plan: ` +
        `${plan.skipped.filter((s) => s.reason === 'cap').length} request(s) were not sent. ` +
        'Raise max_requests to cover the whole inventory.',
    );
  }

  // A host cancellation is a half-finished scan. Finalizing it `cancelled`
  // rather than `completed` is what keeps a partial run out of `getLatest()`
  // and out of every diff and baseline computed from it.
  const cancel = (): ToolResult<Record<string, unknown>> => {
    ctx.storage.scans.finalize({
      scan_id: scanId,
      status: 'cancelled',
      tools_run: [{ name: DAST_ENGINE, status: 'failed', reason: 'cancelled by the host' }],
      missing_tools: [],
    });
    return fail('cancelled', 'Scan was cancelled by the host.');
  };

  const results = await executeProbes(plan.requests, probeOpts);
  if (aborted()) return cancel();

  const analyzeInput: AnalyzeInput = {
    plan,
    results,
    origin: target.origin,
    shadowPaths: specPaths(snapshot, 'code_only'),
    deadDocPaths: specPaths(snapshot, 'spec_only'),
    hasCredentials: credential.value !== null,
  };
  const findings: DastFinding[] = [...analyzeRoutes(analyzeInput), ...analyzeOrigin(analyzeInput)];

  const completed = results.filter((r) => r.outcome === 'completed').length;
  const toolsRun: ToolRun[] = [
    {
      name: DAST_ENGINE,
      status: 'ok',
      reason:
        `${plan.requests.length} request(s) planned, ${completed} completed, ` +
        `${results.length - completed} did not answer`,
    },
  ];
  const missingTools: string[] = [];

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
    probeOpts,
    aborted,
  });
  if (burst.finding !== null) findings.push(burst.finding);

  // ---- 9. Optional nuclei pass -----------------------------------------
  const nuclei = await runNuclei({
    requested: inp.use_nuclei === true,
    binaryPath: inp.use_nuclei === true ? await scannerAvailable('nuclei') : null,
    origin: target.origin,
    outputDir: evidenceDir,
    routes: snapshot.routes,
    readOutput: readJsonSafe,
    ...(callMeta?.signal === undefined ? {} : { signal: callMeta.signal }),
  });
  findings.push(...nuclei.findings);
  if (nuclei.toolRun !== null) toolsRun.push(nuclei.toolRun);
  if (nuclei.missing) missingTools.push('nuclei');

  // The burst and the nuclei pass both stop early on cancellation, so a
  // second check here is what stops a half-run being written as `completed`.
  if (aborted()) return cancel();

  // ---- 10. Evidence + persistence --------------------------------------
  const ordered = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.fingerprint.localeCompare(b.fingerprint),
  );
  const records: EvidenceRecord[] = ordered.map(
    (f) => burst.evidence.get(f.fingerprint) ?? buildEvidence(f, target.origin, results),
  );
  const written = writeEvidenceFiles(evidenceDir, records, redact);
  if (written.capped > 0) {
    warnings.push(
      `${written.capped} finding(s) have no evidence file: the per-scan evidence cap was reached. ` +
        'The findings themselves are complete; only their raw request/response pairs were dropped.',
    );
  }
  if (written.failed > 0) {
    warnings.push(`${written.failed} evidence file(s) could not be written to ${evidenceDir}.`);
  }

  // Redaction is applied to the stored rows as a whole, not to a hand-picked
  // set of fields — see `redact.ts` for why "we never put it there" is not a
  // guarantee.
  ctx.storage.findings.bulkInsert(
    ordered.map((f) =>
      redactObject(
        toInsertInput(f, scanId, written.written.has(f.fingerprint) ? evidenceDir : null),
        redact,
      ),
    ),
  );

  const checks = computeCheckStatuses({
    plan,
    results,
    hasSpecDiff: snapshot.spec_diff !== null,
    hasCredentials: credential.value !== null,
    rateLimit: burst.outcome,
    nuclei: nuclei.outcome,
  });

  const { coverage, warning: coverageWarning } = assessCoverage('dast', toolsRun, missingTools);
  if (coverageWarning !== null) warnings.unshift(coverageWarning);

  const meta: Record<string, unknown> = {
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
    checks,
    evidence_dir: evidenceDir,
  };
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: toolsRun,
    missing_tools: missingTools,
    report_dir: evidenceDir,
    meta: redactObject(meta, redact),
  });

  const record = ctx.storage.scans.getById(scanId);
  const payload: Record<string, unknown> = {
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
      truncated: plan.truncated,
      max_requests: maxRequests,
      skipped: plan.skipped,
      checks,
      rate_limit: burst.summary,
    },
  };
  // The final choke point: every string on the way out, whatever produced it.
  return { ok: true, ...redactObject(payload, redact) };
}

/* -------------------------------------------------------------------- */
/* Credentials                                                           */
/* -------------------------------------------------------------------- */

interface ResolvedCredential {
  /** Already the header VALUE — never an environment-variable name. */
  value: string | null;
  /** For the audit trail. `env:NAME` records the name, never the secret. */
  source: string;
}

/**
 * `auth_header_env` wins when both are supplied: it is the recommended path
 * and the one whose secret never entered the transcript. An unset variable is
 * a reported warning and not a silent anonymous run — the caller asked for
 * authenticated probing and did not get it, and a scan that quietly drops the
 * credential reports `differential_authz` as if it had been tested.
 */
function resolveCredential(inp: Inputs, warnings: string[]): ResolvedCredential {
  const envName = inp.auth_header_env;
  if (envName !== undefined && envName !== '') {
    if (inp.auth_header !== undefined) {
      warnings.push(
        `Both auth_header_env and auth_header were supplied; auth_header_env (${envName}) was ` +
          'used and the literal auth_header was ignored.',
      );
    }
    const value = process.env[envName];
    if (value === undefined || value === '') {
      warnings.push(
        `auth_header_env named the environment variable ${envName}, but it is not set in this ` +
          'process. The scan ran ANONYMOUSLY: the differential-authorization check did not run ' +
          'and no authenticated probe was sent. Export the variable and re-run.',
      );
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
function specPaths(
  snapshot: AttackSurfaceSnapshot,
  side: 'code_only' | 'spec_only',
): ReadonlySet<string> {
  const out = new Set<string>();
  const diff = snapshot.spec_diff;
  if (diff === null) return out;
  for (const entry of diff[side]) {
    const route = side === 'code_only' ? entry.code_route : entry.spec_route;
    if (route !== undefined) out.add(route.path_resolved);
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
function toInsertInput(
  finding: DastFinding,
  scanId: string,
  evidenceDir: string | null,
): Finding & { scan_id: string; raw: unknown } {
  const { check, evidence_id, ...rest } = finding;
  return {
    ...rest,
    scan_id: scanId,
    raw: {
      check,
      evidence_id,
      evidence_file:
        evidenceDir === null ? null : join(evidenceDir, `${finding.fingerprint}.json`),
    },
  };
}

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) out[finding.severity] += 1;
  return out;
}
