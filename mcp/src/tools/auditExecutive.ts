/**
 * `audit_executive` — runs security + quality + deps + compliance scans
 * (and the WordPress / .NET ones the project's stack calls for) CONCURRENTLY,
 * into a single roll-up report.
 *
 * Each sub-tool already persists its own scan record; this tool calls them
 * through the in-process `TOOLS` registry. After the sub-runs we:
 *   - insert a parent `audit` scan row,
 *   - aggregate severity counts and top findings across all four,
 *   - compute deltas vs the previous `audit` scan if one exists.
 *
 * The audit scan row links to the children via `meta.sub_scan_ids` so
 * future tools (or a future report exporter) can fan back out.
 *
 * **What leaves the machine (review 3.0 I3).** The children reach the Semgrep
 * registry with usage metrics, Trivy's database, npm and PyPI (pip-audit
 * installs requirements, building sdists), and a .NET project's NuGet feeds
 * (`dotnet restore` executes its MSBuild) — none of which the description
 * said, and it said "in sequence" of what runs concurrently. `local_only` is
 * passed to every child that takes one (security_scan_full); scan_wordpress,
 * whose Semgrep packs come from the registry and which has no local-only
 * mode, is skipped with the reason; and the result's `local_only_gaps` names
 * what local_only does not stop, as SECURITY.md does.
 */

import { randomUUID } from 'node:crypto';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { z } from 'zod';
import { ProjectPath, SeverityMin } from '../schemas.js';
import { filterFindings } from '../severity/filter.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import {
  SEVERITY_ORDER,
  type DomainError,
  type Finding,
  type FindingsCountBySeverity,
  type ScanCoverage,
  type Severity,
  type ToolResult,
  type ToolRun,
} from '../types.js';
import { registerToolModule, TOOLS, type ToolCallMeta, type ToolModule } from './index.js';

const BASE_SUB_TOOLS = ['security_scan_full', 'quality_check', 'deps_audit', 'compliance_check'] as const;
const WP_EXTRA_SUB_TOOLS = ['scan_wordpress'] as const;
const DOTNET_EXTRA_SUB_TOOLS = ['scan_dotnet_secrets', 'dotnet_target_framework_check'] as const;

interface SubScanSummary {
  tool: string;
  scan_id?: string;
  ok: boolean;
  /** Not run, on purpose: why (only under `local_only`). */
  skipped?: string;
  error?: { code: string; message: string };
  findings_count_by_severity?: FindingsCountBySeverity;
  top_findings?: Finding[];
  coverage?: ScanCoverage;
  missing_tools?: string[];
  warnings?: string[];
}

const tool: ToolModule = {
  name: 'audit_executive',
  title: 'Executive audit (security + quality + deps + compliance)',
  description:
    'Executive roll-up: runs security_scan_full, quality_check, deps_audit and compliance_check ' +
    'CONCURRENTLY, plus scan_wordpress for a WordPress project and scan_dotnet_secrets + ' +
    "dotnet_target_framework_check for .NET, per this project's latest detect_stack. Returns one report: " +
    'severity counts, top-10 findings, the worst child coverage with each gap, and a delta vs this ' +
    "project's previous audit. EGRESS: the Semgrep registry with usage metrics to Semgrep Inc. " +
    "(security_scan_full, scan_wordpress); Trivy's vulnerability database and Maven Central for a " +
    "pom.xml (dev-guardian turns Trivy's version check and telemetry off, and Semgrep's version check); npm audit and PyPI " +
    "(deps_audit); the project's NuGet feeds. CODE EXECUTION: pip-audit installs the requirements into a " +
    "temporary virtualenv (an sdist's build step runs); a .NET restore/build runs the project's MSBuild " +
    "targets; quality_check runs the project's ESLint config. local_only=true passes local_only to " +
    'security_scan_full (Semgrep: rules on disk, --metrics=off) and skips scan_wordpress, which has no ' +
    "local-only mode; it does NOT stop Trivy's requests, deps_audit's registry calls or a .NET " +
    'restore — the result lists those in local_only_gaps.',
  inputSchema: {
    project_path: ProjectPath,
    severity_min: SeverityMin,
    local_only: z
      .boolean()
      .optional()
      .describe(
        'Passed to every child that takes it (security_scan_full: Semgrep rules on disk only, --metrics=off). ' +
          'scan_wordpress, which has no local-only mode, is skipped. Trivy, deps_audit and a .NET restore still ' +
          'reach the network; local_only_gaps in the result says what did. Default: false.',
      ),
  },
  handler: async (input, ctx, callMeta) => handler(input, ctx, callMeta),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; severity_min?: Severity; local_only?: boolean };
  const localOnly = inp.local_only === true;

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  // No bash check: none of the sub-tools runs a shell script any more.

  // Pre-record the audit scan so the children can be linked by id even if a
  // later step fails. tree_hash is captured up front so it reflects the
  // pre-audit state.
  const auditScanId = randomUUID();
  const treeHash = await computeTreeHash(projectPath);
  ctx.storage.scans.insert({
    scan_id: auditScanId,
    scan_type: 'audit',
    project_path: projectPath,
    tree_hash: treeHash,
    meta: { sub_scan_ids: {} },
  });

  const subResults: Record<string, SubScanSummary> = {};
  const aggregateFindings: Finding[] = [];

  // Sub-tools are independent (write to separate report dirs, separate scan
  // rows). Running them concurrently turns a 4× sequential wait into a
  // 1× max-of-four. SQLite is single-writer but our writes are short and
  // WAL handles the contention.
  const subInput: Record<string, unknown> = { project_path: projectPath };
  if (inp.severity_min) subInput['severity_min'] = inp.severity_min;

  // Stack-aware: extend the base set with WP / .NET tools when the latest
  // stack snapshot OF THIS PROJECT indicates those languages.
  const subTools = buildSubToolsForStack(ctx, projectPath);

  const subResultsArr = await Promise.all(
    subTools.map(async (toolName) => {
      const skipped = localOnly ? NO_LOCAL_ONLY_MODE[toolName] : undefined;
      if (skipped !== undefined) {
        return [toolName, { tool: toolName, ok: false, skipped } satisfies SubScanSummary] as const;
      }
      const subTool = TOOLS.find((t) => t.name === toolName);
      if (!subTool) {
        return [
          toolName,
          {
            tool: toolName,
            ok: false,
            error: { code: 'scanner_failed', message: `Tool '${toolName}' is not registered.` },
          } satisfies SubScanSummary,
        ] as const;
      }
      // The host's callMeta, so cancelling the audit aborts every sub-scan's
      // scanner processes and their progress reaches the host (the emitter
      // keeps one shared token's progress increasing across all four).
      const childInput =
        localOnly && 'local_only' in subTool.inputSchema ? { ...subInput, local_only: true } : subInput;
      const result = await subTool.handler(childInput, ctx, callMeta);
      if (result.ok) {
        const r = result as unknown as {
          ok: true;
          scan_id?: string;
          findings_count_by_severity?: FindingsCountBySeverity;
          top_findings?: Finding[];
          coverage?: ScanCoverage;
          missing_tools?: string[];
          warnings?: string[];
        };
        const summary: SubScanSummary = { tool: toolName, ok: true };
        if (r.scan_id !== undefined) summary.scan_id = r.scan_id;
        if (r.findings_count_by_severity !== undefined)
          summary.findings_count_by_severity = r.findings_count_by_severity;
        if (r.top_findings !== undefined) summary.top_findings = r.top_findings;
        if (r.coverage !== undefined) summary.coverage = r.coverage;
        if (r.missing_tools !== undefined) summary.missing_tools = r.missing_tools;
        if (r.warnings !== undefined) summary.warnings = r.warnings;
        return [toolName, summary] as const;
      }
      return [
        toolName,
        { tool: toolName, ok: false, error: result.error } satisfies SubScanSummary,
      ] as const;
    }),
  );

  for (const [name, summary] of subResultsArr) {
    subResults[name] = summary;
  }

  // Update audit row meta to link children.
  const subScanIds: Record<string, string | null> = {};
  for (const [name, summary] of Object.entries(subResults)) {
    subScanIds[name] = summary.scan_id ?? null;
  }

  // Cancelled by the host: the sub-scans were aborted (they share its
  // signal), so there is nothing to aggregate. The row is finalised
  // `cancelled`, never `completed` — a completed audit with zero findings
  // became the previous audit of the next one, whose delta then reported
  // every finding as new and nothing as resolved.
  if (callMeta?.signal?.aborted === true) {
    ctx.storage.scans.finalize({
      scan_id: auditScanId,
      status: 'cancelled',
      tools_run: subToolRuns(subTools, subResults),
      missing_tools: [],
      meta: { sub_scan_ids: subScanIds, ...(localOnly ? { local_only: true } : {}) },
    });
    return failDomain(
      'cancelled',
      'The audit was cancelled by the host; its sub-scans were stopped and nothing was aggregated.',
    );
  }

  for (const summary of Object.values(subResults)) {
    if (summary.ok && summary.scan_id) {
      aggregateFindings.push(...ctx.storage.findings.listByScan(summary.scan_id));
    }
  }

  // Severity floor: re-apply at the aggregate level so audit_executive's own
  // counts match what the model asked for. The floor stops at the RESPONSE —
  // `aggregateFindings` stays whole for the delta and the snapshot below,
  // the same rule `scanToolFactory.ts` follows for the sub-scans this rolls
  // up. See that file's `bulkInsert` comment.
  const filteredAggregate = filterFindings(aggregateFindings, inp.severity_min);
  const aggregate_counts = countBySeverity(filteredAggregate);
  const top_findings = topFindings(filteredAggregate, 10);

  // Delta vs previous audit scan, when one exists. Compared unfiltered on
  // BOTH sides: the previous audit row holds whatever its own call found,
  // and measuring a filtered present against an unfiltered past reports
  // every below-floor finding as `resolved`.
  const previousAudit = findPreviousAudit(ctx, projectPath, auditScanId);
  let deltas: Record<string, unknown> | undefined;
  if (previousAudit) {
    const prevFindings = ctx.storage.findings.listByScan(previousAudit);
    const prevFingerprints = new Set(prevFindings.map((f) => f.fingerprint));
    const curFingerprints = new Set(aggregateFindings.map((f) => f.fingerprint));
    let newCount = 0;
    let resolvedCount = 0;
    for (const fp of curFingerprints) if (!prevFingerprints.has(fp)) newCount += 1;
    for (const fp of prevFingerprints) if (!curFingerprints.has(fp)) resolvedCount += 1;
    deltas = {
      since_audit_scan_id: previousAudit,
      new_findings: newCount,
      resolved_findings: resolvedCount,
    };
  }

  // Persist a snapshot of the aggregated findings on the audit row so
  // diff_scans can run against the audit scan_id directly. UNFILTERED, for
  // exactly that reason: a `severity_min` on this call is a request for a
  // thinner report, not for a baseline that forgets everything below the
  // floor. The sub-scan rows already hold the same findings in full.
  if (aggregateFindings.length > 0) {
    ctx.storage.findings.bulkInsert(
      // Re-key under the audit scan_id; INSERT OR IGNORE handles the cases
      // where a finding already exists on the audit row (unlikely but safe).
      aggregateFindings.map((f) => ({ ...f, scan_id: auditScanId })),
    );
  }
  // Coverage roll-up: the aggregate "0 critical" is only trustworthy when
  // every sub-scan actually ran its scanners. Take the worst coverage across
  // the children and surface each gap (including the loud "0 findings is not
  // clean" line from a sub-scan that scanned nothing) so the executive summary
  // can never be mistaken for a clean bill of health.
  const aggregateMissing = new Set<string>();
  const coverageList: ScanCoverage[] = [];
  const coverage_warnings: string[] = [];
  for (const summary of Object.values(subResults)) {
    if (summary.skipped !== undefined) {
      coverageList.push('partial');
      coverage_warnings.push(`${summary.tool}: skipped — ${summary.skipped}`);
      continue;
    }
    if (!summary.ok) {
      coverageList.push('none');
      coverage_warnings.push(
        `${summary.tool}: did not run (${summary.error?.code ?? 'failed'}) — not covered.`,
      );
      continue;
    }
    coverageList.push(summary.coverage ?? 'full');
    for (const m of summary.missing_tools ?? []) aggregateMissing.add(m);
    if (summary.coverage && summary.coverage !== 'full') {
      const loud = (summary.warnings ?? []).find((w) => w.startsWith('⚠️'));
      coverage_warnings.push(loud ?? `${summary.tool}: coverage=${summary.coverage}.`);
    }
  }
  const overallCoverage = worstCoverage(coverageList);
  const local_only_gaps = localOnly ? localOnlyGaps(subTools) : [];

  ctx.storage.scans.finalize({
    scan_id: auditScanId,
    status: 'completed',
    tools_run: subToolRuns(subTools, subResults),
    missing_tools: [...aggregateMissing],
    // `sub_scan_ids` was computed above and never written — the insert-time
    // placeholder `{}` was all the row ever carried. It is written here
    // because `severity_min` has to go on the same row (the audit findings
    // are now stored unfiltered, so nothing else distinguishes "found
    // nothing above high" from "filtered at high") and `finalize`'s
    // `COALESCE(?, meta)` replaces the whole JSON blob rather than merging
    // into it.
    meta: {
      sub_scan_ids: subScanIds,
      ...(inp.severity_min !== undefined ? { severity_min: inp.severity_min } : {}),
      ...(localOnly ? { local_only: true } : {}),
    },
  });

  return {
    ok: true,
    scan_id: auditScanId,
    project_path: projectPath,
    sub_scans: subResults,
    aggregate_counts,
    coverage: overallCoverage,
    ...(coverage_warnings.length > 0 ? { coverage_warnings } : {}),
    ...(localOnly ? { local_only_gaps } : {}),
    top_findings,
    ...(deltas ? { deltas } : {}),
  };
}

/**
 * The children that cannot honour `local_only`, and why each is skipped under
 * it rather than run: what they would send is exactly what the caller asked
 * not to send.
 */
const NO_LOCAL_ONLY_MODE: Readonly<Record<string, string>> = {
  scan_wordpress:
    'it has no local-only mode: its Semgrep packs (p/php, p/wordpress) come from the Semgrep registry, ' +
    'with usage metrics. Run it without local_only to cover WordPress.',
};

/**
 * What `local_only` does not stop, for the children this audit ran — the
 * rows SECURITY.md lists for them.
 */
function localOnlyGaps(subTools: readonly string[]): string[] {
  const gaps: string[] = [];
  const ran = new Set(subTools);
  if (ran.has('security_scan_full')) {
    gaps.push(
      "security_scan_full: its scan_deps and scan_iac run Trivy, which downloads its vulnerability database and " +
        "checks bundle when its cache is stale; on a .NET project its scan_sast runs dotnet restore (the project's " +
        "NuGet feeds) and dotnet build, which execute the project's MSBuild targets.",
    );
  }
  if (ran.has('deps_audit')) {
    gaps.push(
      'deps_audit: npm audit queries the npm registry; pip-audit installs the requirements from PyPI into a ' +
        "temporary virtualenv (an sdist's build step runs); for .NET, dotnet restore contacts the NuGet feeds and " +
        "executes the project's MSBuild; Trivy may download its database.",
    );
  }
  // Measured, not assumed (review 3.0 round 2): Trivy 0.69.3 running
  // compliance_check's exact `fs --scanners license --quiet` against an empty
  // cache, every proxy variable on a logging proxy, downloaded no
  // vulnerability database but connected to check.trivy.dev and, for a
  // pom.xml, repo.maven.apache.org. check.trivy.dev is now turned off for
  // every Trivy run (runners/trivyRun.ts), so only Maven Central remains.
  if (ran.has('compliance_check')) {
    gaps.push(
      "compliance_check: its Trivy license scan downloads no vulnerability database, but resolves a pom.xml's " +
        'dependencies from Maven Central (its RGPD Semgrep pack already runs with --metrics=off).',
    );
  }
  // Semgrep's own version check is no gap: every Semgrep run has it off
  // (runners/semgrepRun.ts, SEMGREP_ENABLE_VERSION_CHECK=0).
  return gaps;
}

/** One `tools_run` entry per sub-tool: `ok`, `skipped` with why, or `failed` with its error code. */
function subToolRuns(
  subTools: readonly string[],
  subResults: Record<string, SubScanSummary>,
): ToolRun[] {
  return subTools.map((name) => {
    const sub = subResults[name];
    if (sub?.skipped !== undefined) return { name, status: 'skipped', reason: sub.skipped };
    const reason = sub?.error?.code;
    return {
      name,
      status: sub?.ok ? 'ok' : 'failed',
      ...(reason !== undefined ? { reason } : {}),
    };
  });
}

/** none < partial < full — the executive roll-up is only as trustworthy as
 * its least-covered sub-scan. */
function worstCoverage(list: ScanCoverage[]): ScanCoverage {
  const rank: Record<ScanCoverage, number> = { none: 0, partial: 1, full: 2 };
  return list.reduce<ScanCoverage>((worst, c) => (rank[c] < rank[worst] ? c : worst), 'full');
}

/**
 * The sub-tools for THIS project's stack. The snapshot used to be
 * `stack.getLatest()` — the newest detection of ANY project — so an audit of
 * a Node project ran scan_wordpress because a WordPress site was detected
 * last, and skipped the .NET checks of a .NET one (Task 24).
 */
function buildSubToolsForStack(ctx: PluginContext, projectPath: string): readonly string[] {
  const snap = ctx.storage.stack.getLatestForProject(projectPath)?.snapshot;
  const languages = snap?.languages ?? [];
  const frameworks = snap?.frameworks ?? [];
  const out: string[] = [...BASE_SUB_TOOLS];
  if (languages.includes('php') && frameworks.includes('wordpress')) {
    out.push(...WP_EXTRA_SUB_TOOLS);
  }
  if (languages.includes('csharp') || languages.includes('fsharp')) {
    out.push(...DOTNET_EXTRA_SUB_TOOLS);
  }
  return out;
}

/**
 * This project's newest completed audit that started before `thisAuditId` —
 * one project- and type-scoped query. It was the newest completed audit
 * among the 200 newest scans of the whole database: another project's, when
 * that project was audited more recently, so the delta compared two
 * different code bases (Task 24).
 */
function findPreviousAudit(ctx: PluginContext, projectPath: string, thisAuditId: string): string | null {
  const [prev] = ctx.storage.scans.listCompletedOfTypes(projectPath, ['audit'], {
    limit: 1,
    beforeScanId: thisAuditId,
  });
  return prev?.scan_id ?? null;
}

function countBySeverity(findings: Finding[]): FindingsCountBySeverity {
  const out: FindingsCountBySeverity = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

function topFindings(findings: Finding[], limit: number): Finding[] {
  return [...findings]
    .sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.fingerprint.localeCompare(b.fingerprint),
    )
    .slice(0, limit);
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
