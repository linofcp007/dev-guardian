/**
 * `buildSnapshot` — the single project-scoped query pass behind both
 * dashboard views (`dev-guardian status` and `dev-guardian dashboard`). See
 * `docs/superpowers/specs/2026-08-15-local-dashboard-design.md` §4 (scoping),
 * §5 (the snapshot), §5.1 (no data) and §7 (the two deltas).
 *
 * This is the ONLY module in the feature that touches storage — `risk.ts`,
 * `delta.ts` and `hotspots.ts` are pure functions this module calls with
 * already-scoped inputs. That split is what lets the two renderers (not yet
 * written) agree with each other by construction: there is one source, and
 * it is computed once.
 *
 * Project scoping is not a preference here, it is the reason this module
 * exists: `findings.listOpen()` and `scans.getLatest()` answer "the latest
 * completed scan in the WHOLE database, from ANY project" (see the doc
 * comments at `storage/findingsRepo.ts:174-191` and `storage/scansRepo.ts`'s
 * `getLatest`) — correct for a caller with no project in scope, and silently
 * wrong for this one, which has resolved a `project_path` and must never let
 * another project's data stand in for it. This module therefore calls only
 * the `ForProject` repository variants (`scans.getLatestForProject`,
 * `scans.listHistoryForProject`, `findings.listOpenForProject`) plus
 * `findings.listByScan(scanId)`, which is safe by construction: it takes an
 * explicit scan id already resolved through a project-scoped path (scan
 * history, or a validated baseline — see `resolveBaseline` below), never an
 * implicit "latest" selection.
 *
 * `baselines.getActive()` and `suppressions.listActive()` have no
 * project-scoped variant — the `baselines` table has no `project_path`
 * column at all (schema fact, not an oversight of this task), and
 * suppressions are keyed by finding fingerprint, which can outlive the scan
 * that produced it. Suppressions are used as global state deliberately (a
 * suppression is meant to apply everywhere that fingerprint appears).
 * Baselines are not: `BaselineState.active`'s own doc comment reads "null ⇒
 * no baseline has ever been set for THIS PROJECT", so `resolveBaseline`
 * below cross-checks the active baseline's scan against `projectPath` before
 * trusting it, and treats a baseline pointing at another project's scan as
 * absent — the same failure shape as the listOpen() hazard above, just for a
 * field the schema cannot filter by project in SQL.
 */

import type { Storage } from '../storage/index.js';
import type { Cve, Finding, ScanRecord, Severity, Suppression } from '../types.js';
import { compareFindings } from './delta.js';
import { rankFiles } from './hotspots.js';
import { scoreRisk } from './risk.js';
import {
  TOOL_CATEGORIES,
  type BaselineState,
  type CoverageState,
  type CveSummary,
  type DashboardSnapshot,
  type FindingDelta,
  type FindingsSummary,
  type RiskAssessment,
  type ScanSummary,
  type SuppressionState,
  type TruncationNotice,
} from './types.js';

/** Design §8: findings inlined for display are capped at 2000 items. */
const FINDINGS_CAP = 2000;
/** Design §8: new-findings-per-delta are capped at 500, for EACH delta. */
const DELTA_CAP = 500;
/** How far back `listHistoryForProject` looks for a same-type previous scan.
 *  Mirrors `tools/riskScore.ts`'s own `listHistory(50)` convention for "find
 *  the latest scan of a given type" — this feature does not invent a second
 *  policy for the same kind of lookup. */
const HISTORY_LOOKBACK = 50;
/** Design §5: "Active suppressions expiring within 7 days." */
const EXPIRING_SOON_MS = 7 * 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export function buildSnapshot(
  storage: Storage,
  projectPath: string,
  now: number,
): DashboardSnapshot {
  const currentScan = storage.scans.getLatestForProject(projectPath);
  const truncation: TruncationNotice[] = [];

  const coverage = buildCoverage(currentScan);

  // Already project-scoped AND already suppression-filtered by
  // listOpenForProjectStmt's own SQL — this is both the basis of
  // `FindingsSummary` and the "to" side of `since_previous` below. Safe on a
  // project with no completed scan: the underlying CTE then matches zero
  // rows and the join returns [], never an error.
  const openFindings = storage.findings.listOpenForProject(projectPath);
  const findings = buildFindingsSummary(openFindings, truncation);

  const cveItems: Cve[] = currentScan ? storage.cves.listActive(currentScan.scan_id) : [];
  const cves = buildCveSummary(cveItems);

  // Suppression state used to manually filter the OTHER scans this module
  // reads via listByScan (which, unlike listOpenForProject, does not exclude
  // suppressions itself) — "both sides are suppression-filtered before
  // comparison" (design §7), and it is the same live suppression state used
  // for SuppressionState below, so this is one fetch serving both.
  const activeSuppressions = storage.suppressions.listActive();
  const suppressedFingerprints = new Set(activeSuppressions.map((s) => s.finding_fingerprint));

  const sincePrevious = currentScan
    ? buildSincePrevious(storage, projectPath, currentScan, openFindings, suppressedFingerprints, truncation)
    : null;

  const resolvedBaseline = resolveBaseline(storage, projectPath);
  const baseline = buildBaselineState(resolvedBaseline, now);
  const sinceBaseline = currentScan && resolvedBaseline
    ? buildSinceBaseline(storage, resolvedBaseline, currentScan, openFindings, suppressedFingerprints, truncation)
    : null;

  const suppressions = buildSuppressionState(activeSuppressions, now);

  const risk = currentScan
    ? scoreRisk({
        findings: openFindings,
        cves: cveItems,
        // No compliance-scan or dependency-bot signal is gathered by this
        // pass (see task-3-report.md's "scope decisions" — the brief's
        // storage list does not name a path to it, and no given test
        // exercises it). "No signal" mirrors risk_score's own default for
        // the same absence (tools/riskScore.ts: "No deps-audit scan yet ⇒ no
        // signal ⇒ no penalty"), not an invented value.
        policies_missing: 0,
        dependency_bot_configured: true,
        baseline_set_at: resolvedBaseline ? resolvedBaseline.set_at : null,
        coverage_partial: coverage.level !== 'full',
        now,
      })
    : noScanRisk();

  return {
    project_path: projectPath,
    generated_at: new Date(now).toISOString(),
    scan: currentScan ? toScanSummary(currentScan, now) : null,
    coverage,
    risk,
    findings,
    cves,
    deltas: { since_previous: sincePrevious, since_baseline: sinceBaseline },
    baseline,
    suppressions,
    truncation,
  };
}

function toScanSummary(scan: ScanRecord, now: number): ScanSummary {
  const durationSeconds = scan.finished_at !== null
    ? (Date.parse(scan.finished_at) - Date.parse(scan.started_at)) / 1000
    : null;
  return {
    scan_id: scan.scan_id,
    scan_type: scan.scan_type,
    status: scan.status,
    started_at: scan.started_at,
    finished_at: scan.finished_at,
    duration_seconds: durationSeconds,
    age_seconds: (now - Date.parse(scan.finished_at ?? scan.started_at)) / 1000,
  };
}

function buildCoverage(currentScan: ScanRecord | null): CoverageState {
  const missingTools = currentScan?.missing_tools ?? [];
  const toolsRun = (currentScan?.tools_run ?? []).map((t) => t.name);
  const level: CoverageState['level'] =
    currentScan === null ? 'none' : missingTools.length > 0 ? 'partial' : 'full';
  return {
    level,
    tools_run: toolsRun,
    missing_tools: missingTools,
    omitted_categories: omittedCategoriesFor(missingTools),
  };
}

/** Maps each missing tool through TOOL_CATEGORIES, falling back to the
 *  tool's own name so an unrecognised scanner is named rather than dropped —
 *  de-duplicated on the OUTPUT category (two missing tools could share one
 *  category), insertion order preserved. */
function omittedCategoriesFor(missingTools: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const tool of missingTools) {
    const category = TOOL_CATEGORIES[tool] ?? tool;
    if (!seen.has(category)) {
      seen.add(category);
      result.push(category);
    }
  }
  return result;
}

function buildFindingsSummary(
  openFindings: readonly Finding[],
  truncation: TruncationNotice[],
): FindingsSummary {
  const items = openFindings.slice(0, FINDINGS_CAP);
  if (items.length < openFindings.length) {
    truncation.push({
      what: 'findings.items',
      shown: items.length,
      total: openFindings.length,
      reason: `findings exceeds the cap of ${FINDINGS_CAP}; showing the first ` +
        `${items.length} of ${openFindings.length}`,
    });
  }

  // The full set, not `items` — total/grouping/hotspots must never be
  // computed from a capped subset, or the display cap would silently corrupt
  // the very numbers §2 exists to keep honest. `openFindings.length` as the
  // rankFiles limit is always enough: a set of N findings can never span more
  // than N distinct files, so this returns every file, never truncated.
  return {
    total: openFindings.length,
    by_severity: groupBySeverity(openFindings),
    by_category: groupBy(openFindings, (f) => f.category),
    by_tool: groupBy(openFindings, (f) => f.tool),
    hotspots: rankFiles(openFindings, openFindings.length).hotspots,
    items,
  };
}

function buildCveSummary(cveItems: readonly Cve[]): CveSummary {
  return {
    total: cveItems.length,
    by_severity: groupBySeverity(cveItems),
    items: [...cveItems],
  };
}

function buildSincePrevious(
  storage: Storage,
  projectPath: string,
  currentScan: ScanRecord,
  openFindings: readonly Finding[],
  suppressedFingerprints: ReadonlySet<string>,
  truncation: TruncationNotice[],
): FindingDelta | null {
  const history = storage.scans.listHistoryForProject(projectPath, HISTORY_LOOKBACK);
  const previous = history.find(
    (s) =>
      s.status === 'completed' &&
      s.scan_id !== currentScan.scan_id &&
      s.scan_type === currentScan.scan_type,
  );
  if (previous === undefined) return null;

  const previousFindings = filterSuppressed(
    storage.findings.listByScan(previous.scan_id),
    suppressedFingerprints,
  );
  const { delta, truncation: cut } = compareFindings(
    { scan_id: previous.scan_id, findings: previousFindings },
    { scan_id: currentScan.scan_id, findings: openFindings },
    DELTA_CAP,
  );
  if (cut !== null) truncation.push({ ...cut, what: 'deltas.since_previous.new_findings' });
  return delta;
}

function buildSinceBaseline(
  storage: Storage,
  resolvedBaseline: ResolvedBaseline,
  currentScan: ScanRecord,
  openFindings: readonly Finding[],
  suppressedFingerprints: ReadonlySet<string>,
  truncation: TruncationNotice[],
): FindingDelta {
  const baselineFindings = filterSuppressed(
    storage.findings.listByScan(resolvedBaseline.scan_id),
    suppressedFingerprints,
  );
  const { delta, truncation: cut } = compareFindings(
    { scan_id: resolvedBaseline.scan_id, findings: baselineFindings },
    { scan_id: currentScan.scan_id, findings: openFindings },
    DELTA_CAP,
  );
  if (cut !== null) truncation.push({ ...cut, what: 'deltas.since_baseline.new_findings' });
  return delta;
}

interface ResolvedBaseline {
  id: number;
  scan_id: string;
  set_at: string;
  note?: string;
}

/**
 * The active baseline, but ONLY when its scan belongs to `projectPath`.
 * `baselines.getActive()` is global (no `project_path` column exists on that
 * table), so without this check a baseline set from another project's scan
 * would silently become this project's reference point — exactly the
 * "another project's data, and nothing about the output suggests it" failure
 * this module exists to close off, just reached through a field the schema
 * cannot filter in SQL. `scans.getById` is safe to use for the check itself:
 * it is an explicit-id lookup, not an implicit "latest" one.
 */
function resolveBaseline(storage: Storage, projectPath: string): ResolvedBaseline | null {
  const active = storage.baselines.getActive();
  if (active === null) return null;
  const scan = storage.scans.getById(active.scan_id);
  if (scan === null || scan.project_path !== projectPath) return null;
  const resolved: ResolvedBaseline = { id: active.id, scan_id: active.scan_id, set_at: active.set_at };
  if (active.note !== undefined) resolved.note = active.note;
  return resolved;
}

function buildBaselineState(resolved: ResolvedBaseline | null, now: number): BaselineState {
  if (resolved === null) return { active: null, age_days: null };
  const active: BaselineState['active'] = {
    baseline_id: resolved.id,
    scan_id: resolved.scan_id,
    set_at: resolved.set_at,
  };
  if (resolved.note !== undefined) active.note = resolved.note;
  return {
    active,
    age_days: Math.floor((now - Date.parse(resolved.set_at)) / DAY_MS),
  };
}

function buildSuppressionState(
  activeSuppressions: readonly Suppression[],
  now: number,
): SuppressionState {
  const cutoff = now + EXPIRING_SOON_MS;
  const expiringSoon: SuppressionState['expiring_soon'] = [];
  for (const s of activeSuppressions) {
    if (s.expires_at === undefined) continue;
    if (Date.parse(s.expires_at) > cutoff) continue;
    expiringSoon.push({ fingerprint: s.finding_fingerprint, reason: s.reason, expires_at: s.expires_at });
  }
  expiringSoon.sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));

  return {
    active_count: activeSuppressions.length,
    expiring_soon: expiringSoon,
  };
}

/**
 * Design §5.1, verbatim: a project with no completed scan is *unknown*, not
 * safe. `scoreRisk` is not called here at all — feeding it empty findings/no
 * baseline would still charge the 8-point "never set a baseline" penalty
 * (`risk.ts`'s `baseline_set_at === null` branch), producing a small
 * nonzero score that LOOKS like a measurement of something. There is nothing
 * to measure yet, so the score is the literal 0 the design specifies, not an
 * arithmetic result that happens to be low.
 */
function noScanRisk(): RiskAssessment {
  return {
    score: 0,
    band: 'low',
    components: {
      findings: { score: 0, open_findings: 0 },
      cves: { score: 0, active_cves: 0 },
      compliance: { score: 0, policies_missing: 0 },
      baseline: { score: 0, has_active_baseline: false },
    },
    next_action:
      'Run `dev-guardian scan` (or /guardian-scan) — this project has not been scanned yet.',
    coverage_caveat: true,
  };
}

function filterSuppressed(findings: readonly Finding[], suppressed: ReadonlySet<string>): Finding[] {
  return findings.filter((f) => !suppressed.has(f.fingerprint));
}

function groupBy(findings: readonly Finding[], keyOf: (f: Finding) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    const key = keyOf(f);
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

/** Every severity initialised to 0 so a severity absent from the data reads
 *  as 0, never as undefined — mirrors `findingsRepo.ts`'s `countBySeverity`. */
function groupBySeverity(items: readonly { severity: Severity }[]): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const item of items) {
    out[item.severity] += 1;
  }
  return out;
}
