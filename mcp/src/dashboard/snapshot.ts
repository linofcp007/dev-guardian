/**
 * `buildSnapshot` — the single project-scoped query pass behind both
 * dashboard views (`dev-guardian status` and `dev-guardian dashboard`). See
 * the design of record §4 (scoping),
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
 * completed scan in the WHOLE database, from ANY project" — silently wrong
 * for a caller that has resolved a `project_path` and must never let
 * another project's data stand in for it.
 *
 * Type scoping is the second half. The open findings are the project's OPEN
 * SET (`history/openSet.ts`): the union of the newest usable scan of every
 * finding-producing type, deduplicated, suppressions removed. "The latest
 * scan of the project" alone was not enough: an SBOM, a stack detection or a
 * diff review run after a SAST scan became "the scan", and the dashboard
 * showed zero findings. The scan shown (`scan`) is the newest state scan the
 * open set considered; the deltas compare the newest USABLE one against its
 * previous scan of the same type, and against the project's baseline through
 * the newest scan of the baseline's type.
 *
 * Every "latest scan of type X" — the CVE source, the compliance scan, the
 * deps-audit scan, the previous scan — is a project-scoped SQL query
 * (`history/openSet.ts#findLatestUsable`), never a search of a window of
 * recent scans. Baselines are per project and record their scan type
 * (migration 008), so `baselines.getActiveForProject` answers directly.
 *
 * Suppressions are decided against the injected `now`, once, by fingerprint
 * OR identity (`openSet.ts#suppressionMatcher`) — for the open set and for
 * both sides of both deltas alike. `suppressions.listActive()` filters
 * against the real wall clock, which would make this function's result
 * depend on the day it runs rather than on its arguments; and the delta
 * filter used to match fingerprints only, so a finding suppressed by
 * identity after a line shift came back as "resolved".
 */

import {
  findLatestUsable,
  latestStateScan,
  openSetForProject,
  suppressionMatcher,
  type OpenSet,
} from '../history/openSet.js';
import { classifyDiff, compareScansFor } from '../history/runCompare.js';
import type { ProjectBaseline } from '../storage/baselinesRepo.js';
import type { Storage } from '../storage/index.js';
import {
  CVE_SOURCE_SCAN_TYPES,
  isDepsAuditScan,
  type Cve,
  type Finding,
  type ScanRecord,
  type Severity,
  type Suppression,
} from '../types.js';
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
/** Design §5: "Active suppressions expiring within 7 days." */
const EXPIRING_SOON_MS = 7 * 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

type IsSuppressed = (f: Pick<Finding, 'fingerprint' | 'identity'>) => boolean;

export function buildSnapshot(
  storage: Storage,
  projectPath: string,
  now: number,
): DashboardSnapshot {
  const truncation: TruncationNotice[] = [];

  const open = openSetForProject(storage, projectPath, { now });
  // The scan shown: the newest state scan considered, even one skipped for
  // coverage none — it IS the latest attempt, and its gap is disclosed
  // through `coverage`. The deltas start from the newest USABLE one.
  const currentScan = open.newest;
  const deltaScan = open.newestSource;

  // The scan CVEs are actually sourced from — the newest deps-flavoured
  // scan of this project that ran a dependency scanner. `cveGap` is true
  // exactly when this project HAS a current scan but none of its scans
  // measured dependencies — CVEs are then necessarily unmeasured, not zero,
  // and that has to reach coverage or it renders as a clean "0 CVEs".
  const cveSourceScan = findLatestUsable(storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' }).scan;
  const cveGap = currentScan !== null && cveSourceScan === null;
  const coverage = buildCoverage(open, cveGap);

  const openFindings = open.findings;
  const findings = buildFindingsSummary(openFindings, truncation);

  const cveItems: Cve[] = cveSourceScan ? storage.cves.listActive(cveSourceScan.scan_id) : [];
  const cves = buildCveSummary(cveItems);

  const allSuppressions = storage.suppressions.listAll();
  const activeSuppressions = allSuppressions.filter((s) => isSuppressionActiveAt(s, now));
  const isSuppressed = suppressionMatcher(allSuppressions, now);

  const sincePrevious = deltaScan
    ? buildSincePrevious(storage, deltaScan, isSuppressed, truncation)
    : null;

  const resolvedBaseline = storage.baselines.getActiveForProject(projectPath);
  const baseline = buildBaselineState(resolvedBaseline, now);
  const sinceBaseline = deltaScan && resolvedBaseline
    ? buildSinceBaseline(storage, resolvedBaseline, projectPath, isSuppressed, truncation)
    : null;

  const suppressions = buildSuppressionState(activeSuppressions, now);

  const complianceSignals = resolveComplianceSignals(storage, projectPath);

  const risk = currentScan
    ? scoreRisk({
        findings: openFindings,
        cves: cveItems,
        policies_missing: complianceSignals.policies_missing,
        dependency_bot_configured: complianceSignals.dependency_bot_configured,
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

/**
 * Coverage of the numbers on screen: the scanners of every scan the open set
 * considered — its sources, and the newer scans it skipped for coverage none
 * (their gaps are exactly what the numbers lack) — each through the slot it
 * was considered for (`OpenSet.bookkeeping`). A script-era security_full that
 * sources only the sast slot contributes its semgrep entries, not the
 * gitleaks it was missing when a newer scan_secrets measured secrets. Names
 * de-duplicated in first-seen order.
 */
function buildCoverage(open: OpenSet, cveGap: boolean): CoverageState {
  const toolsRun: string[] = [];
  const missingTools: string[] = [];
  const partialTools: string[] = [];
  const addOnce = (list: string[], name: string): void => {
    if (!list.includes(name)) list.push(name);
  };
  for (const view of open.bookkeeping) {
    for (const t of view.tools_run) addOnce(toolsRun, t.name);
    for (const t of view.missing_tools) addOnce(missingTools, t);
    // A scanner recorded as FAILED is a gap even when `missing_tools` does
    // not name it — that is how Semgrep's exit 7 is recorded, and reading
    // `missing_tools` alone left coverage 'full' over a scan that did not
    // run (GC3). A not-applicable skip is not a gap and is not listed.
    const okNames = new Set(view.tools_run.filter((t) => t.status === 'ok').map((t) => t.name));
    for (const t of view.tools_run) {
      if (t.status === 'failed' && !okNames.has(t.name)) addOnce(missingTools, t.name);
    }
    // A name can appear in BOTH missing_tools and tools_run of one scan
    // (see bugHunt.ts's retry-success path): the tool itself ran ('ok'), but
    // named a real, narrower gap anyway. That combination — not "tool absent
    // entirely" — is what partial_tools flags, so the renderers can tell the
    // two apart instead of reporting every missing_tools entry as "did not
    // run this scan". Judged per scan, never across two.
    const okToolNames = new Set(view.tools_run.filter((t) => t.status === 'ok').map((t) => t.name));
    for (const t of view.missing_tools) if (okToolNames.has(t)) addOnce(partialTools, t);
  }
  const omittedCategories = omittedCategoriesFor(missingTools, cveGap);
  const level: CoverageState['level'] =
    open.scans.length === 0 ? 'none' : omittedCategories.length > 0 ? 'partial' : 'full';
  return {
    level,
    tools_run: toolsRun,
    missing_tools: missingTools,
    partial_tools: partialTools,
    omitted_categories: omittedCategories,
  };
}

/**
 * Maps each missing tool through TOOL_CATEGORIES, falling back to the tool's
 * own name so an unrecognised scanner is named rather than dropped, THEN
 * appends the CVE-source gap (if any) under the same category trivy already
 * maps to — de-duplicated on the OUTPUT category (so a scan that is both
 * missing trivy AND has no deps-flavoured scan in its history contributes
 * 'container and dependency' once, not twice), insertion order preserved.
 * Reusing trivy's own category is deliberate: from the reader's side, "these
 * findings are not in these numbers" is equally true whether trivy was
 * attempted and unavailable in THIS scan, or no deps/security_full scan has
 * run recently enough to source current CVE data at all — `omitted_categories`
 * is the "what these numbers do not contain" channel for both reasons.
 */
function omittedCategoriesFor(missingTools: readonly string[], cveGap: boolean): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  const add = (category: string): void => {
    if (!seen.has(category)) {
      seen.add(category);
      result.push(category);
    }
  };
  for (const tool of missingTools) add(TOOL_CATEGORIES[tool] ?? tool);
  if (cveGap) add(TOOL_CATEGORIES.trivy ?? 'trivy');
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

interface ComplianceSignals {
  policies_missing: number;
  dependency_bot_configured: boolean;
}

/**
 * The same signals, and the same arithmetic, as `tools/riskScore.ts`, over
 * the same project-scoped queries. Same fallback, kept deliberately: no
 * compliance/deps-audit scan of this project ⇒ no signal ⇒ no penalty —
 * "not measured", not "0 missing". Both signals are read from files, not
 * from scanner output, so a run's scanner coverage does not disqualify them.
 */
function resolveComplianceSignals(storage: Storage, projectPath: string): ComplianceSignals {
  const latestCompliance = findLatestUsable(storage, projectPath, ['compliance'], {
    skipCoverageNone: false,
  }).scan;
  let policiesMissing = 0;
  if (latestCompliance?.meta) {
    const m = latestCompliance.meta as {
      policy_documents_found?: Record<string, boolean | string[]>;
    };
    const docs = m.policy_documents_found ?? {};
    for (const key of ['privacy_policy', 'terms_of_service', 'security_policy']) {
      if (docs[key] === false) policiesMissing += 1;
    }
  }

  let dependencyBotConfigured = true;
  const latestDepsAudit = findLatestUsable(storage, projectPath, ['deps_audit', 'deps'], {
    skipCoverageNone: false,
    predicate: isDepsAuditScan,
  }).scan;
  if (latestDepsAudit?.meta) {
    const m = latestDepsAudit.meta as { bot_configured?: { renovate?: boolean; dependabot?: boolean } };
    const bot = m.bot_configured ?? {};
    dependencyBotConfigured = Boolean(bot.renovate || bot.dependabot);
  }

  return { policies_missing: policiesMissing, dependency_bot_configured: dependencyBotConfigured };
}

function buildSincePrevious(
  storage: Storage,
  currentScan: ScanRecord,
  isSuppressed: IsSuppressed,
  truncation: TruncationNotice[],
): FindingDelta | null {
  const previous = latestStateScan(storage, currentScan.project_path, currentScan.scan_type, {
    beforeScanId: currentScan.scan_id,
  }).scan;
  if (previous === null) return null;
  return compareScans(storage, previous, currentScan, isSuppressed, truncation, 'deltas.since_previous.new_findings');
}

/**
 * `compareFindings` of two scans, except for what one side did not measure
 * (`history/runCompare.ts`, per scanner): a finding of `from` whose scanner
 * `to` did not run ok is left out and counted in `not_remeasured_count` —
 * never resolved; a finding of `to` whose scanner `from` did not run ok is
 * left out and counted in `not_previously_measured_count` — never new.
 */
function compareScans(
  storage: Storage,
  from: ScanRecord,
  to: ScanRecord,
  isSuppressed: IsSuppressed,
  truncation: TruncationNotice[],
  what: string,
): FindingDelta {
  const check = compareScansFor(storage, from, to);
  const fromFindings = unsuppressed(storage, from.scan_id, isSuppressed);
  const toFindings = unsuppressed(storage, to.scan_id, isSuppressed);
  const classified = classifyDiff(check, fromFindings, toFindings);
  const skipFrom = new Set(classified.notRemeasured);
  const skipTo = new Set(classified.notPreviouslyMeasured);
  const { delta, truncation: cut } = compareFindings(
    { scan_id: from.scan_id, findings: fromFindings.filter((f) => !skipFrom.has(f)) },
    { scan_id: to.scan_id, findings: toFindings.filter((f) => !skipTo.has(f)) },
    DELTA_CAP,
  );
  if (cut !== null) truncation.push({ ...cut, what });
  return {
    ...delta,
    ...(skipFrom.size > 0 ? { not_remeasured_count: skipFrom.size } : {}),
    ...(skipTo.size > 0 ? { not_previously_measured_count: skipTo.size } : {}),
  };
}

/**
 * The baseline against the newest usable scan of the baseline's own type —
 * never against a scan of another type, whose findings come from different
 * rule families and would all read as new.
 */
function buildSinceBaseline(
  storage: Storage,
  baseline: ProjectBaseline,
  projectPath: string,
  isSuppressed: IsSuppressed,
  truncation: TruncationNotice[],
): FindingDelta | null {
  const baselineType = baseline.scan_type ?? storage.scans.getById(baseline.scan_id)?.scan_type;
  if (baselineType === undefined) return null;
  const target = latestStateScan(storage, projectPath, baselineType).scan;
  const baselineScan = storage.scans.getById(baseline.scan_id);
  if (target === null || baselineScan === null) return null;
  return compareScans(storage, baselineScan, target, isSuppressed, truncation, 'deltas.since_baseline.new_findings');
}

function unsuppressed(storage: Storage, scanId: string, isSuppressed: IsSuppressed): Finding[] {
  return storage.findings.listByScan(scanId).filter((f) => !isSuppressed(f));
}

function buildBaselineState(resolved: ProjectBaseline | null, now: number): BaselineState {
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

/**
 * `activeSuppressions` must already be filtered against the SAME `now` this
 * function receives (see `buildSnapshot`'s `isSuppressionActiveAt` call) —
 * this function only decides the "expiring within 7 days" cutoff, not
 * "active at all", so the whole suppression path shares one clock rather
 * than mixing this parameter with an internally-fetched, real-clock-filtered
 * list.
 */
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

/** "Active" relative to the INJECTED clock, never the real one — see the
 *  module doc comment's suppression paragraph. */
function isSuppressionActiveAt(s: Suppression, now: number): boolean {
  return s.expires_at === undefined || Date.parse(s.expires_at) > now;
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
