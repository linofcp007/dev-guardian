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
 * `findings.listByScan(scanId)`/`scans.getById(scanId)`, which are safe by
 * construction: they take an explicit id already resolved through a
 * project-scoped path (scan history, or a validated baseline — see
 * `resolveBaseline` below), never an implicit "latest" selection.
 *
 * The same scoping rule applies one level deeper than the original cut of
 * this module recognised: `risk_score`'s compliance signal, dependency-bot
 * signal and CVE source are all found by *searching scan history for a scan
 * of the right type* (`tools/riskScore.ts`'s own `findLatestOfType`, over
 * the unscoped `listHistory`). A caller with a project in scope must do that
 * same search scoped to its own history — never stub the answer, and never
 * search the whole database — so `findLatestOfType` below runs over the
 * project-scoped `history` fetched once at the top of `buildSnapshot`, and
 * is reused for the compliance scan, the deps-audit scan and the
 * deps-flavoured CVE source scan.
 *
 * `baselines.getActive()` returns one row, globally — the `baselines` table
 * has no `project_path` column at all (schema fact, not an oversight of this
 * task). `BaselineState.active`'s own doc comment reads "null ⇒ no baseline
 * has ever been set for THIS PROJECT", so `resolveBaseline` below does not
 * stop at the single newest row: it walks `baselines.listAll()` (newest
 * first) and uses the first whose *scan* actually belongs to `projectPath`.
 * Stopping at `getActive()` alone gets the cross-project rejection right but
 * silently hides this project's own older baseline whenever another project
 * has set one more recently — correct in the sense that it never borrows
 * another project's data, but still wrong, because a baseline this project
 * genuinely has must not read as "no baseline set".
 *
 * `suppressions.listActive()` similarly has no project-scoped variant — but
 * unlike baselines, filtering by `project_path` is not the relevant gap.
 * Suppressions are keyed by finding fingerprint (deliberately global: a
 * suppression is meant to apply everywhere that fingerprint appears) and
 * `listActive()` filters "not yet expired" against the real wall clock
 * (`nowIso()`), which is exactly right for its other, live callers (e.g.
 * `tools/complianceEvidence.ts`) but wrong for this module: `buildSnapshot`
 * takes an injected `now` so its result is a pure function of its inputs,
 * and a query that reaches past that for the ambient clock defeats the
 * whole point of injecting it — this module then behaves differently
 * depending on which real day it happens to run on, not just on what its
 * arguments say, and drifts out from under any test with a fixed `now`
 * as soon as real time passes the fixture's dates. `suppressions.listAll()`
 * (new, purely additive — `listActive()` and its other callers are
 * untouched) returns every row unfiltered, and `buildSuppressionState`
 * below decides "active" against `now` in JavaScript, once, so the entire
 * suppression-derived state — both the counts here and the fingerprints
 * used to filter the delta comparisons — comes from exactly one clock.
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
/** How far back the project-scoped history search looks for a same-type
 *  previous scan, and for the compliance/deps/CVE source scans. Mirrors
 *  `tools/riskScore.ts`'s own `listHistory(50)` convention for "find the
 *  latest scan of a given type" — this feature does not invent a second
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

  // Fetched once, reused for the since_previous same-type lookup below and
  // for the compliance/deps/CVE-source findLatestOfType searches. Empty
  // (not fetched) when there is no current scan — nothing to search for.
  const history = currentScan
    ? storage.scans.listHistoryForProject(projectPath, HISTORY_LOOKBACK)
    : [];

  // The scan CVEs are actually sourced from — the latest deps-flavoured scan
  // in this project's history, mirroring risk_score's own
  // findLatestOfType(['deps', 'security_full']), not just "whatever the
  // latest scan happens to be". `cveGap` is true exactly when this project
  // HAS a current scan but none of its history (within the lookback window)
  // is deps-flavoured — CVEs are then necessarily unmeasured, not zero, and
  // that has to reach coverage or it renders as a clean "0 CVEs".
  const cveSourceScan = findLatestOfType(history, ['deps', 'security_full']);
  const cveGap = currentScan !== null && cveSourceScan === null;
  const coverage = buildCoverage(currentScan, cveGap);

  // Already project-scoped AND already suppression-filtered by
  // listOpenForProjectStmt's own SQL — this is both the basis of
  // `FindingsSummary` and the "to" side of `since_previous` below. Safe on a
  // project with no completed scan: the underlying CTE then matches zero
  // rows and the join returns [], never an error.
  const openFindings = storage.findings.listOpenForProject(projectPath);
  const findings = buildFindingsSummary(openFindings, truncation);

  const cveItems: Cve[] = cveSourceScan ? storage.cves.listActive(cveSourceScan.scan_id) : [];
  const cves = buildCveSummary(cveItems);

  // Suppression state, entirely against the injected `now` — see the module
  // doc comment for why this is `listAll()` + a JS-side filter rather than
  // `listActive()`. Reused for both the delta suppression-filtering below
  // and `SuppressionState` itself, so — like `history` above — it is fetched
  // and decided exactly once.
  const allSuppressions = storage.suppressions.listAll();
  const activeSuppressions = allSuppressions.filter((s) => isSuppressionActiveAt(s, now));
  const suppressedFingerprints = new Set(activeSuppressions.map((s) => s.finding_fingerprint));

  const sincePrevious = currentScan
    ? buildSincePrevious(storage, currentScan, history, openFindings, suppressedFingerprints, truncation)
    : null;

  const resolvedBaseline = resolveBaseline(storage, projectPath);
  const baseline = buildBaselineState(resolvedBaseline, now);
  const sinceBaseline = currentScan && resolvedBaseline
    ? buildSinceBaseline(storage, resolvedBaseline, currentScan, openFindings, suppressedFingerprints, truncation)
    : null;

  const suppressions = buildSuppressionState(activeSuppressions, now);

  const complianceSignals = resolveComplianceSignals(history);

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

function buildCoverage(currentScan: ScanRecord | null, cveGap: boolean): CoverageState {
  const missingTools = currentScan?.missing_tools ?? [];
  const toolsRun = (currentScan?.tools_run ?? []).map((t) => t.name);
  const omittedCategories = omittedCategoriesFor(missingTools, cveGap);
  const level: CoverageState['level'] =
    currentScan === null ? 'none' : omittedCategories.length > 0 ? 'partial' : 'full';
  return {
    level,
    tools_run: toolsRun,
    missing_tools: missingTools,
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

/**
 * The same shape as `tools/riskScore.ts`'s own `findLatestOfType` (also
 * duplicated in `resources/misc.ts`, `resources/dotnet.ts`,
 * `resources/wp.ts`) — "the newest completed scan of one of these types" —
 * but over an already project-scoped `history` array instead of that
 * helper's unscoped `listHistory(50)`. `listHistoryForProject`'s rows
 * already carry `meta` (via `rowToRecord`), so unlike those originals this
 * needs no separate `getById` call.
 */
function findLatestOfType(history: readonly ScanRecord[], types: readonly string[]): ScanRecord | null {
  return history.find((s) => s.status === 'completed' && types.includes(s.scan_type)) ?? null;
}

interface ComplianceSignals {
  policies_missing: number;
  dependency_bot_configured: boolean;
}

/**
 * Ported from `tools/riskScore.ts:47-67` verbatim, scoped by project via the
 * already-fetched `history` instead of that tool's unscoped `listHistory(50)`.
 * Same fallback, kept deliberately: no compliance/deps scan anywhere in this
 * project's (lookback-bounded) history ⇒ no signal ⇒ no penalty — "not
 * measured", not "0 missing" — matching `risk_score`'s own accepted
 * behaviour for the identical absence, since design §3.1 requires
 * `risk_score`'s public behaviour to stay unchanged and this is the exact
 * logic it already runs, just reached through a scoped history instead of
 * an unscoped one.
 */
function resolveComplianceSignals(history: readonly ScanRecord[]): ComplianceSignals {
  const latestCompliance = findLatestOfType(history, ['compliance']);
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
  const latestDepsAudit = findLatestOfType(history, ['deps']);
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
  history: readonly ScanRecord[],
  openFindings: readonly Finding[],
  suppressedFingerprints: ReadonlySet<string>,
  truncation: TruncationNotice[],
): FindingDelta | null {
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
 * The most recent baseline whose scan belongs to `projectPath` — NOT just
 * the single globally-newest baseline. `baselines` has no `project_path`
 * column, so `getActive()` alone can only ever see one row across every
 * project in the database; stopping there after rejecting a cross-project
 * mismatch (the correct, safe half of this check) leaves this project's own
 * older baseline permanently invisible whenever any other project sets one
 * more recently. `listAll()` returns every baseline, newest first
 * (`baselinesRepo.ts`), so walking it and returning the first whose scan's
 * `project_path` matches finds this project's real most-recent baseline
 * regardless of what else has been set since. `scans.getById` is safe to use
 * for the per-candidate check: it is an explicit-id lookup, not an implicit
 * "latest" one.
 */
function resolveBaseline(storage: Storage, projectPath: string): ResolvedBaseline | null {
  const candidates = storage.baselines.listAll();
  for (const candidate of candidates) {
    const scan = storage.scans.getById(candidate.scan_id);
    if (scan === null || scan.project_path !== projectPath) continue;
    const resolved: ResolvedBaseline = {
      id: candidate.id,
      scan_id: candidate.scan_id,
      set_at: candidate.set_at,
    };
    if (candidate.note !== undefined) resolved.note = candidate.note;
    return resolved;
  }
  return null;
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
 *  module doc comment's `suppressions.listActive()` paragraph. */
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
