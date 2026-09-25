/**
 * A project's open findings, and "the latest usable scan" of a type — the
 * two reads every history consumer is built on.
 *
 * Open findings for project P = the union, over every state type
 * (`history/scanRoles.ts`), of the newest usable completed scan of that type
 * for P — deduplicated by `identity`, the fingerprint as the fallback where a
 * side has none (`fingerprint/findingIdentity.ts#indexFindings`) — minus the
 * suppressions active at `now`.
 *
 * "Usable" means three things, each a defect when missing:
 *   - scoped to P by an exact `project_path` match, never "the newest row in
 *     the database": that answered for whichever project scanned last;
 *   - not scoped to part of the project (`meta.scope`): a diff review's
 *     silence about a file is not evidence about it;
 *   - coverage is not `none`: a run whose scanner was missing measured
 *     nothing, and its empty result would otherwise read as "all fixed".
 *     Such a scan is SKIPPED — the one before it answers — and every skip is
 *     reported, because a reader must be able to tell stale-but-measured
 *     data from fresh data.
 *
 * Every lookup is a project- and type-scoped SQL query, paged only past the
 * rows it skips; nothing here searches a fixed window of recent scans.
 */

import { indexFindings } from '../fingerprint/findingIdentity.js';
import type { Storage } from '../storage/index.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import {
  SEVERITY_ORDER,
  type Finding,
  type ScanCoverage,
  type ScanRecord,
  type ScanType,
  type Suppression,
} from '../types.js';
import {
  STATE_SCAN_TYPES,
  findingInSlot,
  isScopedScan,
  slotView,
  sourceTypesOf,
  type OpenSetSlot,
} from './scanRoles.js';

/** Rows fetched per query while looking past skipped scans. */
const PAGE = 25;

/** A finding in the open set, with the scan it was read from. */
export interface OpenFinding extends Finding {
  scan_id: string;
}

/** A newer scan a reader passed over — reported, never silently dropped. */
export interface SkippedScan {
  slot: OpenSetSlot;
  scan_id: string;
  scan_type: ScanType;
  started_at: string;
  reason: 'coverage_none';
}

export interface OpenSetSource {
  slot: OpenSetSlot;
  scan_id: string;
  scan_type: ScanType;
  started_at: string;
  finished_at: string | null;
  coverage: ScanCoverage;
  /** Findings this source contributed after suppressions and deduplication. */
  findings: number;
}

export interface OpenSet {
  project_path: string;
  /** Severity-descending, fingerprint-ascending — the order `findings/open` always had. */
  findings: OpenFinding[];
  sources: OpenSetSource[];
  skipped: SkippedScan[];
  /**
   * `none` when no state scan is usable; `partial` when a source's own
   * coverage is partial or a newer scan was skipped; `full` otherwise.
   */
  coverage: ScanCoverage;
  /** Every scan the read considered (sources and skipped), newest first, once each. */
  scans: ScanRecord[];
  /** `scans[0]`: the newest state scan considered (source or skipped), or null. */
  newest: ScanRecord | null;
  /** The newest scan findings were actually read from, or null. */
  newestSource: ScanRecord | null;
}

export interface UsableScan {
  scan: ScanRecord | null;
  /** Coverage of the part of `scan` the read judged it on. */
  coverage: ScanCoverage | null;
  skipped: SkippedScan[];
}

export interface FindUsableOptions {
  /**
   * Judge security_full rows by one slot's tools only (see
   * `scanRoles.ts#slotView`) and skip one that did not attempt that slot.
   * Omitted: every row is judged on its whole bookkeeping.
   */
  slot?: OpenSetSlot;
  /** Only scans strictly older than this one — "the previous scan". */
  beforeScanId?: string;
  /** Default true. False for readers of `meta` that no scanner produced. */
  skipCoverageNone?: boolean;
  /** Further narrowing (e.g. `isDepsAuditScan`). */
  predicate?: (scan: ScanRecord) => boolean;
}

/**
 * The newest completed, unscoped scan of `types` for `projectPath` whose
 * coverage is not `none` — and the none-coverage scans passed over on the
 * way, newest first.
 */
export function findLatestUsable(
  storage: Storage,
  projectPath: string,
  types: readonly ScanType[],
  opts: FindUsableOptions = {},
): UsableScan {
  const skipCoverageNone = opts.skipCoverageNone ?? true;
  const skipped: SkippedScan[] = [];
  for (let offset = 0; ; offset += PAGE) {
    const page = storage.scans.listCompletedOfTypes(projectPath, types, {
      limit: PAGE,
      offset,
      ...(opts.beforeScanId !== undefined ? { beforeScanId: opts.beforeScanId } : {}),
    });
    for (const scan of page) {
      if (isScopedScan(scan)) continue;
      if (opts.predicate !== undefined && !opts.predicate(scan)) continue;
      const judged = judge(scan, opts.slot);
      if (judged === null) continue;
      if (skipCoverageNone && judged === 'none') {
        skipped.push({
          slot: opts.slot ?? scan.scan_type,
          scan_id: scan.scan_id,
          scan_type: scan.scan_type,
          started_at: scan.started_at,
          reason: 'coverage_none',
        });
        continue;
      }
      return { scan, coverage: judged, skipped };
    }
    if (page.length < PAGE) return { scan: null, coverage: null, skipped };
  }
}

/** `findLatestUsable` for one open-set slot, over every type that feeds it. */
export function latestUsableForSlot(
  storage: Storage,
  projectPath: string,
  slot: OpenSetSlot,
  opts: Omit<FindUsableOptions, 'slot'> = {},
): UsableScan {
  return findLatestUsable(storage, projectPath, sourceTypesOf(slot), { ...opts, slot });
}

/**
 * The newest usable scan of any state type — or of exactly `scanType` when
 * given. What "the latest scan" means for a reader that compares or exports
 * ONE scan (`diff_scans`, `regression_alert`, `set_baseline`,
 * `report_export`): an SBOM, a stack detection or a diff review is never it.
 */
export function latestStateScan(
  storage: Storage,
  projectPath: string,
  scanType?: ScanType,
  opts: Pick<FindUsableOptions, 'beforeScanId'> = {},
): UsableScan {
  return findLatestUsable(storage, projectPath, scanType !== undefined ? [scanType] : STATE_SCAN_TYPES, opts);
}

/**
 * Coverage of the part of `scan` that speaks for `slot`, or null when a
 * security_full row never attempted that slot's scanners at all (such a row
 * says nothing about the slot, so it must not supersede one that does). A
 * row with no bookkeeping at all is taken to have attempted everything: that
 * is how rows written before `tools_run` was reliable, and hand-seeded ones,
 * look — and dropping them would make their findings vanish.
 */
function judge(scan: ScanRecord, slot: OpenSetSlot | undefined): ScanCoverage | null {
  if (slot === undefined || scan.scan_type !== 'security_full' || slot === 'security_full') {
    const view = slot === undefined ? scan : slotView(scan, slot);
    return computeCoverage(view.tools_run, view.missing_tools);
  }
  const view = slotView(scan, slot);
  const noBookkeeping = scan.tools_run.length === 0 && scan.missing_tools.length === 0;
  const attempted = view.tools_run.length > 0 || view.missing_tools.length > 0 || noBookkeeping;
  if (!attempted) return null;
  return computeCoverage(view.tools_run, view.missing_tools);
}

/**
 * "Is this finding suppressed?" against `now` — by fingerprint, or by
 * identity where both sides have one: the same either-key rule as
 * `findingsRepo.ts#SUPPRESSION_MATCHES_F`, decided on an injected clock.
 */
export function suppressionMatcher(
  suppressions: readonly Suppression[],
  now: number,
): (f: Pick<Finding, 'fingerprint' | 'identity'>) => boolean {
  const fingerprints = new Set<string>();
  const identities = new Set<string>();
  for (const s of suppressions) {
    if (s.expires_at !== undefined && !(Date.parse(s.expires_at) > now)) continue;
    fingerprints.add(s.finding_fingerprint);
    if (s.finding_identity !== undefined) identities.add(s.finding_identity);
  }
  return (f) => fingerprints.has(f.fingerprint) || (f.identity !== undefined && identities.has(f.identity));
}

export function openSetForProject(
  storage: Storage,
  projectPath: string,
  opts: { now?: number } = {},
): OpenSet {
  const isSuppressed = suppressionMatcher(storage.suppressions.listAll(), opts.now ?? Date.now());

  const picked: Array<{ slot: OpenSetSlot; scan: ScanRecord; coverage: ScanCoverage }> = [];
  const skipped: SkippedScan[] = [];
  const considered = new Map<string, ScanRecord>();
  for (const slot of STATE_SCAN_TYPES) {
    const found = latestUsableForSlot(storage, projectPath, slot);
    for (const s of found.skipped) {
      skipped.push(s);
      if (!considered.has(s.scan_id)) {
        const record = storage.scans.getById(s.scan_id);
        if (record !== null) considered.set(s.scan_id, record);
      }
    }
    if (found.scan !== null && found.coverage !== null) {
      picked.push({ slot, scan: found.scan, coverage: found.coverage });
      considered.set(found.scan.scan_id, found.scan);
    }
  }

  // Newest first, in SQL's own order (started_at, then rowid — two scans can
  // start in the same millisecond), so where two sources hold the same
  // finding the newer copy — its line numbers, its scan id — is kept.
  const order = storage.scans.sortNewestFirst([...considered.keys()]);
  const rank = new Map(order.map((id, i) => [id, i]));
  const rankOf = (scanId: string): number => rank.get(scanId) ?? order.length;
  picked.sort((a, b) => rankOf(a.scan.scan_id) - rankOf(b.scan.scan_id));

  const byScan = new Map<string, Finding[]>();
  const findings: OpenFinding[] = [];
  const sources: OpenSetSource[] = [];
  for (const { slot, scan, coverage } of picked) {
    let rows = byScan.get(scan.scan_id);
    if (rows === undefined) {
      rows = storage.findings.listByScan(scan.scan_id);
      byScan.set(scan.scan_id, rows);
    }
    const seen = indexFindings(findings);
    let contributed = 0;
    for (const f of rows) {
      if (!findingInSlot(scan, f, slot) || isSuppressed(f) || seen.has(f)) continue;
      findings.push({ ...f, scan_id: scan.scan_id });
      contributed += 1;
    }
    sources.push({
      slot,
      scan_id: scan.scan_id,
      scan_type: scan.scan_type,
      started_at: scan.started_at,
      finished_at: scan.finished_at,
      coverage,
      findings: contributed,
    });
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.fingerprint.localeCompare(b.fingerprint),
  );

  const scans = [...considered.values()].sort((a, b) => rankOf(a.scan_id) - rankOf(b.scan_id));
  const coverage: ScanCoverage =
    sources.length === 0
      ? 'none'
      : sources.some((s) => s.coverage !== 'full') || skipped.length > 0
        ? 'partial'
        : 'full';

  return {
    project_path: projectPath,
    findings,
    sources,
    skipped,
    coverage,
    scans,
    newest: scans[0] ?? null,
    // `picked` is newest first.
    newestSource: picked[0]?.scan ?? null,
  };
}

/**
 * What a reader tells its caller about the set it answered from: which
 * scans, how complete, and which newer scans it passed over.
 */
export function describeOpenSet(set: OpenSet): {
  project_path: string;
  coverage: ScanCoverage;
  sources: OpenSetSource[];
  skipped: SkippedScan[];
} {
  return {
    project_path: set.project_path,
    coverage: set.coverage,
    sources: set.sources,
    skipped: set.skipped,
  };
}

