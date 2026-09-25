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
 *     reported, as a count plus the newest few ({@link SkippedSummary}),
 *     because a reader must be able to tell stale-but-measured data from
 *     fresh data — and 200 runs without gitleaks must not become 200 entries
 *     in every response.
 *
 * `security_full` rows, both shapes (`scanRoles.ts#isOrchestratedFullScan`):
 *   - an orchestrated parent is never a source — its children are real scans
 *     of their own types and hold the same findings;
 *   - a script-era row is split across the slots of the tools that re-evaluate
 *     its findings, and judged per slot on that slot's scanners only. It ran
 *     a subset of every dedicated tool's rule sources (Semgrep's registry but
 *     not the project's rules, base.yml or registered packs; gitleaks over
 *     history but not uncommitted files; Trivy on the Dockerfile but not the
 *     image), so it NEVER SUPERSEDES a dedicated scan: when it is the newer
 *     of the two, its findings are ADDED to the dedicated scan's (deduplicated)
 *     rather than replacing them — which keeps a finding it never evaluated,
 *     at the price of possibly keeping one it would have called fixed. A
 *     dedicated scan newer than it supersedes it normally. (Chosen over
 *     splitting findings by rule source, which no stored field records.)
 *
 * Every lookup is a project- and type-scoped SQL query, paged only past the
 * rows it skips; nothing here searches a fixed window of recent scans.
 */
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { SEVERITY_ORDER, } from '../types.js';
import { STATE_SCAN_TYPES, findingInSlot, isOrchestratedFullScan, isScopedScan, isScriptEraFullScan, slotView, sourceTypesOf, } from './scanRoles.js';
/** Rows fetched per query while looking past skipped scans. */
const PAGE = 25;
/** How many skipped scans a summary names, per reason. The count is exact. */
export const SKIPPED_SAMPLE = 5;
/**
 * The newest completed, unscoped scan of `types` for `projectPath` whose
 * coverage is not `none` — and the none-coverage scans passed over on the
 * way.
 */
export function findLatestUsable(storage, projectPath, types, opts = {}) {
    const r = search(storage, projectPath, types, opts);
    return { scan: r.scan, coverage: r.coverage, skipped: summarizeSkipped(r.hits), hits: r.hits };
}
function search(storage, projectPath, types, opts) {
    const skipCoverageNone = opts.skipCoverageNone ?? true;
    const hits = [];
    for (let offset = 0;; offset += PAGE) {
        const page = storage.scans.listCompletedOfTypes(projectPath, types, {
            limit: PAGE,
            offset,
            ...(opts.beforeScanId !== undefined ? { beforeScanId: opts.beforeScanId } : {}),
            ...(opts.afterScanId !== undefined ? { afterScanId: opts.afterScanId } : {}),
            ...(opts.excludeOrchestrated === true ? { excludeWithChildScans: true } : {}),
        });
        for (const scan of page) {
            if (isScopedScan(scan))
                continue;
            if (opts.predicate !== undefined && !opts.predicate(scan))
                continue;
            const judged = judge(scan, opts.slot);
            if (judged === null)
                continue;
            if (skipCoverageNone && judged === 'none') {
                hits.push({ slot: opts.slot ?? scan.scan_type, scan, reason: 'coverage_none' });
                continue;
            }
            return { scan, coverage: judged, hits };
        }
        if (page.length < PAGE)
            return { scan: null, coverage: null, hits };
    }
}
/**
 * The newest usable scan of any state type — or of exactly `scanType` when
 * given. What "the latest scan" means for a reader that compares or exports
 * ONE scan (`diff_scans`, `regression_alert`, `set_baseline`,
 * `report_export`): an SBOM, a stack detection or a diff review is never it.
 */
export function latestStateScan(storage, projectPath, scanType, opts = {}) {
    const found = findLatestUsable(storage, projectPath, scanType !== undefined ? [scanType] : STATE_SCAN_TYPES, opts);
    if (scanType !== undefined || found.scan === null)
        return found;
    // Any type: an orchestrated run is one scan to its reader. Its children
    // start after the parent, so the newest row is whichever child started
    // last — the iac child, say — and a baseline, an export or a diff of that
    // alone would silently leave out everything the other children found.
    const run = runOf(storage, projectPath, found.scan);
    if (run === found.scan)
        return found;
    return { ...found, scan: run, coverage: judge(run, undefined) };
}
function mapRun(storage, projectPath, scan) {
    return scan === undefined ? null : runOf(storage, projectPath, scan);
}
/**
 * `scan`'s orchestrated `security_full` parent when it is a child of a
 * completed one in the same project, else `scan` itself.
 */
function runOf(storage, projectPath, scan) {
    const parentId = scan.meta?.['parent_scan_id'];
    if (typeof parentId !== 'string')
        return scan;
    const parent = storage.scans.getById(parentId);
    if (parent === null ||
        parent.status !== 'completed' ||
        parent.project_path !== projectPath ||
        !isOrchestratedFullScan(parent)) {
        return scan;
    }
    return parent;
}
/**
 * Coverage of the part of `scan` that speaks for `slot`, or null when that
 * part is empty: a security_full row whose bookkeeping never names one of the
 * slot's scanners did not attempt the slot, says nothing about it, and must
 * not become a source of it. That holds for the residual `security_full`
 * slot too — filtering a row's bookkeeping to unroutable tools leaves nothing,
 * and `computeCoverage([], [])` is 'full', which made every security_full row
 * a full, zero-finding source (review item 1). The one exception: a row with
 * no bookkeeping AT ALL is taken to have attempted everything, which is how
 * the oldest rows look, and dropping them would make their findings vanish.
 */
function judge(scan, slot) {
    if (slot === undefined || scan.scan_type !== 'security_full') {
        return computeCoverage(scan.tools_run, scan.missing_tools);
    }
    if (scan.tools_run.length === 0 && scan.missing_tools.length === 0)
        return 'full';
    const view = slotView(scan, slot);
    if (view.tools_run.length === 0 && view.missing_tools.length === 0)
        return null;
    return computeCoverage(view.tools_run, view.missing_tools);
}
/** One count and a bounded, newest-first sample per reason; a scan counted once. */
export function summarizeSkipped(hits) {
    const byScan = new Map();
    for (const h of hits) {
        const seen = byScan.get(h.scan.scan_id);
        if (seen !== undefined) {
            if (!seen.slots.includes(h.slot))
                seen.slots.push(h.slot);
            continue;
        }
        byScan.set(h.scan.scan_id, {
            scan_id: h.scan.scan_id,
            scan_type: h.scan.scan_type,
            started_at: h.scan.started_at,
            reason: h.reason,
            slots: [h.slot],
        });
    }
    const all = [...byScan.values()].sort((a, b) => a.started_at === b.started_at ? 0 : a.started_at < b.started_at ? 1 : -1);
    const by_reason = { coverage_none: 0 };
    const newest = [];
    for (const s of all) {
        by_reason[s.reason] += 1;
        if (by_reason[s.reason] <= SKIPPED_SAMPLE)
            newest.push(s);
    }
    return { count: all.length, by_reason, newest };
}
/**
 * "Is this finding suppressed?" against `now` — by fingerprint, or by
 * identity where both sides have one: the same either-key rule as
 * `findingsRepo.ts#SUPPRESSION_MATCHES_F`, decided on an injected clock.
 */
export function suppressionMatcher(suppressions, now) {
    const fingerprints = new Set();
    const identities = new Set();
    for (const s of suppressions) {
        if (s.expires_at !== undefined && !(Date.parse(s.expires_at) > now))
            continue;
        fingerprints.add(s.finding_fingerprint);
        if (s.finding_identity !== undefined)
            identities.add(s.finding_identity);
    }
    return (f) => fingerprints.has(f.fingerprint) || (f.identity !== undefined && identities.has(f.identity));
}
/**
 * The source(s) of one slot, and the scans passed over for it. See the
 * module comment for the script-era rule this encodes.
 */
function slotSources(storage, projectPath, slot) {
    const pick = (r) => r.scan !== null && r.coverage !== null ? [{ scan: r.scan, coverage: r.coverage }] : [];
    // Script-era rows only — orchestrated parents are left out in SQL, so no
    // read pages through every orchestrated run to find none (the predicate
    // stays as the JS-side guarantee).
    const scriptEra = { excludeOrchestrated: true, predicate: isScriptEraFullScan };
    // The residual slot: only what a script-era row could not route.
    if (slot === 'security_full') {
        const r = search(storage, projectPath, ['security_full'], { slot, ...scriptEra });
        return { picks: pick(r), hits: r.hits };
    }
    const dedicated = search(storage, projectPath, [slot], { slot });
    if (!sourceTypesOf(slot).includes('security_full')) {
        return { picks: pick(dedicated), hits: dedicated.hits };
    }
    // A script-era row counts only when it is newer than the dedicated source
    // (it is added, never superseding), so the search stops at that source.
    // Every row it returns — and every blind row it passes — is newer.
    const legacy = search(storage, projectPath, ['security_full'], {
        slot,
        ...scriptEra,
        ...(dedicated.scan !== null ? { afterScanId: dedicated.scan.scan_id } : {}),
    });
    const picks = pick(dedicated);
    if (legacy.scan !== null && legacy.coverage !== null) {
        picks.push({ scan: legacy.scan, coverage: legacy.coverage });
    }
    return { picks, hits: [...dedicated.hits, ...legacy.hits] };
}
export function openSetForProject(storage, projectPath, opts = {}) {
    const isSuppressed = suppressionMatcher(storage.suppressions.listAll(), opts.now ?? Date.now());
    const picked = [];
    const hits = [];
    const considered = new Map();
    for (const slot of STATE_SCAN_TYPES) {
        const found = slotSources(storage, projectPath, slot);
        for (const h of found.hits) {
            hits.push(h);
            considered.set(h.scan.scan_id, h.scan);
        }
        for (const p of found.picks) {
            picked.push({ slot, ...p });
            considered.set(p.scan.scan_id, p.scan);
        }
    }
    // Newest first, in SQL's own order (started_at, then rowid — two scans can
    // start in the same millisecond), so where two sources hold the same
    // finding the newer copy — its line numbers, its scan id — is kept.
    const order = storage.scans.sortNewestFirst([...considered.keys()]);
    const rank = new Map(order.map((id, i) => [id, i]));
    const rankOf = (scanId) => rank.get(scanId) ?? order.length;
    picked.sort((a, b) => rankOf(a.scan.scan_id) - rankOf(b.scan.scan_id));
    const byScan = new Map();
    const findings = [];
    const sources = [];
    for (const { slot, scan, coverage } of picked) {
        let rows = byScan.get(scan.scan_id);
        if (rows === undefined) {
            rows = storage.findings.listByScan(scan.scan_id);
            byScan.set(scan.scan_id, rows);
        }
        const seen = indexFindings(findings);
        let contributed = 0;
        for (const f of rows) {
            if (!findingInSlot(scan, f, slot) || isSuppressed(f) || seen.has(f))
                continue;
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
    findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.fingerprint.localeCompare(b.fingerprint));
    const skipped = summarizeSkipped(hits);
    const scans = [...considered.values()].sort((a, b) => rankOf(a.scan_id) - rankOf(b.scan_id));
    const coverage = sources.length === 0
        ? 'none'
        : sources.some((s) => s.coverage !== 'full') || skipped.count > 0
            ? 'partial'
            : 'full';
    const bookkeeping = [
        ...picked.map((p) => ({ scan_id: p.scan.scan_id, slot: p.slot, ...slotView(p.scan, p.slot) })),
        ...hits.map((h) => ({ scan_id: h.scan.scan_id, slot: h.slot, ...slotView(h.scan, h.slot) })),
    ];
    return {
        project_path: projectPath,
        findings,
        sources,
        skipped,
        coverage,
        scans,
        bookkeeping,
        // Named as a run: a child of an orchestrated security_full stands for
        // its parent (see `latestStateScan`). `picked` is newest first.
        newest: mapRun(storage, projectPath, scans[0]),
        newestSource: mapRun(storage, projectPath, picked[0]?.scan),
    };
}
/**
 * What a reader tells its caller about the set it answered from: which
 * scans, how complete, and how many newer scans it passed over.
 */
export function describeOpenSet(set) {
    return {
        project_path: set.project_path,
        coverage: set.coverage,
        sources: set.sources,
        skipped: set.skipped,
    };
}
//# sourceMappingURL=openSet.js.map