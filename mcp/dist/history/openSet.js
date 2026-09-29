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
 * ---- What the newest scan did not look at again ----------------------
 *
 * A slot's source is its newest usable scan, but "usable" is not "complete":
 * a Semgrep that only partly parsed a file (the shared judge's `partial`
 * verdict), a Semgrep that failed beside an ok Bandit, an image pass over
 * image B. Read as the slot's whole answer, every older finding that scan
 * did not look at again vanished — from `findings/open`, `risk_score`, the
 * dashboard, triage, prioritize, create_fix_pr, validate_finding and
 * create_github_issues — with only `coverage: partial` left to say so.
 *
 * So each slot also CARRIES FORWARD the findings of its older usable scans
 * that the newer ones left open — the one predicate `runCompare.ts` answers
 * "not re-measured" with (`openGapFor`: a gap the newer scan recorded in
 * that finding's key, a partly parsed file, a pass over another target),
 * never a second copy of it:
 *   - walking back scan by scan, a finding is carried only while EVERY newer
 *     scan left it open — one that measured it and did not find it resolved
 *     it for good;
 *   - a newer copy of the same identity wins;
 *   - a carried finding is marked `not_remeasured: true`, and the scan it
 *     came from is listed in `sources` with `carried_for` (the gaps);
 *   - suppressions still apply;
 *   - a scanner the newer scan did not run AT ALL (no gap recorded: a
 *     Python-free project's Bandit) is not a gap, and carries nothing —
 *     except a pass that runs only when asked (`trivy-image`, nuclei:
 *     `runNames.ts` `onRequest`): a scan that did not ask did not look;
 *   - a carry makes the set's coverage `partial`, and the carried scan's
 *     bookkeeping speaks only for the gaps it was carried for.
 * Which findings can be carried is decided per key from bookkeeping alone
 * (`runCompare.ts#ChainIndex`), so an older scan's rows are read only for a
 * key still open, and the walk is linear in the history it covers.
 *
 * Every lookup is a project- and type-scoped SQL query, paged only past the
 * rows it skips; nothing here searches a fixed window of recent scans.
 */
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { SEVERITY_ORDER, } from '../types.js';
import { admitLookup, ChainIndex, openGapFor, producedKeys, scopeAdmits, StillCarry, UNKNOWN_FINDING_KEY, } from './runCompare.js';
import { findingKey, toolsOfKey } from './runNames.js';
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
    const types = scanType !== undefined ? [scanType] : STATE_SCAN_TYPES;
    const found = findLatestUsable(storage, projectPath, types, opts);
    if (scanType !== undefined || found.scan === null)
        return found;
    // Any type: an orchestrated run is one scan to its reader. Its children
    // start after the parent, so the newest row is whichever child started
    // last — the iac child, say — and a baseline, an export or a diff of that
    // alone would silently leave out everything the other children found.
    //
    // The child was judged, the run was not: an iac child that skipped every
    // pass for want of IaC is coverage `full`, while its parent — every other
    // child blind — measured nothing. A parent judged `none` is passed over
    // like any other coverage-none scan, with every child that maps to it, and
    // the search goes on below.
    const hits = [...found.hits];
    const rejected = new Set();
    let current = found;
    for (;;) {
        const child = current.scan;
        if (child === null)
            return { ...current, hits, skipped: summarizeSkipped(hits) };
        const run = runOf(storage, projectPath, child);
        if (run === child)
            return { ...current, hits, skipped: summarizeSkipped(hits) };
        if (!rejected.has(run.scan_id)) {
            const coverage = judge(run, undefined);
            if (coverage !== 'none')
                return { ...current, scan: run, coverage, hits, skipped: summarizeSkipped(hits) };
            rejected.add(run.scan_id);
            hits.push({ slot: run.scan_type, scan: run, reason: 'coverage_none' });
        }
        current = findLatestUsable(storage, projectPath, types, { beforeScanId: child.scan_id });
        hits.push(...current.hits);
    }
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
 * "Is this finding suppressed?" against `now` and `projectPath` — by
 * fingerprint, or by identity where both sides have one: the same
 * either-key rule as `findingsRepo.ts#SUPPRESSION_MATCHES_F`, decided on an
 * injected clock. `suppressions` is typically the WHOLE database's list
 * (`storage.suppressions.listAll()`, never project-scoped by the query
 * itself), so this is also where cross-project isolation happens: a
 * suppression whose `project_path` (migration 011) names a different
 * project is skipped entirely, and one with no project at all (every row
 * written before that column existed) still matches — see
 * `suppressionsRepo.ts`'s module comment for why NULL means "every
 * project", not "no project".
 */
export function suppressionMatcher(suppressions, now, projectPath) {
    const fingerprints = new Set();
    const identities = new Set();
    for (const s of suppressions) {
        if (s.expires_at !== undefined && !(Date.parse(s.expires_at) > now))
            continue;
        if (s.project_path !== undefined && s.project_path !== projectPath)
            continue;
        fingerprints.add(s.finding_fingerprint);
        if (s.finding_identity !== undefined)
            identities.add(s.finding_identity);
    }
    return (f) => fingerprints.has(f.fingerprint) || (f.identity !== undefined && identities.has(f.identity));
}
/**
 * `findings` split by `projectPath`'s suppressions active at `now`, exactly
 * as the open set applies them ({@link suppressionMatcher}) — for a reader
 * that compares scans rather than reading the open set (`regression_alert`,
 * `diff_scans`). A suppressed finding is never new, resolved or a regression
 * there; it is listed apart. They used to compare every stored finding, so a
 * suppressed critical still raised `regressed: true, score_delta: 10` while
 * the dashboard and risk_score said 0.
 */
export function partitionSuppressed(storage, projectPath, findings, now = Date.now()) {
    const isSuppressed = suppressionMatcher(storage.suppressions.listAll(), now, projectPath);
    const visible = [];
    const suppressed = [];
    for (const f of findings)
        (isSuppressed(f) ? suppressed : visible).push(f);
    return { visible, suppressed };
}
/**
 * The suppressed findings of two compared scans, once each: all of
 * `current`'s, then those of `reference` whose identity (the fingerprint
 * where there is none) `current` does not hold.
 */
export function suppressedOfEither(current, reference) {
    const key = (f) => (f.identity !== undefined ? `i:${f.identity}` : `f:${f.fingerprint}`);
    const seen = new Set(current.map(key));
    return [...current, ...reference.filter((f) => !seen.has(key(f)))];
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
/**
 * Older scans of a slot the carry-forward walk examines at most. The walk
 * stops by itself at the first scan that measured what the newer ones did
 * not (`StillCarry`); this bounds a history kept without retention.
 */
const CARRY_WALK_LIMIT = 5000;
/**
 * The findings of `source`'s older usable scans (same slot, same type) that
 * every newer scan left open — see the module comment. Newest first.
 *
 * Linear in the history it walks, never history x findings x chain (fix
 * round 2: the first version checked every finding against the whole chain
 * of newer scans — 4.2 s for 200 scans x 300 findings with one file partly
 * parsed in every scan, 14 s for 250 x 1000; fix round 3: holders that each
 * scanned their own image re-folded the whole chain each — 21 s for 2000):
 *   - per key, the newer scans are indexed once (`ChainIndex`), and a
 *     holder's scope is read through the scans able to look at its targets —
 *     one fold per kind of holder, carried on as the chain grows; a
 *     finding's fate is read off it (`scopeAdmits`); the per-finding verdict
 *     (`openGapFor`) is asked once per (key, file, rule), for the label;
 *   - an older scan's findings are read only for a key that could still be
 *     open, and then only that key's tools, or the files and rules its
 *     scope names — never every row;
 *   - a finding whose identity the walk already holds (the source's own, or
 *     carried from a newer scan) is dropped on its keys alone, before its row
 *     is read: it could only lose to the newer copy;
 *   - the walk stops once no older scan, whatever it ran, could have a
 *     finding every newer one left open (`StillCarry`).
 */
function carryForward(storage, projectPath, slot, source, sourceRows, isSuppressed) {
    const index = new ChainIndex();
    index.push(slotView(source, slot));
    const history = storage.scans.runNamesOfType(projectPath, slot);
    const stillCarry = new StillCarry(index, history.names, history.anyEmpty);
    const known = new KnownFindings();
    for (const f of sourceRows)
        if (findingInSlot(source, f, slot) && !isSuppressed(f))
            known.add(f);
    const out = [];
    if (!stillCarry.check())
        return out;
    let walked = 0;
    // Keyset pages (strictly older than the last scan seen), never OFFSET:
    // an offset re-reads every row it skips, which is quadratic in the walk.
    let before = source.scan_id;
    while (walked < CARRY_WALK_LIMIT) {
        const page = storage.scans.listCompletedOfTypes(projectPath, [slot], { limit: PAGE, beforeScanId: before });
        const last = page[page.length - 1];
        if (last !== undefined)
            before = last.scan_id;
        for (const scan of page) {
            if (walked >= CARRY_WALK_LIMIT)
                break;
            if (isScopedScan(scan))
                continue;
            const coverage = judge(scan, slot);
            // Measured nothing (or nothing of this slot): no finding to carry, and
            // no evidence either way about the ones older than it.
            if (coverage === null || coverage === 'none')
                continue;
            walked += 1;
            const holder = slotView(scan, slot);
            const carried = carriedFrom({ storage, scan, slot, holder, index, isSuppressed, known });
            if (carried.length > 0) {
                out.push({ slot, scan, coverage, findings: carried });
                for (const { finding } of carried)
                    known.add(finding);
            }
            index.push(holder);
            if (!stillCarry.check())
                return out;
        }
        if (page.length < PAGE)
            break;
    }
    return out;
}
/**
 * The identities (and, for a row without one, fingerprints) of the findings
 * a slot's open set already holds — each certain to end up in it, itself or
 * as a newer copy — so an older copy is dropped on its keys alone, exactly
 * as `indexFindings` would drop it later.
 */
class KnownFindings {
    identities = new Set();
    bare = new Set();
    add(f) {
        if (f.identity !== undefined)
            this.identities.add(f.identity);
        else
            this.bare.add(f.fingerprint);
    }
    /** A row with these keys would lose to a finding already held. */
    holds(keys) {
        return keys.identity !== null && keys.identity !== undefined
            ? this.identities.has(keys.identity)
            : this.bare.has(keys.fingerprint);
    }
}
/** The findings of `scan` (bookkeeping `holder`) that every scan of the chain `index` holds left open. */
function carriedFrom(args) {
    const { storage, scan, slot, holder, index, isSuppressed, known } = args;
    const scopes = new Map();
    const scopeOf = (key) => {
        let scope = scopes.get(key);
        if (scope === undefined) {
            scope = index.scope(holder, key);
            scopes.set(key, scope);
        }
        return scope;
    };
    // What to read: nothing, when no key could stay open; a key open key-wide,
    // by the tools whose findings carry it (`toolsOfKey`) — every row only for
    // a key no tool name stands for; else only the files and rules its scope
    // names (`admitLookup`: every admitted finding is in one of them).
    // Reading every row of every older scan whenever one key stayed open took
    // 2.4 s for 250 scans x 1000 findings under a Semgrep that kept failing
    // beside an ok Bandit (fix round 2).
    let everything = false;
    const tools = new Set();
    const files = new Set();
    const rules = new Set();
    let anyOpen = false;
    for (const key of producedKeys(holder)) {
        const scope = scopeOf(key);
        if (scope.kind === 'never')
            continue;
        anyOpen = true;
        if (scope.admit.all) {
            if (key === UNKNOWN_FINDING_KEY) {
                everything = true;
                break;
            }
            for (const tool of toolsOfKey(key))
                tools.add(tool);
            continue;
        }
        const lookup = admitLookup(scope.admit);
        for (const f of lookup.files)
            files.add(f);
        for (const r of lookup.rules)
            rules.add(r);
    }
    if (!anyOpen)
        return [];
    const rows = everything
        ? storage.findings.listByScan(scan.scan_id).filter((f) => !known.holds(f))
        : storage.findings.listByScanMatching(scan.scan_id, { tools: [...tools], files: [...files], rules: [...rules] }, (keys) => known.holds(keys));
    const newest = index.bookAt(0);
    const labels = new Map();
    const carried = [];
    for (const finding of rows) {
        if (!findingInSlot(scan, finding, slot) || isSuppressed(finding))
            continue;
        const key = findingKey(finding);
        const file = finding.file_path === undefined ? undefined : finding.file_path.replace(/\\/g, '/');
        if (!scopeAdmits(scopeOf(key), file, finding.rule_id))
            continue;
        // The label is the newest scan's own verdict on this finding — the same
        // `openGapFor` every comparison's "not re-measured" reads.
        const memo = JSON.stringify([key, file ?? null, finding.rule_id ?? null]);
        let gap = labels.get(memo);
        if (gap === undefined) {
            gap = newest === undefined ? null : openGapFor(holder, newest, finding);
            labels.set(memo, gap);
        }
        if (gap === null)
            continue;
        carried.push({ finding, gap });
    }
    return carried;
}
/** `semgrep (partly parsed: wp/a.php)` → `semgrep`; `semgrep, bandit` → both: the scanners a gap names. */
function scannersOfGap(gap) {
    const head = gap.split(' (')[0] ?? gap;
    return head.split(', ').filter((name) => name.length > 0);
}
export function openSetForProject(storage, projectPath, opts = {}) {
    const isSuppressed = suppressionMatcher(storage.suppressions.listAll(), opts.now ?? Date.now(), projectPath);
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
    // Each source's rows, read once (a script-era row can source two slots).
    const byScan = new Map();
    const rowsOf = (scan) => {
        let rows = byScan.get(scan.scan_id);
        if (rows === undefined) {
            rows = storage.findings.listByScan(scan.scan_id);
            byScan.set(scan.scan_id, rows);
        }
        return rows;
    };
    // What each slot's dedicated source did not look at again (the module
    // comment). The residual `security_full` slot has no dedicated source.
    const carried = [];
    for (const p of picked) {
        if (p.slot === 'security_full' || p.scan.scan_type !== p.slot)
            continue;
        for (const c of carryForward(storage, projectPath, p.slot, p.scan, rowsOf(p.scan), isSuppressed)) {
            carried.push(c);
            considered.set(c.scan.scan_id, c.scan);
        }
    }
    // Newest first, in SQL's own order (started_at, then rowid — two scans can
    // start in the same millisecond), so where two sources hold the same
    // finding the newer copy — its line numbers, its scan id — is kept.
    // (Carried scans are in `considered` too: `sources` is sorted by this.)
    const order = storage.scans.sortNewestFirst([...considered.keys()]);
    const rank = new Map(order.map((id, i) => [id, i]));
    const rankOf = (scanId) => rank.get(scanId) ?? order.length;
    picked.sort((a, b) => rankOf(a.scan.scan_id) - rankOf(b.scan.scan_id));
    carried.sort((a, b) => rankOf(a.scan.scan_id) - rankOf(b.scan.scan_id));
    const findings = [];
    const sources = [];
    // Grows with `findings`, one source at a time: a source's rows are matched
    // against every earlier source's, never against each other — and never by
    // rebuilding the index per source, which made the carried scans below
    // quadratic (fix round 2).
    const seen = indexFindings([]);
    const admit = (batch) => {
        for (const f of batch) {
            findings.push(f);
            seen.add(f);
        }
    };
    // The findings the sources hold that a suppression hides, once each — so
    // a reader can say how much a suppression (a mass one included) takes out.
    const suppressedSeen = indexFindings([]);
    let suppressedCount = 0;
    for (const { slot, scan, coverage } of picked) {
        const batch = [];
        for (const f of rowsOf(scan)) {
            if (!findingInSlot(scan, f, slot) || seen.has(f))
                continue;
            if (isSuppressed(f)) {
                if (!suppressedSeen.has(f)) {
                    suppressedSeen.add(f);
                    suppressedCount += 1;
                }
                continue;
            }
            batch.push({ ...f, scan_id: scan.scan_id });
        }
        admit(batch);
        const contributed = batch.length;
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
    // After every source: a newer copy of the same identity always wins.
    for (const { slot, scan, coverage, findings: rows } of carried) {
        const gaps = new Set();
        const batch = [];
        for (const { finding, gap } of rows) {
            if (seen.has(finding))
                continue;
            batch.push({ ...finding, scan_id: scan.scan_id, not_remeasured: true });
            gaps.add(gap);
        }
        admit(batch);
        const contributed = batch.length;
        if (contributed === 0)
            continue;
        sources.push({
            slot,
            scan_id: scan.scan_id,
            scan_type: scan.scan_type,
            started_at: scan.started_at,
            finished_at: scan.finished_at,
            coverage,
            findings: contributed,
            carried_for: [...gaps],
        });
    }
    findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.fingerprint.localeCompare(b.fingerprint));
    // Newest first, carried sources included (`resources/findings.ts` names
    // `sources[0]` as the scan the set was read from).
    sources.sort((a, b) => rankOf(a.scan_id) - rankOf(b.scan_id));
    const skipped = summarizeSkipped(hits);
    const scans = [...considered.values()].sort((a, b) => rankOf(a.scan_id) - rankOf(b.scan_id));
    // A carried finding is one no newer scan looked at again: partial, even
    // when every source's own coverage is full (image B's scan over image A).
    const coverage = sources.length === 0
        ? 'none'
        : sources.some((s) => s.coverage !== 'full' || s.carried_for !== undefined) || skipped.count > 0
            ? 'partial'
            : 'full';
    // A carried scan speaks only for what it was carried FOR — the gaps of the
    // newer scans — never for its own stale bookkeeping (a hadolint missing
    // then, installed since). A scanner the slot's source ran ok is listed as
    // run too, so a reader says "ran with reduced coverage" (image B, not
    // image A) rather than "did not run"; one it did not run (nuclei, not
    // requested this time) stays missing only.
    const okInSlot = new Map();
    for (const p of picked) {
        const names = okInSlot.get(p.slot) ?? new Set();
        for (const t of slotView(p.scan, p.slot).tools_run)
            if (t.status === 'ok')
                names.add(t.name);
        okInSlot.set(p.slot, names);
    }
    const bookkeeping = [
        ...picked.map((p) => ({ scan_id: p.scan.scan_id, slot: p.slot, ...slotView(p.scan, p.slot) })),
        ...sources
            .filter((src) => src.carried_for !== undefined)
            .map((src) => {
            const scanners = [...new Set((src.carried_for ?? []).flatMap(scannersOfGap))];
            const ran = okInSlot.get(src.slot) ?? new Set();
            return {
                scan_id: src.scan_id,
                slot: src.slot,
                tools_run: scanners.filter((name) => ran.has(name)).map((name) => ({ name, status: 'ok' })),
                missing_tools: scanners,
            };
        }),
        ...hits.map((h) => ({ scan_id: h.scan.scan_id, slot: h.slot, ...slotView(h.scan, h.slot) })),
    ];
    return {
        project_path: projectPath,
        findings,
        suppressed: suppressedCount,
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