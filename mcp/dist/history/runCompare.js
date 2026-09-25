/**
 * What a comparison of two scans may call "resolved" — and "new".
 *
 * A finding of the older scan that the newer one does not report is resolved
 * only if the newer scan LOOKED — with the scanner that reports it. Counted
 * otherwise, the gap read as a fix: an orchestrated `security_scan_full`
 * run is compared as a whole (its parent row holds every child's findings
 * merged), and when a child measured nothing (Semgrep exit 7, Trivy not
 * installed) its type was absent from the parent and every earlier finding
 * of it read as resolved — in the dashboard's since_previous, `diff_scans`'s
 * default, `regression_alert` (where the false resolution cancelled a real
 * new high) and `set_baseline` (fix round 2). Nor is "the child ran" enough:
 * a Python project's sast child can be [semgrep failed, bandit ok] — coverage
 * partial, status completed — and every Semgrep finding still vanished (fix
 * round 3). So the question is asked per SCANNER:
 *
 *   - NOT RE-MEASURED: a finding of `from` whose scanner the newer scan did
 *     not run ok (for the child that covers it). Never resolved, never
 *     unchanged.
 *   - NOT PREVIOUSLY MEASURED: the mirror — a finding of `to` whose scanner
 *     the reference (a baseline, the previous run) did not run ok. Not "new":
 *     a partial baseline would otherwise raise a false regression alarm.
 *
 * "Ran ok" is read from the scan's bookkeeping (`tools_run`, `missing_tools`)
 * through the explicit name table in `history/runNames.ts` — the names are
 * not the findings' tools (`npm` records npm-audit's findings,
 * `guardian-dast` the `dast` ones). For a finding's scanner:
 *
 *   - measured when some entry naming it ran ok, no entry naming it failed
 *     (a failed pass — `guardian-dast:unanswered`, `gitleaks-working-tree` —
 *     vetoes the whole scanner: its findings cannot be told apart by pass),
 *     and no `missing_tools` entry names it — unless that same name also ran
 *     ok, which is a run with a narrower gap inside it (bug_hunt's pack
 *     retry, gitleaks' size limits);
 *   - NOT RUN when the bookkeeping never names a scanner the table knows —
 *     nuclei not requested, no image given: the scan did not look — and
 *     when the older scan ran a pass with a target of its own
 *     (`trivy-image`) that may have produced the finding, and the newer one
 *     did not run that pass again: its Dockerfile pass measures the same
 *     key, but never looked at the image;
 *   - for a tool the table does not know at all, measured only by a scan
 *     with no gap anywhere (coverage `full`), never by a partial one;
 *   - a scan with no bookkeeping at all (the oldest rows) measured
 *     everything.
 *
 * An audit_executive row is judged by its sub-scans' own bookkeeping (its
 * own entries only say which sub-tool answered).
 */
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { KNOWN_FINDING_KEYS, findingKey, keysOfRun, runNameEntry } from './runNames.js';
import { isOrchestratedFullScan, isScriptEraFullScan, scriptEraSlotOfFinding } from './scanRoles.js';
/** A comparison with nothing unmeasured on either side (no reference scan row to read). */
export const COMPLETE_COMPARISON = {
    isNotRemeasured: () => false,
    isNotPreviouslyMeasured: () => false,
    notRunByTo: () => null,
    notRunByFrom: () => null,
    notMeasuredByTo: [],
    notMeasuredByFrom: [],
};
/** An orchestrated run's children, as its parent row lists them. */
function childrenOf(storage, parent) {
    const listed = parent.meta?.['child_scans'];
    if (!Array.isArray(listed))
        return [];
    const out = [];
    for (const entry of listed) {
        if (entry === null || typeof entry !== 'object')
            continue;
        const e = entry;
        const row = typeof e.scan_id === 'string' ? storage.scans.getById(e.scan_id) : null;
        const type = row?.scan_type ?? (typeof e.tool === 'string' ? e.tool.replace(/^scan_/, '') : null);
        if (type !== null)
            out.push({ type, row });
    }
    return out;
}
/** A child that can speak for its type at all: present, completed. */
function usableChild(c) {
    return c.row !== null && c.row.status === 'completed';
}
/**
 * An audit_executive row's bookkeeping, as its sub-scans recorded it. The
 * row's own entries are one per sub-tool (`security_scan_full: ok`): that
 * the sub-tool answered, not that each of its scanners ran — a sub-scan
 * whose Semgrep failed still reports `ok`. Each ok entry is therefore
 * replaced by its sub-scan's own `tools_run` / `missing_tools`; an entry
 * without a readable sub-scan (a sub-tool that failed before it wrote one,
 * a pruned row) stays, and speaks through `runNames.ts`.
 */
function auditBookkeeping(storage, audit) {
    const ids = audit.meta?.['sub_scan_ids'];
    if (ids === null || typeof ids !== 'object' || Array.isArray(ids))
        return audit;
    const byTool = ids;
    const tools_run = [];
    const missing_tools = [...audit.missing_tools];
    for (const entry of audit.tools_run) {
        const id = Object.hasOwn(byTool, entry.name) ? byTool[entry.name] : undefined;
        const sub = entry.status === 'ok' && typeof id === 'string' ? storage.scans.getById(id) : null;
        if (sub === null || (sub.tools_run.length === 0 && sub.missing_tools.length === 0)) {
            tools_run.push(entry);
            continue;
        }
        tools_run.push(...sub.tools_run);
        missing_tools.push(...sub.missing_tools);
    }
    return { tools_run, missing_tools };
}
function bookkeepingOf(storage, scan) {
    return scan.scan_type === 'audit' ? auditBookkeeping(storage, scan) : scan;
}
// ---------------------------------------------------------------------------
// Per-scanner "did this bookkeeping measure this key?"
// ---------------------------------------------------------------------------
function keyVerdict(book, key) {
    let named = false;
    let anyOk = false;
    let anyFailed = false;
    const okNames = new Set();
    for (const run of book.tools_run) {
        const ok = run.status === 'ok';
        if (!(keysOfRun(run.name, ok)?.includes(key) ?? false))
            continue;
        named = true;
        if (ok) {
            anyOk = true;
            okNames.add(run.name);
        }
        else if (run.status === 'failed') {
            anyFailed = true;
        }
    }
    let missing = false;
    for (const name of book.missing_tools) {
        if (!(keysOfRun(name, false)?.includes(key) ?? false))
            continue;
        named = true;
        // Listed missing AND ok under the same name: the scanner ran, with a
        // narrower gap inside it (bug_hunt's pack retry, gitleaks' size limits).
        if (!okNames.has(name))
            missing = true;
    }
    if (named)
        return anyOk && !anyFailed && !missing ? 'measured' : 'unmeasured';
    if (KNOWN_FINDING_KEYS.has(key))
        return 'not_run';
    // A tool no bookkeeping name is known to measure: only a scan with no gap
    // anywhere can speak for it — never a partial one.
    return computeCoverage(book.tools_run, book.missing_tools) === 'full' ? 'measured' : 'unmeasured';
}
function bookkeepingVerdict(book, f) {
    if (book.tools_run.length === 0 && book.missing_tools.length === 0)
        return 'measured';
    return keyVerdict(book, findingKey(f));
}
// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------
/**
 * The type of each finding of `scan`, in the terms of an orchestrated run's
 * children (sast / secrets / deps / iac), or null when it cannot be told.
 */
function typeResolver(storage, scan) {
    if (isOrchestratedFullScan(scan)) {
        const indexed = childrenOf(storage, scan)
            .filter((c) => c.row !== null)
            .map((c) => ({ type: c.type, index: indexFindings(storage.findings.listByScan(c.row.scan_id)) }));
        return (f) => indexed.find((c) => c.index.has(f))?.type ?? null;
    }
    if (isScriptEraFullScan(scan)) {
        return (f) => {
            const slot = scriptEraSlotOfFinding(f);
            // The script's Dockerfile pass is re-run today by scan_iac's
            // `trivy config` over the whole tree, the child an orchestrated run has.
            if (slot === 'containers')
                return 'iac';
            return slot === 'security_full' ? null : slot;
        };
    }
    return () => scan.scan_type;
}
function booksOf(storage, scan) {
    if (!isOrchestratedFullScan(scan)) {
        const book = bookkeepingOf(storage, scan);
        return () => book;
    }
    const children = childrenOf(storage, scan);
    return (fType) => {
        if (fType === null)
            return scan;
        const child = children.find((c) => c.type === fType);
        return child !== undefined && usableChild(child) ? child.row : null;
    };
}
/**
 * The own-target pass (`runNames.ts`: `trivy-image`) that `older` ran ok,
 * that may have produced `f`, and that `newer` did not run ok again — or
 * null. `f` shares its key with passes that look elsewhere (an image's
 * misconfiguration and a Dockerfile's are both `trivy:config`), so the
 * newer scan's Dockerfile pass says nothing about the image.
 */
function ownTargetNotRerun(older, newer, f) {
    if (older === null)
        return null;
    const key = findingKey(f);
    for (const run of older.tools_run) {
        if (run.status !== 'ok' || runNameEntry(run.name)?.ownTarget !== true)
            continue;
        if (!(keysOfRun(run.name, true)?.includes(key) ?? false))
            continue;
        if (!newer.tools_run.some((r) => r.name === run.name && r.status === 'ok'))
            return run.name;
    }
    return null;
}
/** How `newer` answers for `f`, a finding of `older` (both already narrowed to `f`'s child). */
function answerFor(older, newer, f) {
    if (newer === null)
        return { verdict: 'unmeasured', notRun: null };
    const verdict = bookkeepingVerdict(newer, f);
    if (verdict !== 'measured')
        return { verdict, notRun: verdict === 'not_run' ? f.tool : null };
    const pass = ownTargetNotRerun(older, newer, f);
    return pass === null ? { verdict, notRun: null } : { verdict: 'not_run', notRun: pass };
}
/**
 * What `scan` did not measure, for a caller to name — exactly the names
 * whose findings a comparison treats as unmeasured, so a reader that
 * promises "reported as not re-measured / not previously measured" keeps
 * the promise: the whole type of an orchestrated run's missing, unfinished
 * or blind child; the scan's own type when it measured nothing at all;
 * otherwise each bookkeeping name that did not run ok and leaves its
 * findings unmeasured (`npm`, `guardian-dast:unanswered`), or reports none
 * (`pip-audit`). A pass that was merely skipped beside one that ran (no
 * uncommitted files for gitleaks' working-tree pass) is not a gap.
 */
export function notMeasured(storage, scan) {
    const out = [];
    const add = (x) => {
        if (!out.includes(x))
            out.push(x);
    };
    const gapsOf = (book, wholeType) => {
        if (computeCoverage(book.tools_run, book.missing_tools) === 'none') {
            add(wholeType);
            return;
        }
        const names = [...book.tools_run.filter((t) => t.status !== 'ok').map((t) => t.name), ...book.missing_tools];
        for (const name of names) {
            const keys = keysOfRun(name, false);
            if (keys === null || keys.length === 0 || keys.some((k) => keyVerdict(book, k) !== 'measured'))
                add(name);
        }
    };
    if (!isOrchestratedFullScan(scan)) {
        gapsOf(bookkeepingOf(storage, scan), scan.scan_type);
        return out;
    }
    for (const child of childrenOf(storage, scan)) {
        if (!usableChild(child))
            add(child.type);
        else
            gapsOf(child.row, child.type);
    }
    return out;
}
export function compareScansFor(storage, from, to) {
    const typeOfFrom = typeResolver(storage, from);
    const typeOfTo = typeResolver(storage, to);
    const fromBooks = booksOf(storage, from);
    const toBooks = booksOf(storage, to);
    /** `to`'s answer for a finding of `from`. */
    const inTo = (f) => {
        const t = typeOfFrom(f);
        return answerFor(fromBooks(t), toBooks(t), f);
    };
    /** `from`'s answer for a finding of `to`. */
    const inFrom = (f) => {
        const t = typeOfTo(f);
        return answerFor(toBooks(t), fromBooks(t), f);
    };
    return {
        isNotRemeasured: (f) => inTo(f).verdict !== 'measured',
        isNotPreviouslyMeasured: (f) => inFrom(f).verdict !== 'measured',
        notRunByTo: (f) => inTo(f).notRun,
        notRunByFrom: (f) => inFrom(f).notRun,
        notMeasuredByTo: notMeasured(storage, to),
        notMeasuredByFrom: notMeasured(storage, from),
    };
}
/**
 * Classifies two scans' findings. Matching is by identity with the
 * fingerprint as the fallback (`indexFindings`); a finding present on both
 * sides is unchanged whatever the bookkeeping says.
 */
export function classifyDiff(check, fromFindings, toFindings) {
    const fromIndex = indexFindings(fromFindings);
    const toIndex = indexFindings(toFindings);
    const out = {
        new: [],
        resolved: [],
        unchanged: [],
        notRemeasured: [],
        notPreviouslyMeasured: [],
        notRunByTo: [],
        notRunByFrom: [],
    };
    const note = (list, name) => {
        if (name !== null && !list.includes(name))
            list.push(name);
    };
    for (const f of toFindings) {
        if (fromIndex.has(f))
            out.unchanged.push(f);
        else if (check.isNotPreviouslyMeasured(f)) {
            out.notPreviouslyMeasured.push(f);
            note(out.notRunByFrom, check.notRunByFrom(f));
        }
        else
            out.new.push(f);
    }
    for (const f of fromFindings) {
        if (toIndex.has(f))
            continue;
        if (check.isNotRemeasured(f)) {
            out.notRemeasured.push(f);
            note(out.notRunByTo, check.notRunByTo(f));
        }
        else
            out.resolved.push(f);
    }
    return out;
}
export function measurementGaps(check, d) {
    const union = (a, b) => [...a, ...b.filter((x) => !a.includes(x))];
    return { byTo: union(check.notMeasuredByTo, d.notRunByTo), byFrom: union(check.notMeasuredByFrom, d.notRunByFrom) };
}
/** A human line for a response, or null when both scans measured everything. */
export function describeMeasurementGaps(from, to, gaps) {
    const parts = [];
    if (gaps.byTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not measure ${gaps.byTo.join(', ')} (did not run, or failed): ` +
            'earlier findings there are reported as not re-measured, never as resolved.');
    }
    if (gaps.byFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not measure ${gaps.byFrom.join(', ')}: ` +
            'findings there are reported as not previously measured, never as new.');
    }
    return parts.length > 0 ? `${parts.join(' ')} Re-run once the scanner works.` : null;
}
//# sourceMappingURL=runCompare.js.map