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
 * round 3). So the question is asked per TOOL:
 *
 *   - NOT RE-MEASURED: a finding of `from` whose tool the newer scan did not
 *     run ok (for the child that covers it). Never resolved, never unchanged.
 *   - NOT PREVIOUSLY MEASURED: the mirror — a finding of `to` whose tool the
 *     reference (a baseline, the previous run) did not run ok. Not "new": a
 *     partial baseline would otherwise raise a false regression alarm.
 *
 * "Ran ok" is read from the scan's bookkeeping (`tools_run`, `missing_tools`),
 * with the aliases the scanners actually record: Trivy's passes are
 * `trivy-config`, `trivy-dockerfile` and `trivy-image` while their findings
 * all carry `trivy`; the WordPress passes are `semgrep-wp` and `phpcs-wpcs`.
 * A tool the bookkeeping never names falls back to the scan's own coverage
 * (anything but none counts as measured), so a naming this module does not
 * know never turns every finding into "not re-measured" forever. A scan with
 * no bookkeeping at all (the oldest rows) is taken to have measured
 * everything.
 */
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { isOrchestratedFullScan, isScriptEraFullScan, scriptEraSlotOfFinding } from './scanRoles.js';
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
// ---------------------------------------------------------------------------
// Per-tool "did this bookkeeping measure this finding?"
// ---------------------------------------------------------------------------
const TRIVY_CONFIG_PASSES = new Set(['trivy-config', 'trivy-dockerfile']);
/** What a finding needs a scanner to have run: its tool, split by pass for Trivy. */
function findingKey(f) {
    if (f.tool !== 'trivy')
        return f.tool;
    if (f.category === 'license' || f.subcategory === 'cve' || f.subcategory === 'secret')
        return 'trivy:fs';
    return 'trivy:config';
}
/**
 * The finding keys a bookkeeping entry speaks for. `trivy` that ran ok is the
 * dependency pass; `trivy` skipped or failed means Trivy itself is absent,
 * so no pass of it ran. Any other `base-variant` name (`semgrep-wp`) also
 * speaks for its base tool.
 */
function keysOfRun(name, ok) {
    if (TRIVY_CONFIG_PASSES.has(name))
        return ['trivy:config'];
    if (name === 'trivy-image')
        return ['trivy:fs'];
    if (name === 'trivy')
        return ok ? ['trivy:fs'] : ['trivy:fs', 'trivy:config'];
    const dash = name.indexOf('-');
    return dash > 0 ? [name, name.slice(0, dash)] : [name];
}
/** true / false when the bookkeeping names the finding's scanner, null when it never does. */
function toolMeasured(book, f) {
    const key = findingKey(f);
    let named = false;
    let ok = false;
    for (const run of book.tools_run) {
        if (!keysOfRun(run.name, run.status === 'ok').includes(key))
            continue;
        named = true;
        if (run.status === 'ok')
            ok = true;
    }
    for (const name of book.missing_tools) {
        if (!keysOfRun(name, false).includes(key))
            continue;
        named = true;
        // Listed as missing but also `ok` (bug_hunt's retry path): the scanner
        // ran, with a narrower gap inside it. It measured.
    }
    if (!named)
        return null;
    return ok;
}
function bookkeepingMeasures(book, f) {
    if (book.tools_run.length === 0 && book.missing_tools.length === 0)
        return true;
    return toolMeasured(book, f) ?? computeCoverage(book.tools_run, book.missing_tools) !== 'none';
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
/**
 * Whether `scan` measured findings like `f` (`fType` is `f`'s child type, in
 * the terms of {@link typeResolver}, or null). For an orchestrated run the
 * child of that type answers — a missing or unfinished child measured
 * nothing — and when the type cannot be told, the run's merged bookkeeping.
 */
function measurer(storage, scan) {
    if (!isOrchestratedFullScan(scan))
        return (f) => bookkeepingMeasures(scan, f);
    const children = childrenOf(storage, scan);
    return (f, fType) => {
        if (fType === null)
            return bookkeepingMeasures(scan, f);
        const child = children.find((c) => c.type === fType);
        if (child === undefined || !usableChild(child))
            return false;
        return bookkeepingMeasures(child.row, f);
    };
}
/**
 * What `scan` did not measure, for a caller to name: the whole type of an
 * orchestrated run's missing, unfinished or blind child; otherwise each
 * scanner that failed or was missing; or the scan's own type when it
 * measured nothing at all.
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
        const ok = new Set(book.tools_run.filter((t) => t.status === 'ok').map((t) => t.name));
        for (const t of book.tools_run)
            if (t.status === 'failed' && !ok.has(t.name))
                add(t.name);
        for (const t of book.missing_tools)
            if (!ok.has(t))
                add(t);
    };
    if (!isOrchestratedFullScan(scan)) {
        gapsOf(scan, scan.scan_type);
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
    const toMeasures = measurer(storage, to);
    const fromMeasures = measurer(storage, from);
    return {
        isNotRemeasured: (f) => !toMeasures(f, typeOfFrom(f)),
        isNotPreviouslyMeasured: (f) => !fromMeasures(f, typeOfTo(f)),
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
    const out = { new: [], resolved: [], unchanged: [], notRemeasured: [], notPreviouslyMeasured: [] };
    for (const f of toFindings) {
        if (fromIndex.has(f))
            out.unchanged.push(f);
        else if (check.isNotPreviouslyMeasured(f))
            out.notPreviouslyMeasured.push(f);
        else
            out.new.push(f);
    }
    for (const f of fromFindings) {
        if (toIndex.has(f))
            continue;
        if (check.isNotRemeasured(f))
            out.notRemeasured.push(f);
        else
            out.resolved.push(f);
    }
    return out;
}
/** A human line for a response, or null when both scans measured everything. */
export function describeMeasurementGaps(from, to, check) {
    const parts = [];
    if (check.notMeasuredByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not measure ${check.notMeasuredByTo.join(', ')} (did not run or failed): ` +
            'earlier findings there are reported as not re-measured, never as resolved.');
    }
    if (check.notMeasuredByFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not measure ${check.notMeasuredByFrom.join(', ')}: ` +
            'findings there are reported as not previously measured, never as new.');
    }
    return parts.length > 0 ? `${parts.join(' ')} Re-run once the scanner works.` : null;
}
//# sourceMappingURL=runCompare.js.map