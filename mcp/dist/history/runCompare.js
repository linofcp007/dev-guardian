/**
 * What a comparison of two scans may call "resolved".
 *
 * A finding of the older scan that the newer one does not report is resolved
 * only if the newer scan LOOKED. An orchestrated `security_scan_full` run is
 * compared as a whole — its parent row holds every child's findings merged —
 * and when one of its children measured nothing (Semgrep exit 7, Trivy not
 * installed: coverage none), that child's type is simply absent from the
 * parent. Diffed parent against parent, every earlier finding of that type
 * read as resolved: the dashboard's since_previous, `diff_scans`'s default,
 * `regression_alert` (where the false resolution cancelled a real new high)
 * and `set_baseline` all took it (Task 8 review, fix round 2).
 *
 * Such a finding is NOT RE-MEASURED — neither resolved nor unchanged — and
 * every reader counts it separately. The same holds, whole, for any `to` scan
 * whose own coverage is none (an explicit `to_scan_id` of a blind scan).
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
/**
 * The types `scan` did not measure. For an orchestrated run: each child that
 * is missing (it refused to run), not completed, or at coverage none. For any
 * other scan: its own type when its coverage is none, else nothing.
 */
export function notMeasuredTypes(storage, scan) {
    if (!isOrchestratedFullScan(scan)) {
        return computeCoverage(scan.tools_run, scan.missing_tools) === 'none' ? [scan.scan_type] : [];
    }
    const out = [];
    for (const child of childrenOf(storage, scan)) {
        const row = child.row;
        const usable = row !== null && row.status === 'completed' && computeCoverage(row.tools_run, row.missing_tools) !== 'none';
        if (!usable && !out.includes(child.type))
            out.push(child.type);
    }
    return out;
}
/**
 * The type of each finding of `from`, in the terms of an orchestrated run's
 * children (sast / secrets / deps / iac), or null when it cannot be told —
 * which the check below treats as "not re-measured": never claim a fix it
 * cannot attribute.
 */
function typeResolver(storage, from) {
    if (isOrchestratedFullScan(from)) {
        const indexed = childrenOf(storage, from)
            .filter((c) => c.row !== null)
            .map((c) => ({ type: c.type, index: indexFindings(storage.findings.listByScan(c.row.scan_id)) }));
        return (f) => indexed.find((c) => c.index.has(f))?.type ?? null;
    }
    if (isScriptEraFullScan(from)) {
        return (f) => {
            const slot = scriptEraSlotOfFinding(f);
            // The script's Dockerfile pass is re-run today by scan_iac's
            // `trivy config` over the whole tree, the child an orchestrated run has.
            if (slot === 'containers')
                return 'iac';
            return slot === 'security_full' ? null : slot;
        };
    }
    return () => from.scan_type;
}
export function remeasureCheck(storage, from, to) {
    const notMeasured = notMeasuredTypes(storage, to);
    if (notMeasured.length === 0)
        return { notMeasured, isNotRemeasured: () => false };
    // `to` itself measured nothing: none of `from`'s findings was looked at.
    if (!isOrchestratedFullScan(to))
        return { notMeasured, isNotRemeasured: () => true };
    const typeOf = typeResolver(storage, from);
    return {
        notMeasured,
        isNotRemeasured: (f) => {
            const type = typeOf(f);
            return type === null || notMeasured.includes(type);
        },
    };
}
/** A human line for a response, or null when every type was measured. */
export function describeNotMeasured(to, notMeasured) {
    if (notMeasured.length === 0)
        return null;
    return (`Scan ${to.scan_id} did not measure ${notMeasured.join(', ')} (its scanner there did not run or ` +
        'failed: coverage none). Earlier findings of those types are reported as not re-measured, never ' +
        'as resolved; re-run the scan once the scanner works.');
}
//# sourceMappingURL=runCompare.js.map