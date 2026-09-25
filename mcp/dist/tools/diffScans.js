/**
 * `diff_scans` — compute the new / resolved / unchanged finding sets
 * between two scans of ONE project.
 *
 * Inputs:
 *   - `to_scan_id` (explicit) or `to: 'latest'` (default): the project's
 *     newest usable state scan — of `scan_type` when given. An SBOM, a stack
 *     detection or a diff review is never "the latest scan" (see
 *     `history/scanRoles.ts`), nor is a scan whose coverage was none.
 *   - `from_scan_id` (explicit), `from: 'baseline'` (the project's active
 *     baseline of the `to` scan's type), or `from: 'previous'` (the
 *     project's usable scan of the same `scan_type` immediately before
 *     `to`).
 *
 * The project is `project_path` (default: the server's working directory),
 * or — when `to_scan_id` is given — that scan's own project. "Previous" used
 * to be searched in the 200 newest scans of the WHOLE database, so it could
 * be another project's scan of the same type.
 *
 * "Previous of same type" matters: comparing a `deps` scan with a `sast`
 * scan is meaningless because the fingerprints come from different rule
 * families.
 *
 * Findings are matched by their line-independent `identity`, with the
 * fingerprint as the fallback where either scan predates identities
 * (`fingerprint/findingIdentity.ts#indexFindings`).
 *
 * Response size: `summary` carries the true counts; each list carries at
 * most {@link ITEMS_PER_BUCKET} findings and `truncated` says which were cut.
 */
import { z } from 'zod';
import { latestStateScan, summarizeSkipped } from '../history/openSet.js';
import { classifyDiff, compareScansFor, describeMeasurementGaps, measurementGaps } from '../history/runCompare.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { SCAN_TYPES } from '../types.js';
import { registerToolModule } from './index.js';
/** Items returned per bucket; the counts in `summary` are never capped. */
export const ITEMS_PER_BUCKET = 50;
const FromEnum = z.enum(['baseline', 'previous']);
const ToEnum = z.enum(['latest']);
const inputSchema = {
    project_path: ProjectPath,
    scan_type: z
        .enum(SCAN_TYPES)
        .optional()
        .describe("With to='latest': diff the newest scan of this type. Default: the newest scan of any finding-producing type."),
    from_scan_id: z.string().uuid().optional(),
    from: FromEnum.optional(),
    to_scan_id: z.string().uuid().optional(),
    to: ToEnum.optional(),
};
const tool = {
    name: 'diff_scans',
    title: 'Diff scans (regression / resolution detection)',
    description: 'Compare findings between two scans of one project (same scan_type). Returns new (in to but ' +
        'not in from), resolved (in from but not in to), unchanged (in both) and not_remeasured (in ' +
        'from, of a type to did not measure — e.g. a failed child of a security_scan_full run; never ' +
        'counted as resolved): true counts in `summary`, at most 50 findings per list, `truncated` ' +
        'naming the lists that were cut. Findings are matched by their line-independent identity, so ' +
        'code moving above a finding does not make it new; scans from before identities existed match ' +
        "by fingerprint. Default: from=previous, to=latest — the newest usable scan of project_path " +
        "(default: the server's working directory), never an SBOM/stack/diff-review run or one whose " +
        'scanners did not run; skipped scans are counted in `skipped`. from=baseline uses the ' +
        "project's baseline of the same scan type.",
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const skipHits = [];
    // Resolve `to` first because `from='previous'` depends on it.
    const toScan = resolveTo(inp, ctx, skipHits);
    if (!toScan.ok)
        return toScan.err;
    const fromId = resolveFrom(inp, toScan.value, ctx, skipHits);
    if (!fromId.ok)
        return fromId.err;
    if (fromId.value === toScan.value.scan_id) {
        return failDomain('unknown_scan_id', `Cannot diff a scan against itself (${toScan.value.scan_id}).`);
    }
    const fromScan = ctx.storage.scans.getById(fromId.value);
    if (!fromScan)
        return failDomain('unknown_scan_id', `from scan '${fromId.value}' not found`);
    const fromFindings = ctx.storage.findings.listByScan(fromId.value);
    const toFindings = ctx.storage.findings.listByScan(toScan.value.scan_id);
    // Per scanner (`history/runCompare.ts`): a `from` finding whose scanner `to`
    // did not measure is not resolved, and a `to` finding whose scanner `from`
    // named and did not run ok is not new. A scanner `from` did not run at all
    // (not applicable, or not requested, then) leaves its findings new.
    const check = compareScansFor(ctx.storage, fromScan, toScan.value);
    const d = classifyDiff(check, fromFindings, toFindings);
    const gaps = measurementGaps(check, d);
    const note = describeMeasurementGaps(fromScan, toScan.value, gaps);
    const cap = (list) => list.slice(0, ITEMS_PER_BUCKET);
    const cut = (list) => list.length > ITEMS_PER_BUCKET;
    return {
        ok: true,
        project_path: toScan.value.project_path,
        scan_type: toScan.value.scan_type,
        from_scan_id: fromId.value,
        to_scan_id: toScan.value.scan_id,
        summary: {
            new: d.new.length,
            resolved: d.resolved.length,
            unchanged: d.unchanged.length,
            not_remeasured: d.notRemeasured.length,
            not_previously_measured: d.notPreviouslyMeasured.length,
        },
        new_findings: cap(d.new),
        resolved_findings: cap(d.resolved),
        unchanged_findings: cap(d.unchanged),
        not_remeasured_findings: cap(d.notRemeasured),
        not_previously_measured_findings: cap(d.notPreviouslyMeasured),
        truncated: {
            new: cut(d.new),
            resolved: cut(d.resolved),
            unchanged: cut(d.unchanged),
            not_remeasured: cut(d.notRemeasured),
            not_previously_measured: cut(d.notPreviouslyMeasured),
        },
        ...(gaps.byTo.length > 0 ? { not_measured: gaps.byTo } : {}),
        ...(gaps.byFrom.length > 0 ? { reference_not_measured: gaps.byFrom } : {}),
        ...(note !== null ? { note } : {}),
        ...(skipHits.length > 0 ? { skipped: summarizeSkipped(skipHits) } : {}),
    };
}
function resolveTo(inp, ctx, skipHits) {
    if (inp.to_scan_id) {
        const scan = ctx.storage.scans.getById(inp.to_scan_id);
        if (!scan)
            return { ok: false, err: failDomain('unknown_scan_id', `to scan '${inp.to_scan_id}' not found`) };
        return { ok: true, value: scan };
    }
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return { ok: false, err: failDomain('not_a_git_repo', e.message) };
    }
    // Default: this project's newest usable state scan.
    const latest = latestStateScan(ctx.storage, projectPath, inp.scan_type);
    skipHits.push(...latest.hits);
    if (!latest.scan) {
        return {
            ok: false,
            err: failDomain('unknown_scan_id', `No usable completed ${inp.scan_type ?? 'finding-producing'} scan for ${projectPath} yet.` +
                describeSkipped(latest.skipped)),
        };
    }
    return { ok: true, value: latest.scan };
}
function resolveFrom(inp, toScan, ctx, skipHits) {
    if (inp.from_scan_id) {
        const scan = ctx.storage.scans.getById(inp.from_scan_id);
        if (!scan)
            return {
                ok: false,
                err: failDomain('unknown_scan_id', `from scan '${inp.from_scan_id}' not found`),
            };
        return { ok: true, value: inp.from_scan_id };
    }
    const mode = inp.from ?? 'previous';
    if (mode === 'baseline') {
        const baseline = ctx.storage.baselines.getActiveForProject(toScan.project_path, toScan.scan_type);
        if (!baseline)
            return {
                ok: false,
                err: failDomain('unknown_scan_id', `No '${toScan.scan_type}' baseline is set for ${toScan.project_path}. ` +
                    'Call `set_baseline` on a scan of that type first.'),
            };
        return { ok: true, value: baseline.scan_id };
    }
    // mode === 'previous' — this project's previous usable scan of the same type.
    const previous = latestStateScan(ctx.storage, toScan.project_path, toScan.scan_type, {
        beforeScanId: toScan.scan_id,
    });
    skipHits.push(...previous.hits);
    if (!previous.scan)
        return {
            ok: false,
            err: failDomain('unknown_scan_id', `No previous usable '${toScan.scan_type}' scan of ${toScan.project_path} exists before ` +
                `${toScan.scan_id}.${describeSkipped(previous.skipped)}`),
        };
    return { ok: true, value: previous.scan.scan_id };
}
function describeSkipped(skipped) {
    if (skipped.count === 0)
        return '';
    const named = skipped.newest.map((s) => s.scan_id).join(', ');
    const more = skipped.count > skipped.newest.length ? `, and ${skipped.count - skipped.newest.length} older` : '';
    return ` Skipped ${skipped.count} scan(s) whose scanners did not run (coverage none): ${named}${more}.`;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=diffScans.js.map