/**
 * `regression_alert` — compute a severity-weighted regression score between
 * two scans of the SAME type of ONE project, and flag whether action is
 * warranted.
 *
 * Current: the project's newest usable scan of `scan_type` — default, of any
 * finding-producing type (never an SBOM, a stack detection, a diff review or a
 * scan whose scanners did not run). Reference: the project's active baseline
 * OF THAT TYPE, else the previous usable scan of that type. It used to take
 * the newest scan in the whole database and the newest baseline in the whole
 * database, so it compared a SAST scan against a secrets baseline — or
 * against another project's.
 *
 * Pure SQL — no scanners. Output:
 *   { regressed: boolean, score_delta, baseline_scan_id, current_scan_id,
 *     scan_type, new_findings_by_severity, hint }
 *
 * The model decides what to do with `regressed: true` — open an issue,
 * call audit_executive, etc. We do not auto-trigger anything.
 *
 * New and resolved are decided by the findings' line-independent `identity`,
 * with the fingerprint as the fallback where either scan predates identities
 * — see `diff_scans`, which classifies the same way.
 */
import { z } from 'zod';
import { latestStateScan, summarizeSkipped } from '../history/openSet.js';
import { COMPLETE_COMPARISON, classifyDiff, compareScansFor, describeMeasurementGaps, measurementGaps, } from '../history/runCompare.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { SCAN_TYPES } from '../types.js';
import { registerToolModule } from './index.js';
const SEVERITY_WEIGHT = {
    info: 0.5,
    low: 1,
    medium: 2,
    high: 5,
    critical: 10,
};
const inputSchema = {
    project_path: ProjectPath,
    scan_type: z
        .enum(SCAN_TYPES)
        .optional()
        .describe('Compare scans of this type. Default: the type of the newest finding-producing scan.'),
    threshold: z
        .number()
        .min(0)
        .max(1000)
        .optional()
        .describe('Score-delta threshold above which `regressed=true`. Default 5. ' +
        'A single new critical alone surpasses this; 5 new lows do not.'),
};
const tool = {
    name: 'regression_alert',
    title: 'Regression alert',
    description: "Compare one project's latest scan against its baseline of the same scan type (or its " +
        'previous scan of that type) and flag when the severity-weighted change exceeds a ' +
        "threshold. project_path defaults to the server's working directory; scan_type defaults " +
        'to the newest finding-producing scan. Never compares scans of different types or ' +
        'projects. Returns enough context for the model to recommend follow-up actions.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const threshold = inp.threshold ?? 5;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return { ok: false, error: { code: 'not_a_git_repo', message: e.message } };
    }
    const skipHits = [];
    const current = latestStateScan(ctx.storage, projectPath, inp.scan_type);
    skipHits.push(...current.hits);
    const latest = current.scan;
    if (!latest) {
        return {
            ok: true,
            regressed: false,
            score_delta: 0,
            project_path: projectPath,
            scan_type: inp.scan_type ?? null,
            baseline_scan_id: null,
            current_scan_id: null,
            hint: 'No usable scans recorded for this project yet.',
            ...(skipHits.length > 0 ? { skipped: summarizeSkipped(skipHits) } : {}),
        };
    }
    // Reference: this project's baseline of the same type, else its previous
    // usable scan of that type.
    const baseline = ctx.storage.baselines.getActiveForProject(projectPath, latest.scan_type);
    const otherTypeBaseline = baseline ? null : ctx.storage.baselines.getActiveForProject(projectPath);
    const note = otherTypeBaseline?.scan_type != null
        ? {
            note: `This project's baseline is a '${otherTypeBaseline.scan_type}' scan, not ` +
                `'${latest.scan_type}'; pass scan_type: '${otherTypeBaseline.scan_type}' to compare against it.`,
        }
        : {};
    let baselineId = null;
    let reference = null;
    if (baseline && baseline.scan_id !== latest.scan_id) {
        baselineId = baseline.scan_id;
        reference = 'baseline';
    }
    else {
        const prev = latestStateScan(ctx.storage, projectPath, latest.scan_type, {
            beforeScanId: latest.scan_id,
        });
        skipHits.push(...prev.hits);
        if (prev.scan) {
            baselineId = prev.scan.scan_id;
            reference = 'previous';
        }
    }
    if (!baselineId) {
        return {
            ok: true,
            regressed: false,
            score_delta: 0,
            project_path: projectPath,
            scan_type: latest.scan_type,
            baseline_scan_id: null,
            current_scan_id: latest.scan_id,
            hint: `No '${latest.scan_type}' baseline or previous '${latest.scan_type}' scan to compare against.`,
            ...(skipHits.length > 0 ? { skipped: summarizeSkipped(skipHits) } : {}),
            ...note,
        };
    }
    const prevFindings = ctx.storage.findings.listByScan(baselineId);
    const curFindings = ctx.storage.findings.listByScan(latest.scan_id);
    // Per scanner (`history/runCompare.ts`): a reference finding whose scanner
    // the current scan did not run ok is not resolved — counted as such it
    // cancelled a real new high — and a current finding whose scanner the
    // reference did not run ok is not new — counted as such a partial baseline
    // raised a false alarm. Neither moves the score.
    const baselineScan = ctx.storage.scans.getById(baselineId);
    const check = baselineScan === null ? COMPLETE_COMPARISON : compareScansFor(ctx.storage, baselineScan, latest);
    const d = classifyDiff(check, prevFindings, curFindings);
    const gaps = measurementGaps(check, d);
    const newFindings = d.new;
    const resolvedFindings = d.resolved;
    const score = weightedScore(newFindings) - weightedScore(resolvedFindings);
    const regressed = score > threshold;
    const measuredNote = baselineScan === null ? null : describeMeasurementGaps(baselineScan, latest, gaps);
    return {
        ok: true,
        regressed,
        score_delta: Math.round(score * 10) / 10,
        threshold,
        project_path: projectPath,
        scan_type: latest.scan_type,
        reference,
        baseline_scan_id: baselineId,
        current_scan_id: latest.scan_id,
        new_findings_by_severity: countBySeverity(newFindings),
        resolved_findings_by_severity: countBySeverity(resolvedFindings),
        not_remeasured_by_severity: countBySeverity(d.notRemeasured),
        not_previously_measured_by_severity: countBySeverity(d.notPreviouslyMeasured),
        ...(gaps.byTo.length > 0 ? { not_measured: gaps.byTo } : {}),
        ...(gaps.byFrom.length > 0 ? { reference_not_measured: gaps.byFrom } : {}),
        hint: regressed
            ? 'Severity-weighted change exceeded the threshold. Consider triage_findings + audit_executive, or revert recent changes.'
            : measuredNote !== null
                ? `No significant regression among the types that were measured. ${measuredNote}`
                : 'No significant regression.',
        ...(skipHits.length > 0 ? { skipped: summarizeSkipped(skipHits) } : {}),
        ...note,
        ...(measuredNote !== null ? { not_measured_note: measuredNote } : {}),
    };
}
function weightedScore(findings) {
    return findings.reduce((acc, f) => acc + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
}
function countBySeverity(findings) {
    const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        out[f.severity] += 1;
    return out;
}
//# sourceMappingURL=regressionAlert.js.map