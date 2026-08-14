/**
 * The gate: findings + baseline + threshold + coverage -> verdict and exit
 * code. Pure — every input arrives as an argument, so it can be tested from
 * fixtures with no filesystem or scanner involved.
 *
 * This module exists to enforce two rules:
 *
 *   1. Historical debt must not fail the build. A finding already present in
 *      the baseline never blocks, however severe — that is the whole point
 *      of a baseline: a repository adopting this tool with 200 existing
 *      findings must go green on day one.
 *   2. A missing scanner is not a green build. "Zero new findings" from a
 *      scan that did not run is not a pass; it is a scan that says nothing.
 *      `computeCoverage` (see `../tools/scanCoverage.ts`) is the single,
 *      shared definition of "did the scan actually run" — this module reuses
 *      it rather than re-deriving a second one that could disagree.
 *
 * `GATE_FAILED` outranks `INCOMPLETE_SCAN` when both apply: a real regression
 * is the actionable failure a pipeline must see, and the coverage gaps are
 * still reported alongside it, not swallowed by it.
 */
import { SEVERITY_ORDER } from '../types.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { newFindings } from './baseline.js';
import { CI_EXIT } from './types.js';
export function evaluateGate(input) {
    const { findings, baseline, failOn, steps, droppedBaselineEntries } = input;
    // Coverage comes from a single call to computeCoverage over the union of
    // every step's tool bookkeeping — never a second, hand-rolled notion of
    // "complete". A step that refused to run (`ran: false`) contributes its
    // own `tool` name into the "missing" side of that union: it is a gap in
    // exactly the sense computeCoverage already understands (something
    // expected did not happen), so `coverage` itself comes out 'partial' or
    // 'none' rather than leaving `coverage: 'full'` sitting next to an
    // INCOMPLETE_SCAN exit code.
    const allToolsRun = [];
    const allMissingTools = [];
    const coverageGaps = [];
    for (const step of steps) {
        allToolsRun.push(...step.tools_run);
        if (!step.ran) {
            allMissingTools.push(step.tool);
            coverageGaps.push(`${step.tool}: ${step.reason ?? 'did not run'}`);
            continue;
        }
        for (const missing of step.missing_tools) {
            allMissingTools.push(missing);
            coverageGaps.push(`${step.tool}: ${missing} not installed`);
        }
        for (const run of step.tools_run) {
            if (run.status === 'failed') {
                coverageGaps.push(`${step.tool}: ${run.name} failed${run.reason ? ` (${run.reason})` : ''}`);
            }
            // status 'skipped' (nothing to do, e.g. no Dockerfile) is deliberately
            // not a gap — computeCoverage's own contract, see scanCoverage.ts.
        }
    }
    if (droppedBaselineEntries > 0) {
        const noun = droppedBaselineEntries === 1 ? 'entry' : 'entries';
        const verb = droppedBaselineEntries === 1 ? 'is' : 'are';
        coverageGaps.push(`baseline: ${droppedBaselineEntries} ${noun} could not be read and ${verb} no longer suppressed`);
    }
    const coverage = computeCoverage(allToolsRun, allMissingTools);
    // Historical debt must not fail the build: `newFindings` already excludes
    // anything the baseline recognises by fingerprint, however severe.
    const newlyFound = newFindings(findings, baseline);
    const blocking = newlyFound.filter((finding) => SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[failOn]);
    let exitCode;
    if (blocking.length > 0) {
        exitCode = CI_EXIT.GATE_FAILED;
    }
    else if (coverage !== 'full') {
        exitCode = CI_EXIT.INCOMPLETE_SCAN;
    }
    else {
        exitCode = CI_EXIT.PASS;
    }
    return { exitCode, newFindings: newlyFound, blocking, coverage, coverageGaps };
}
//# sourceMappingURL=gate.js.map