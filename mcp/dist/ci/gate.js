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
/**
 * Coverage in, exit code out — the half of the gate's exit-code rule that
 * does not depend on findings at all. Exported so a caller that has no
 * `blocking` concept of its own (`dev-guardian baseline update`: it writes
 * the baseline unconditionally and has no pass/fail gate, but still has to
 * say whether the write it just made reflects every scanner running) can
 * reuse this exact mapping instead of re-encoding it as a second ternary
 * outside this module. `evaluateGate` below calls this too, so there is
 * only ever one definition of "what does an incomplete scan's coverage
 * value mean for an exit code", not two that could drift apart.
 */
export function exitCodeForCoverage(coverage) {
    return coverage === 'full' ? CI_EXIT.PASS : CI_EXIT.INCOMPLETE_SCAN;
}
const withReason = (reason) => (reason ? ` (${reason})` : '');
/**
 * The gap line for one `missing_tools` name, worded from what that step's
 * `tools_run` says about it — or null when the failed-run line below
 * already names it. "Not installed" is said only when nothing says
 * otherwise: a step lists a scanner missing for reasons other than absence,
 * and every one of them has sent a reader to reinstall a working scanner.
 *
 *   - an `ok` run of the same name ran, but did not cover everything (files
 *     it could not read, a pack that failed to load) — scanCoverage.ts's
 *     own convention;
 *   - a `failed` run of the same name is reported as failed, once;
 *   - a run `skipped` for a reason other than `not_installed` did not scan,
 *     and its reason says why (scan_deps: `trivy` recognised no manifest);
 *   - `<scanner>:<part>` with no run of its own is one part of a scanner
 *     that ran (scan_deps: `trivy:dotnet`, a manifest ecosystem Trivy
 *     produced nothing for) and is worded from that scanner's run.
 */
function describeMissing(name, toolsRun) {
    const own = toolsRun.filter((run) => run.name === name);
    const ok = own.find((run) => run.status === 'ok');
    if (ok !== undefined)
        return `${name} ran with reduced coverage${withReason(ok.reason)}`;
    if (own.some((run) => run.status === 'failed'))
        return null;
    const skipped = own.find((run) => run.status === 'skipped' && run.reason && run.reason !== 'not_installed');
    if (skipped !== undefined)
        return `${name} skipped${withReason(skipped.reason)}`;
    const colon = name.indexOf(':');
    if (own.length === 0 && colon > 0) {
        const scanner = name.slice(0, colon);
        const part = name.slice(colon + 1);
        const base = toolsRun.find((run) => run.name === scanner && run.status === 'ok');
        if (base !== undefined)
            return `${scanner} ran with reduced coverage — ${part} not covered${withReason(base.reason)}`;
    }
    return `${name} not installed`;
}
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
            const gap = describeMissing(missing, step.tools_run);
            if (gap !== null)
                coverageGaps.push(`${step.tool}: ${gap}`);
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
    // GATE_FAILED outranks whatever exitCodeForCoverage would say on its own:
    // a real regression is the actionable failure a pipeline must see, ahead
    // of an incomplete-scan signal that is still reported (via coverageGaps)
    // but does not get to hide a blocking finding behind it.
    const exitCode = blocking.length > 0 ? CI_EXIT.GATE_FAILED : exitCodeForCoverage(coverage);
    return {
        exitCode,
        newFindings: newlyFound,
        blocking,
        coverage,
        coverageGaps,
        baselineAbsent: baseline === null,
    };
}
//# sourceMappingURL=gate.js.map