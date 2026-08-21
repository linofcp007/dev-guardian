/**
 * What `create_fix_pr` did NOT act on, and why.
 *
 * `candidates.ts` decides which findings are fixable. This module accounts
 * for every finding that decision left behind. The two are deliberately
 * separate, and the split is what makes the count honest: coverage is
 * measured from the groups `buildGroups` ACTUALLY produced (a fingerprint is
 * covered iff some group's candidate claims it), never re-derived from a
 * second copy of the eligibility rules that could drift out of step with the
 * first. Only the *reason* a leftover finding was left behind is inferred.
 *
 * **Why this exists at all.** `severity_min` defaults to `high`, and the
 * 1.9.0 audit took the `ERROR` tier — the only tier the parser maps to
 * `high` — from 20 rules of 34 to 4 of 58. On a project whose findings all
 * come from the local packs, a default run now returns zero groups, and
 * nothing in the result said "there were 40 findings and I filtered all of
 * them". The floor is correct: lowering it would open pull requests from
 * rules that are heuristic by construction. The silence was the defect.
 *
 * **The reasons are ordered, and the order is load-bearing.** A finding is
 * charged to `no_fix_available` before the severity floor is even consulted,
 * because a floor the caller could lower is only worth naming when lowering
 * it would actually recover something. Every rule in this repo's own Semgrep
 * packs is `fix:`-less, so every finding they produce is excluded at ANY
 * floor — and a report that answered "pass severity_min: medium" there would
 * cost the caller a second run to find out it changed nothing.
 */
import { passes } from '../severity/filter.js';
import { describeShortfallTiers, lowestExcludedSeverity, severityShortfall, } from '../severity/breakdown.js';
export function summariseExclusions(input) {
    const covered = new Set(input.groups.flatMap((group) => group.candidates.flatMap((candidate) => candidate.fingerprints)));
    const by_reason = {
        no_fix_available: 0,
        below_severity_min: 0,
        no_fix_source: 0,
    };
    const belowFloor = [];
    let candidates = 0;
    for (const finding of input.findings) {
        if (covered.has(finding.fingerprint)) {
            candidates += 1;
        }
        else if (!finding.fix_available) {
            by_reason.no_fix_available += 1;
        }
        else if (!passes(finding.severity, input.severityMin)) {
            by_reason.below_severity_min += 1;
            belowFloor.push(finding);
        }
        else {
            by_reason.no_fix_source += 1;
        }
    }
    return {
        considered: input.findings.length,
        candidates,
        excluded: input.findings.length - candidates,
        by_reason,
        below_severity_min: severityShortfall(belowFloor, input.severityMin),
    };
}
/**
 * The human-readable half — one line, for the same reason `deferred_reason`
 * is one line beside `deferred`: the structured field is for the caller that
 * branches on it, the prose is for the caller (usually a model) that reads
 * the result and has to decide what to say next.
 *
 * `null` iff nothing was excluded, exactly as `deferred_reason` is `null` iff
 * `deferred` is empty. Never inferred from silence downstream.
 */
export function describeExclusions(exclusions, severityMin, sources) {
    if (exclusions.excluded === 0)
        return null;
    const parts = [];
    const { no_fix_available, below_severity_min, no_fix_source } = exclusions.by_reason;
    if (below_severity_min > 0) {
        parts.push(`${below_severity_min} below severity_min "${severityMin}" ` +
            `(${describeShortfallTiers(exclusions.below_severity_min)})`);
    }
    if (no_fix_available > 0) {
        parts.push(`${no_fix_available} with no scanner-produced fix (fix_available=false — this tool only ` +
            'applies a fix the scanner itself emitted, and most rule packs emit none)');
    }
    if (no_fix_source > 0) {
        parts.push(`${no_fix_source} that no requested source can act on (sources: ${sources.join(', ')})`);
    }
    const head = `${exclusions.excluded} of ${exclusions.considered} open finding(s) were excluded; ` +
        `${exclusions.candidates} remain as fix candidate(s). Excluded: ${parts.join('; ')}.`;
    return head + severityHint(exclusions.below_severity_min);
}
/** The actionable half, and only when it IS actionable — emitted solely for
 *  the `below_severity_min` bucket, whose findings a lower floor genuinely
 *  recovers. Never for the other two reasons, which no floor recovers. */
function severityHint(shortfall) {
    const suggested = shortfall.suggested_severity_min;
    if (suggested === null)
        return '';
    const lowest = lowestExcludedSeverity(shortfall);
    const rest = lowest !== null && lowest !== suggested
        ? `, or "${lowest}" for all ${shortfall.total}`
        : '';
    return ` Pass severity_min "${suggested}" to include ${shortfall.recovered_by_suggestion} of them${rest}.`;
}
//# sourceMappingURL=exclusions.js.map