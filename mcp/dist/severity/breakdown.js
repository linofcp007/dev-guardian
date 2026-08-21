/**
 * What a `severity_min` floor threw away, and the smallest floor that would
 * get some of it back.
 *
 * `filter.ts` answers "does this pass?". This answers the question a caller
 * asks *after* a filtered run comes back thinner than expected: **what did
 * you drop, and what do I pass to see it?** A tool that filters and then
 * reports only the survivors is indistinguishable, to its caller, from a
 * project with nothing to find — which is the failure this module exists to
 * make impossible.
 *
 * Pure and shape-agnostic: it takes anything with a `severity`, so both a
 * `Finding` and a candidate-shaped projection of one work unchanged.
 */
import { SEVERITIES, SEVERITY_ORDER } from '../types.js';
/** Severities from the highest tier down. Derived from SEVERITY_ORDER, never
 *  from the declaration order of `SEVERITIES` and never alphabetically. */
const HIGHEST_FIRST = [...SEVERITIES].sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a]);
export function severityShortfall(items, min) {
    const by_severity = {
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    const floor = SEVERITY_ORDER[min];
    let total = 0;
    for (const item of items) {
        if (SEVERITY_ORDER[item.severity] >= floor)
            continue;
        by_severity[item.severity] += 1;
        total += 1;
    }
    for (const severity of HIGHEST_FIRST) {
        const count = by_severity[severity];
        if (count > 0) {
            return { total, by_severity, suggested_severity_min: severity, recovered_by_suggestion: count };
        }
    }
    return { total, by_severity, suggested_severity_min: null, recovered_by_suggestion: 0 };
}
/**
 * `"37 medium, 3 low"` — the non-zero tiers only, highest first. Empty string
 * when nothing was excluded, which callers should not be printing anyway.
 */
export function describeShortfallTiers(shortfall) {
    return HIGHEST_FIRST.filter((severity) => shortfall.by_severity[severity] > 0)
        .map((severity) => `${shortfall.by_severity[severity]} ${severity}`)
        .join(', ');
}
/** The LOWEST excluded tier — the floor that recovers every excluded item.
 *  Null when nothing was excluded. */
export function lowestExcludedSeverity(shortfall) {
    for (let i = HIGHEST_FIRST.length - 1; i >= 0; i -= 1) {
        const severity = HIGHEST_FIRST[i];
        if (severity !== undefined && shortfall.by_severity[severity] > 0)
            return severity;
    }
    return null;
}
//# sourceMappingURL=breakdown.js.map