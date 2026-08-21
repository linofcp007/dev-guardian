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

import { SEVERITIES, SEVERITY_ORDER, type Severity } from '../types.js';

export interface SeverityShortfall {
  /** How many items sat strictly below the floor. */
  total: number;
  /**
   * Per-tier counts, every tier present including the zeroes. A full record
   * rather than a sparse one: a consumer reading `by_severity.low` must be
   * able to tell "none" from "this report does not cover that tier", and an
   * absent key answers neither.
   */
  by_severity: Record<Severity, number>;
  /**
   * The HIGHEST excluded tier — the smallest step down from the current
   * floor that recovers anything at all. Null when nothing was excluded.
   *
   * Highest, not lowest, on purpose: suggesting the lowest excluded tier
   * would also drag in every heuristic-by-construction rule between here and
   * there, which is the exact outcome the default floor exists to prevent.
   */
  suggested_severity_min: Severity | null;
  /**
   * How many of `total` that suggestion actually recovers — never assumed to
   * be all of them. With 37 `medium` and 3 `low` below a `high` floor,
   * passing `medium` returns 37, and a caller told only "pass medium" would
   * reasonably expect 40.
   */
  recovered_by_suggestion: number;
}

/** Severities from the highest tier down. Derived from SEVERITY_ORDER, never
 *  from the declaration order of `SEVERITIES` and never alphabetically. */
const HIGHEST_FIRST: readonly Severity[] = [...SEVERITIES].sort(
  (a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a],
);

export function severityShortfall(
  items: readonly { severity: Severity }[],
  min: Severity,
): SeverityShortfall {
  const by_severity: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  const floor = SEVERITY_ORDER[min];

  let total = 0;
  for (const item of items) {
    if (SEVERITY_ORDER[item.severity] >= floor) continue;
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
export function describeShortfallTiers(shortfall: SeverityShortfall): string {
  return HIGHEST_FIRST.filter((severity) => shortfall.by_severity[severity] > 0)
    .map((severity) => `${shortfall.by_severity[severity]} ${severity}`)
    .join(', ');
}

/** The LOWEST excluded tier — the floor that recovers every excluded item.
 *  Null when nothing was excluded. */
export function lowestExcludedSeverity(shortfall: SeverityShortfall): Severity | null {
  for (let i = HIGHEST_FIRST.length - 1; i >= 0; i -= 1) {
    const severity = HIGHEST_FIRST[i];
    if (severity !== undefined && shortfall.by_severity[severity] > 0) return severity;
  }
  return null;
}
