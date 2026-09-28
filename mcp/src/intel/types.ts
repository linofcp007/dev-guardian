/**
 * Shared types for CVE exploitability intel (CISA KEV + FIRST EPSS) —
 * `intel/enrich.ts`'s output, consumed by `tools/prioritizeFindings.ts`,
 * `tools/riskScore.ts` (via `dashboard/risk.ts`), `resources/misc.ts`, and
 * `create_fix_pr` (through `intel/rank.ts`'s `rankByExploitability`).
 */

/**
 * One CVE's exploitability signal. `status: 'unavailable'` means exactly
 * what it says everywhere else in this codebase's scanners: this was NOT
 * measured, never "measured clean" — `kev: false` on an `unavailable` row is
 * a filler value for callers that index straight into `.kev`, not a claim
 * that the CVE is not KEV-listed. Callers that care about the distinction
 * must check `status` first.
 */
export interface CveIntelResult {
  cve_id: string;
  status: 'ok' | 'unavailable';
  /** Meaningful only when `status === 'ok'`. */
  kev: boolean;
  kev_date_added?: string;
  /** 0-1. Present only when FIRST has scored this CVE and the fetch (this
   *  call's or an earlier one still within the cache's TTL) succeeded. */
  epss_score?: number;
  epss_percentile?: number;
  /** True when this `status: 'ok'` row is a cached value the network could
   *  not refresh this call (older than {@link import('./enrich.js').INTEL_TTL_MS}) —
   *  still real data, just possibly outdated. Omitted (never `false`) when
   *  the row is fresh. */
  stale?: boolean;
  /** Populated whenever a refresh was attempted and did not fully succeed —
   *  on an `unavailable` row, why; on a `stale: true` row, why the refresh
   *  that would have cleared the staleness did not happen. */
  reason?: string;
  /** ISO timestamp of the data this result reflects — cache or fresh. Absent
   *  exactly when `status === 'unavailable'` (no data was ever obtained). */
  fetched_at?: string;
}
