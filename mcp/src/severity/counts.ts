/**
 * The two summaries every scan result carries — findings counted per
 * severity, and the worst few first — in one place (review 8, finding 14:
 * thirteen copies in nine files, the tools, the scan factory and the scans
 * resource each with its own).
 */

import { SEVERITY_ORDER, type Finding, type FindingsCountBySeverity, type Severity } from '../types.js';

/** How many findings of each severity — every tier present, zeroes included. */
export function countBySeverity(findings: readonly { severity: Severity }[]): FindingsCountBySeverity {
  const out: FindingsCountBySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

/** The `limit` most severe findings, worst first; within a tier by fingerprint, so the order is stable. */
export function topFindings(findings: readonly Finding[], limit: number): Finding[] {
  return [...findings]
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.fingerprint.localeCompare(b.fingerprint))
    .slice(0, limit);
}
